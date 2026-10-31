// Quantum Edge Guard (qeg) — v1
// Terminal-first audit / grade / policy tool for a machine's crypto posture.
// Written from scratch by NIGHTWARE LABZ. See README.md and SPEC.md.
//
// Commands:
//   qeg scan   [--policy <file>]   audit this machine's crypto configuration
//   qeg check  <host[:port]> [--policy <file>]
//                                  grade an endpoint's negotiated TLS crypto
//   qeg report                     print the policy format + example
//
// Grades: PASS / WARN / FAIL / POLICY FAIL / INFO.
// Exit codes: 0 clean, 1 FAIL findings, 2 policy violations.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

// ---------- findings ----------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Grade {
    Pass,
    Info,
    Warn,
    Fail,
    PolicyFail,
}

impl Grade {
    fn label(self) -> &'static str {
        match self {
            Grade::Pass => "PASS",
            Grade::Info => "INFO",
            Grade::Warn => "WARN",
            Grade::Fail => "FAIL",
            Grade::PolicyFail => "POLICY FAIL",
        }
    }
}

struct Findings {
    rows: Vec<(Grade, String, String)>,
}

impl Findings {
    fn new() -> Self {
        Findings { rows: Vec::new() }
    }
    fn add(&mut self, g: Grade, check: &str, evidence: String) {
        self.rows.push((g, check.to_string(), evidence));
    }
    fn exit_code(&self) -> u8 {
        if self.rows.iter().any(|(g, _, _)| *g == Grade::PolicyFail) {
            2
        } else if self.rows.iter().any(|(g, _, _)| *g == Grade::Fail) {
            1
        } else {
            0
        }
    }
    fn print(&self, header: &str) {
        println!("{header}");
        let mut n = [0usize; 5];
        for (g, check, ev) in &self.rows {
            println!("[{:<11}] {} — {}", g.label(), check, ev);
            n[*g as usize] += 1;
        }
        println!(
            "summary: {} pass, {} info, {} warn, {} fail, {} policy-fail",
            n[Grade::Pass as usize],
            n[Grade::Info as usize],
            n[Grade::Warn as usize],
            n[Grade::Fail as usize],
            n[Grade::PolicyFail as usize]
        );
    }
}

// ---------- policy ----------

#[derive(Default)]
struct Policy {
    min_tls: Option<(u32, u32)>, // (major, minor) e.g. (1, 2)
    require_pqc: bool,
    deny_hosts: Vec<String>,
}

fn load_policy(path: &str) -> io::Result<Policy> {
    let text = fs::read_to_string(path)?;
    let mut p = Policy::default();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            let (k, v) = (k.trim(), v.trim());
            match k {
                "min_tls" => {
                    let mut it = v.split('.');
                    if let (Some(a), Some(b)) = (it.next(), it.next()) {
                        if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) {
                            p.min_tls = Some((a, b));
                        }
                    }
                }
                "require_pqc" => p.require_pqc = v.eq_ignore_ascii_case("true"),
                "deny_host" => p.deny_hosts.push(v.to_ascii_lowercase()),
                _ => {}
            }
        }
    }
    Ok(p)
}

// ---------- scan: local posture ----------

fn grade_kex(f: &mut Findings, file: &str, line_no: usize, value: &str) {
    let v = value.to_ascii_lowercase();
    let weak = [
        "diffie-hellman-group1-",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "gss-gex-sha1",
        "gss-group14-sha1",
        "rsa1024-sha1",
    ];
    if weak.iter().any(|w| v.contains(w)) {
        f.add(Grade::Fail, "ssh kex", format!("{file}:{line_no} offers known-weak key exchange: {value}"));
    } else if v.contains("mlkem") || v.contains("sntrup") {
        f.add(Grade::Pass, "ssh kex", format!("{file}:{line_no} includes post-quantum key exchange: {value}"));
    } else {
        f.add(Grade::Warn, "ssh kex", format!("{file}:{line_no} classical-only key exchange (quantum-vulnerable): {value}"));
    }
}

fn grade_ciphers(f: &mut Findings, file: &str, line_no: usize, value: &str) {
    let v = value.to_ascii_lowercase();
    if v.contains("arcfour") || v.contains("3des") || v.contains("blowfish") || v.contains("cast128") {
        f.add(Grade::Fail, "ssh ciphers", format!("{file}:{line_no} enables broken ciphers: {value}"));
    } else if v.contains("-cbc") {
        f.add(Grade::Warn, "ssh ciphers", format!("{file}:{line_no} enables legacy CBC ciphers: {value}"));
    } else {
        f.add(Grade::Pass, "ssh ciphers", format!("{file}:{line_no} no broken ciphers listed: {value}"));
    }
}

fn grade_macs(f: &mut Findings, file: &str, line_no: usize, value: &str) {
    let v = value.to_ascii_lowercase();
    if v.contains("hmac-md5") || v.contains("umac-64") {
        f.add(Grade::Fail, "ssh macs", format!("{file}:{line_no} enables broken MACs: {value}"));
    } else if v.contains("hmac-sha1") {
        f.add(Grade::Warn, "ssh macs", format!("{file}:{line_no} enables SHA-1 MACs: {value}"));
    } else {
        f.add(Grade::Pass, "ssh macs", format!("{file}:{line_no} no broken MACs listed: {value}"));
    }
}

fn grade_hostkeys(f: &mut Findings, file: &str, line_no: usize, key: &str, value: &str) {
    let v = value.to_ascii_lowercase();
    if v.contains("ssh-dss") {
        f.add(Grade::Fail, "ssh host keys", format!("{file}:{line_no} {key} allows DSA (ssh-dss): {value}"));
    } else if v.contains("ssh-rsa") {
        f.add(Grade::Warn, "ssh host keys", format!("{file}:{line_no} {key} allows ssh-rsa (SHA-1 signatures): {value}"));
    }
}

fn scan_ssh_file(f: &mut Findings, path: &str) -> bool {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let mut any = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, |c: char| c.is_whitespace() || c == '=');
        let key = parts.next().unwrap_or("").to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        match key.as_str() {
            "kexalgorithms" => {
                any = true;
                grade_kex(f, path, i + 1, value);
            }
            "ciphers" => {
                any = true;
                grade_ciphers(f, path, i + 1, value);
            }
            "macs" => {
                any = true;
                grade_macs(f, path, i + 1, value);
            }
            "hostkeyalgorithms" | "pubkeyacceptedalgorithms" | "pubkeyacceptedkeytypes" => {
                any = true;
                grade_hostkeys(f, path, i + 1, &key, value);
            }
            "protocol" => {
                if value.starts_with('1') {
                    any = true;
                    f.add(Grade::Fail, "ssh protocol", format!("{path}:{} enables SSH protocol 1", i + 1));
                }
            }
            _ => {}
        }
    }
    if !any {
        f.add(Grade::Info, "ssh config", format!("{path}: no explicit crypto directives — compiled defaults apply"));
    }
    true
}

fn scan_openssl(f: &mut Findings, path: &str) -> bool {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(_) => return false,
    };
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("minprotocol") {
            if lower.contains("tlsv1.1") || lower.ends_with("tlsv1") || lower.contains("sslv3") {
                f.add(Grade::Fail, "openssl floor", format!("{path}:{} allows pre-TLS-1.2: {line}", i + 1));
            } else {
                f.add(Grade::Pass, "openssl floor", format!("{path}:{} MinProtocol is TLS 1.2+: {line}", i + 1));
            }
        }
        if lower.contains("seclevel=0") {
            f.add(Grade::Fail, "openssl floor", format!("{path}:{} sets SECLEVEL=0 (all checks off)", i + 1));
        } else if lower.contains("seclevel=1") {
            f.add(Grade::Warn, "openssl floor", format!("{path}:{} sets SECLEVEL=1 (80-bit floor, legacy-tolerant)", i + 1));
        }
    }
    true
}

fn scan_listeners(f: &mut Findings) {
    let mut ports = BTreeSet::new();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = fs::read_to_string(table) {
            for line in text.lines().skip(1) {
                let cols: Vec<&str> = line.split_whitespace().collect();
                // cols[1] = local_address (hex ip:hex port), cols[3] = state (0A = LISTEN)
                if cols.len() > 3 && cols[3] == "0A" {
                    if let Some(port_hex) = cols[1].rsplit(':').next() {
                        if let Ok(p) = u16::from_str_radix(port_hex, 16) {
                            ports.insert(p);
                        }
                    }
                }
            }
        }
    }
    if ports.is_empty() {
        f.add(Grade::Info, "listeners", "no listening TCP sockets found in /proc/net/tcp{,6}".to_string());
        return;
    }
    let list: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
    f.add(Grade::Info, "listeners", format!("{} listening TCP ports: {}", ports.len(), list.join(", ")));
    for (port, name) in [(21u16, "FTP"), (23, "Telnet"), (80, "HTTP")] {
        if ports.contains(&port) {
            f.add(Grade::Warn, "listeners", format!("port {port} ({name}) is listening — plaintext service, no crypto at all"));
        }
    }
}

fn cmd_scan(policy: &Policy) -> u8 {
    let mut f = Findings::new();
    let home = env::var("HOME").unwrap_or_default();
    let mut found_any = false;
    for path in [
        format!("{home}/.ssh/config"),
        "/etc/ssh/ssh_config".to_string(),
        "/etc/ssh/sshd_config".to_string(),
    ] {
        if scan_ssh_file(&mut f, &path) {
            found_any = true;
        }
    }
    if !found_any {
        f.add(Grade::Info, "ssh config", "no SSH config files found in the standard paths".to_string());
    }
    if scan_openssl(&mut f, "/etc/ssl/openssl.cnf") {
        // graded per-line above
    } else {
        f.add(Grade::Info, "openssl config", "/etc/ssl/openssl.cnf not present".to_string());
    }
    scan_listeners(&mut f);
    let _ = policy; // scan is an audit; policy floors apply to endpoint checks in v1
    f.print("qeg scan — local crypto posture");
    f.exit_code()
}

// ---------- check: endpoint grading ----------

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
}

fn cert_sig_family(der: &[u8]) -> (&'static str, bool) {
    // OID content bytes (the value bytes of the OID), matched inside the leaf DER.
    // Heuristic identification, in the snoot tradition: a match means "look here".
    const MLDSA: [&[u8]; 3] = [
        b"\x60\x86\x48\x01\x65\x03\x04\x03\x11", // ML-DSA-44  2.16.840.1.101.3.4.3.17
        b"\x60\x86\x48\x01\x65\x03\x04\x03\x12", // ML-DSA-65
        b"\x60\x86\x48\x01\x65\x03\x04\x03\x13", // ML-DSA-87
    ];
    for oid in MLDSA {
        if contains(der, oid) {
            return ("ML-DSA (post-quantum signature)", true);
        }
    }
    if contains(der, b"\x2a\x86\x48\xce\x3d\x04\x03") {
        return ("ECDSA (classical signature)", false);
    }
    if contains(der, b"\x2b\x65\x70") || contains(der, b"\x2b\x65\x71") {
        return ("EdDSA Ed25519/Ed448 (classical signature)", false);
    }
    if contains(der, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01") {
        return ("RSA (classical signature)", false);
    }
    ("unrecognised", false)
}

fn split_hostport(s: &str) -> (String, u16) {
    if let Some((h, p)) = s.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (s.to_string(), 443)
}

// Lab-use verifier: accepts any certificate. Used ONLY behind the explicit
// --insecure flag, so internal/self-signed endpoints can still have their
// negotiated cryptography graded. Identity is NOT verified in this mode and
// the report says so, loudly.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn cmd_check(target: &str, policy: &Policy, insecure: bool) -> u8 {
    let mut f = Findings::new();
    let (host, port) = split_hostport(target);
    let header = format!("qeg check — {host}:{port}");

    if policy.deny_hosts.iter().any(|d| d == &host.to_ascii_lowercase()) {
        f.add(Grade::PolicyFail, "policy block-list", format!("{host} is on the policy deny_host list — check refused before connecting"));
        f.print(&header);
        return 2;
    }

    // Resolve + connect.
    let addr = match (host.as_str(), port).to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => {
            f.add(Grade::Fail, "connect", format!("could not resolve {host}"));
            f.print(&header);
            return 1;
        }
    };
    let mut tcp = match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            f.add(Grade::Fail, "connect", format!("TCP connect to {addr} failed: {e}"));
            f.print(&header);
            return 1;
        }
    };
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(10)));

    // TLS handshake with rustls (ring provider, webpki roots).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let builder = rustls::ClientConfig::builder();
    let config = if insecure {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    } else {
        let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    if insecure {
        f.add(Grade::Info, "certificate verify", "--insecure given: certificate identity NOT verified; grading negotiated crypto only".to_string());
    }
    let server_name = match rustls::pki_types::ServerName::try_from(host.clone()) {
        Ok(n) => n,
        Err(_) => {
            f.add(Grade::Fail, "connect", format!("invalid server name: {host}"));
            f.print(&header);
            return 1;
        }
    };
    let mut conn = match rustls::ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(e) => {
            f.add(Grade::Fail, "tls", format!("could not start TLS: {e}"));
            f.print(&header);
            return 1;
        }
    };
    if let Err(e) = conn.complete_io(&mut tcp) {
        f.add(Grade::Warn, "tls handshake", format!("handshake did not complete (verification or negotiation failure): {e}"));
        f.print(&header);
        return f.exit_code();
    }

    // Protocol version.
    let version = conn.protocol_version();
    let (vlabel, vtuple) = match version {
        Some(rustls::ProtocolVersion::TLSv1_3) => ("TLS 1.3", (1u32, 3u32)),
        Some(rustls::ProtocolVersion::TLSv1_2) => ("TLS 1.2", (1u32, 2u32)),
        _ => ("unknown/older", (0u32, 0u32)),
    };
    if vtuple >= (1, 3) {
        f.add(Grade::Pass, "tls version", "negotiated TLS 1.3".to_string());
    } else if vtuple == (1, 2) {
        f.add(Grade::Warn, "tls version", "negotiated TLS 1.2 — serviceable, but TLS 1.3 should be offered".to_string());
    } else {
        f.add(Grade::Fail, "tls version", format!("negotiated {vlabel}"));
    }
    if let Some(min) = policy.min_tls {
        if vtuple < min {
            f.add(Grade::PolicyFail, "policy min_tls", format!("negotiated {vlabel}, policy requires TLS {}.{}", min.0, min.1));
        }
    }

    // Cipher suite.
    if let Some(suite) = conn.negotiated_cipher_suite() {
        f.add(Grade::Info, "cipher suite", format!("{:?}", suite.suite()));
    }

    // Key exchange group — the quantum question.
    let mut pqc = false;
    match conn.negotiated_key_exchange_group() {
        Some(group) => {
            let name = format!("{:?}", group.name());
            if name.to_ascii_uppercase().contains("MLKEM") || name.to_ascii_uppercase().contains("ML_KEM") {
                pqc = true;
                f.add(Grade::Pass, "key exchange", format!("{name} — post-quantum hybrid key exchange negotiated"));
            } else {
                f.add(Grade::Warn, "key exchange", format!("{name} — classical key exchange: harvest-now-decrypt-later applies"));
            }
        }
        None => {
            f.add(Grade::Info, "key exchange", "key-exchange group not exposed by the TLS stack for this connection".to_string());
        }
    }
    if policy.require_pqc && !pqc {
        f.add(Grade::PolicyFail, "policy require_pqc", "policy requires post-quantum key exchange; this endpoint negotiated classical".to_string());
    }

    // Certificate signature family.
    if let Some(certs) = conn.peer_certificates() {
        if let Some(leaf) = certs.first() {
            let (family, is_pqc) = cert_sig_family(leaf.as_ref());
            if is_pqc {
                f.add(Grade::Pass, "certificate", format!("leaf signature: {family}"));
            } else {
                f.add(Grade::Warn, "certificate", format!("leaf signature: {family} — Shor-vulnerable family; migration to ML-DSA required long-term"));
            }
        }
    }

    f.print(&header);
    f.exit_code()
}

// ---------- report / usage ----------

const EXAMPLE_POLICY: &str = "\
# Quantum Edge Guard policy — copy to qeg.policy and edit.
# One key = value per line. # starts a comment.
min_tls = 1.2        # minimum TLS version an endpoint may negotiate
require_pqc = false  # true: classical key exchange becomes a POLICY FAIL
# deny_host = legacy.example.com   # repeatable block-list
";

fn usage() {
    println!("Quantum Edge Guard (qeg) v0.1.0 — NIGHTWARE LABZ");
    println!("  qeg scan [--policy <file>]            audit this machine's crypto posture");
    println!("  qeg check <host[:port]> [--policy <f>] [--insecure] grade an endpoint's negotiated TLS");
    println!("  qeg report                            show the policy format + example");
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        return ExitCode::SUCCESS;
    }
    let mut policy_path: Option<String> = None;
    let mut insecure = false;
    let mut positional: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--policy" && i + 1 < args.len() {
            policy_path = Some(args[i + 1].clone());
            i += 2;
        } else if args[i] == "--insecure" {
            insecure = true;
            i += 1;
        } else {
            positional.push(args[i].clone());
            i += 1;
        }
    }
    let policy = match &policy_path {
        Some(p) => match load_policy(p) {
            Ok(pol) => pol,
            Err(e) => {
                eprintln!("qeg: could not read policy {p}: {e}");
                return ExitCode::from(2);
            }
        },
        None => Policy::default(),
    };
    let code = match positional.first().map(|s| s.as_str()) {
        Some("scan") => cmd_scan(&policy),
        Some("check") => match positional.get(1) {
            Some(t) => cmd_check(t, &policy, insecure),
            None => {
                eprintln!("qeg check needs a host, e.g. qeg check example.com:443");
                2
            }
        },
        Some("report") => {
            println!("qeg report — policy format\n\n{EXAMPLE_POLICY}");
            println!("grades: PASS / WARN / FAIL / POLICY FAIL / INFO; exit 0 clean, 1 fail, 2 policy violation");
            0
        }
        _ => {
            usage();
            0
        }
    };
    ExitCode::from(code)
}
