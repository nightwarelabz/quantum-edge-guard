# Quantum Edge Guard — SPEC

Status: v1 founding spec, 2026-10-31. Owner: NIGHTWARE LABZ.

## 1. Product in one paragraph

Quantum Edge Guard (`qeg`) is a terminal-first, installable guard that
audits, grades, and policy-checks the cryptography a machine uses and the
cryptography of the endpoints it connects to — built for a world where
AI-driven attack automation is cheap and where classical public-key
cryptography has a known expiry date. It is sold, not given away:
one-time license + yearly updates.

## 2. Threat model (honest)

In scope:

- **Harvest now, decrypt later.** Adversaries record classical-TLS traffic
  today to decrypt it when a cryptographically relevant quantum computer
  exists. Defence available *now*: negotiate post-quantum hybrid key
  exchange (X25519+ML-KEM-768 per FIPS 203), or know exactly which of your
  connections don't.
- **Classical configuration rot.** Machines accumulate weak SSH/TLS
  settings (group1/group14-sha1 KEX, 3DES, hmac-md5, TLS 1.0 floors,
  SECLEVEL=0) that modern automated attack tooling — increasingly
  AI-assisted — exploits first because they are the cheapest wins.
- **Plaintext exposure.** Listening FTP/Telnet/HTTP services on machines
  that believe they are "internal."
- **Silent downgrade.** Endpoints that *could* do better accepting
  classical-only handshakes without anyone noticing.

Out of scope (and never claimed):

- Making any system unbreakable. No honest tool can.
- Stopping a determined attacker with local/physical access.
- Application-layer vulnerabilities (injection, logic flaws) — other
  tools' territory.
- Guaranteeing an endpoint has *no* PQC support: the v1 probe grades what
  it negotiates. Absence claims require the v1.x multi-probe (see §7).

## 3. Check surface A — local posture (`qeg scan`)

Inputs (read-only, cited by file:line in the report):

- SSH: `~/.ssh/config`, `/etc/ssh/ssh_config`, `/etc/ssh/sshd_config`
  — `KexAlgorithms`, `Ciphers`, `MACs`, `HostKeyAlgorithms`, `Protocol`.
- OpenSSL: `/etc/ssl/openssl.cnf` — `MinProtocol`, `CipherString` SECLEVEL.
- Listening services: `/proc/net/tcp`, `/proc/net/tcp6` (Linux) — every
  LISTEN socket, with known-plaintext port flags (21, 23, 80).

Grades: `PASS` clean/explicitly strong · `WARN` classical-only or legacy
present but not worst-case · `FAIL` known-broken settings present.

## 4. Check surface B — endpoint grading (`qeg check <host[:port]>`)

A real TLS handshake (rustls). The report records:

- negotiated protocol version and cipher suite;
- negotiated key-exchange group — `X25519MLKEM768` / other ML-KEM hybrids
  grade PASS (post-quantum); X25519 / secp256r1 / secp384r1 / FFDHE grade
  WARN "classical — quantum-vulnerable"; anything weaker grades FAIL;
- certificate signature family, read from the leaf certificate
  (RSA / ECDSA / Ed25519 today; ML-DSA / SLH-DSA recognised by OID so the
  grader is ready before such certificates are common);
- TLS below 1.2 grades FAIL; certificate verification failure is reported
  as its own finding, never silently ignored.

## 5. Check surface C — policy (`--policy <file>`)

Format: one `key = value` per line, `#` comments. Keys in v1:

```
min_tls = 1.2            # 1.2 | 1.3
require_pqc = false      # true: classical key exchange = POLICY FAIL
deny_host = bad.example  # repeatable; qeg refuses to pass these hosts
```

Enforcement semantics in v1: a policy violation is printed as
`POLICY FAIL` and the process exits `2`. That is real enforcement at the
level a terminal tool can honestly enforce: scripts, cron, and CI that
call `qeg` stop. Intercepting *other programs'* traffic is the v2 proxy
(§7), and v1 copy must never imply it already happens.

## 6. Report format

Plain text, stable line shapes (parseable):

```
qeg <scan|check> <target>
[PASS ] <check> — <evidence>
[WARN ] <check> — <evidence>
[FAIL ] <check> — <evidence>
[POLICY FAIL] <check> — <evidence>
summary: N pass, N warn, N fail, N policy-fail
```

JSON output (`--json`) is a v1.x item; the text format above is the v1
contract.

## 7. Roadmap

- **v1 (this repo):** terminal tool — scan / check / report / policy.
- **v1.x:** multi-probe endpoint grading (offer PQC-preferred and
  classical-only handshakes separately, so "endpoint supports PQC" and
  "endpoint *prefers* PQC" become distinct, provable grades); `--json`
  reports; scheduled/watch mode (`qeg watch` daemon re-checking policy on
  an interval, alerting on drift); Windows/macOS local-scan paths.
- **v2:** opt-in enforcement proxy — local TLS policy enforcement point
  for applications routed through it; only at this version may copy say
  the guard "blocks" connections, and only for proxied traffic.

## 8. Pricing model (sketch, founder-set)

- One-time license per machine (indie/small-team tier and site tier).
- Yearly update subscription: new checks, PQC standards tracking
  (NIST FIPS 203/204/205 evolution), threat-model updates.
- No per-seat SaaS, no telemetry, no account requirement — the product
  runs on the customer's machine, under the customer's policy.

## 9. License

Proprietary, source-visible: © 2026 Chase Bryan / NIGHTWARE LABZ, all
rights reserved (see `LICENSE`). Public visibility is for transparency
and evaluation. This is a deliberate contrast with snoot (AGPL): snoot
sells *reports and expertise*; Quantum Edge Guard sells *the product*.
