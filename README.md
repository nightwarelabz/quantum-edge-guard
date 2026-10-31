# Quantum Edge Guard

**A terminal-first guard that audits, grades, and enforces your machine's
cryptography posture for the AI and quantum era.**

By **NIGHTWARE LABZ** — a commercial product, built from scratch.

> Mission: keep your machines out of reach of AI-driven and quantum-era
> attacks. This README is deliberately plain about what the current version
> actually does toward that mission — and what it does not do yet.

## What v1 does (real checks, all runnable today)

Quantum Edge Guard (`qeg`) runs locally, in your terminal:

1. **Local posture audit — `qeg scan`**
   Reads the crypto configuration already on the machine (SSH client/server
   configs, OpenSSL config) and grades what it finds: weak or classical-only
   key exchange, legacy ciphers and MACs, permissive TLS floors. It also
   lists listening TCP services from the kernel tables and flags known
   plaintext services (FTP, Telnet, HTTP) when they are exposed.

2. **Endpoint grading — `qeg check <host[:port]>`**
   Opens a real TLS handshake to the endpoint and grades what was actually
   negotiated: protocol version, cipher suite, key-exchange group, and the
   certificate's signature family. Classical-only key exchange
   (X25519 / NIST curves / finite-field DH) is flagged as
   quantum-vulnerable — it is exactly what "harvest now, decrypt later"
   collection targets. Endpoints that negotiate post-quantum hybrid key
   exchange (e.g. X25519+ML-KEM) pass.

3. **Policy enforcement — `--policy <file>`**
   A small local policy file sets your floor: minimum TLS version, whether
   post-quantum key exchange is required, and a block-list of hosts the
   guard refuses to pass. Checks that violate policy are reported as
   `POLICY FAIL` and exit non-zero, so `qeg` can gate scripts and CI.

4. **Reporting — every run prints a graded text report** (`PASS` / `WARN` /
   `FAIL` / `POLICY FAIL`, with the evidence line for each grade). No
   telemetry, no phone-home: the report is yours.

## What v1 does NOT do (honest limits)

- It does **not** make any machine unbreakable, and no version of this
  product will ever honestly claim to. It finds and grades weak
  cryptography and enforces the policy you set; it is not a magic shield.
- It does **not** intercept or proxy traffic (an enforcement proxy is on
  the roadmap, see `SPEC.md` — it is not in v1).
- It does **not** patch your software. It tells you, precisely, what to fix.
- The endpoint probe negotiates with the key-exchange groups its TLS stack
  offers. A "classical negotiated" grade means the endpoint accepted a
  classical handshake from this probe — read it as "quantum-vulnerable
  unless the endpoint also offers PQC and prefers it," and see the report
  notes for each endpoint.
- Local scanning is heuristic configuration review, in the tradition of
  NIGHTWARE LABZ's snoot scanner: a flag means "look here," with the file
  and line cited.

## Install

```sh
cargo build --release
# binary: target/release/qeg  (package name: quantum-edge-guard)
```

Rust, no runtime services, no account, no network access needed except the
endpoints you explicitly ask it to check.

## Usage

```sh
qeg scan                                  # audit this machine
qeg check example.com                     # grade an endpoint (port 443)
qeg check mail.example.com:993            # grade a specific port
qeg check example.com --policy qeg.policy # grade against your policy
qeg check 192.168.1.10:8443 --insecure    # self-signed/internal endpoint:
                                          # crypto graded, identity NOT verified
                                          # (the report says so, loudly)
qeg scan --policy qeg.policy              # audit against your policy
qeg report                                # print an example policy + format
```

Exit codes: `0` = nothing failed · `1` = findings at FAIL level ·
`2` = policy violation.

## Pricing

Quantum Edge Guard is a commercial product: **one-time license per
machine, with a yearly update subscription** for new checks, new PQC
standards coverage, and threat-model updates. Pricing tiers are published
with the first commercial release; the source is public for transparency
and evaluation — visibility is not a use license (see `LICENSE`).

## Layout

```
Cargo.toml          package + the `qeg` binary
src/main.rs         the whole v1 tool: scan / check / report / policy
qeg.policy.example  annotated example policy
SPEC.md             threat model, check surfaces, formats, roadmap
LICENSE             proprietary — © NIGHTWARE LABZ, all rights reserved
```

## Lineage

Quantum Edge Guard is written from scratch in-house. Its grading approach
grows out of what NIGHTWARE LABZ learned building **snoot**, our
post-quantum crypto-inventory scanner — snoot inventories the crypto in
your *code*; Quantum Edge Guard grades the crypto on your *machines and
the endpoints they talk to*.

© 2026 Chase Bryan / NIGHTWARE LABZ. All rights reserved.
