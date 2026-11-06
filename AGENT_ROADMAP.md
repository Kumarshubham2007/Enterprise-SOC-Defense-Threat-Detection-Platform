# Multi-Host Endpoint Agent Architecture & Production Roadmap

## 1. Overview & Objectives

While ESMIR provides a working local collector (`backend/app/collectors/local_collector.py` and `agent/collectors/collector.py`) for single-host telemetry, scaling to an enterprise fleet requires a robust, distributed **Multi-Host Endpoint Agent Architecture**.

This roadmap documents the architectural specifications, cryptographic protocols, communication models, and tamper-resistance measures planned for deploying ESMIR endpoint sensors across heterogeneous Windows and Linux production estates.

---

## 2. Distributed Agent Architecture

```
┌────────────────────────────────────────────────────────┐
│                   Remote Endpoint                      │
│                                                        │
│  ┌─────────────────┐       ┌────────────────────────┐  │
│  │ OS Event Tap    │       │ FIM Watcher (Inotify / │  │
│  │ (WinEventLog /  │       │ ReadDirectoryChangesW) │  │
│  │ eBPF / Auditd)  │       │                        │  │
│  └────────┬────────┘       └───────────┬────────────┘  │
│           │                            │               │
│           ▼                            ▼               │
│  ┌──────────────────────────────────────────────────┐  │
│  │        Agent Core Engine (Go / Rust)             │  │
│  │  - Normalization & Timestamping (UTC ISO-8601)   │  │
│  │  - Local Deduplication & Noise Suppression       │  │
│  │  - Zero-Allocation In-Memory Ring Buffer         │  │
│  └────────────────────────┬─────────────────────────┘  │
│                           │                            │
│                           ▼                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │    Local Spooling Storage (Encrypted SQLite)     │  │
│  │  - Write-Ahead Logging (WAL) Mode                │  │
│  │  - 500 MB Circular Disk Budget                  │  │
│  │  - Offline Buffering during Network Outages      │  │
│  └────────────────────────┬─────────────────────────┘  │
│                           │                            │
│                           ▼                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │   Secure Transport Dispatcher (mTLS / gRPC)      │  │
│  │  - Exponential Backoff & Jitter                  │  │
│  │  - Batch Compression (Zstandard / Snappy)        │  │
│  │  - Rate Limiter (Token Bucket: 100 ev/s burst)   │  │
│  └────────────────────────┬─────────────────────────┘  │
└───────────────────────────┼────────────────────────────┘
                            │
               mTLS / TLS 1.3 Strict Mutual Auth
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│               ESMIR Central Collector Gateway          │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Reverse Proxy / API Gateway (mTLS Termination)    │  │
│  │  - Client Certificate CN / SAN Validation        │  │
│  │  - Revocation Check (OCSP Stapling / CRL)        │  │
│  └────────────────────────┬─────────────────────────┘  │
│                           │                            │
│                           ▼                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Ingestion & Threat Detection Pipeline            │  │
│  │  - High-Throughput Stream Ingestion (Kafka/NATS) │  │
│  │  - Stateless Normalizers & Correlation Workers   │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────┘
```

---

## 3. Cryptographic Enrollment & Provisioning Protocol

Endpoint agents must never be provisioned with long-lived universal administrative API keys. Instead, ESMIR mandates a **Cryptographic Enrollment Ceremony**:

### Step 1: Administrator Pre-Registration
1. The SOC administrator generates a single-use or time-bound **Host Enrollment Token** in the ESMIR console:
   - Format: `esmir_enroll_<uuidv4>_<hmac-sha256-signature>`
   - Configurable TTL: Default 4 hours, single-use per hostname.
   - Assigned Asset Group, Policy Profile, and Baseline Template.

### Step 2: Agent Installation & CSR Generation
1. The agent installer runs with administrative privileges on the target endpoint (`SYSTEM` on Windows, `root` on Linux).
2. The agent generates a local hardware-backed private key:
   - Ed25519 or ECDSA (P-256) key pair generated inside Windows DPAPI / TPM 2.0 or Linux PKCS#11 / kernel keyring where available.
   - Private key permissions are locked strictly to `NT AUTHORITY\SYSTEM` or `root:root (0600)`.
3. The agent compiles a **Certificate Signing Request (CSR)** embedding:
   - Subject Common Name: `agent-<asset_id>.<domain>`
   - SAN: Host UUID, primary MAC address, OS architecture.

### Step 3: Registration Handshake
1. The agent transmits the CSR over TLS 1.3 to `POST /api/v1/agents/enroll` accompanied by the `Host Enrollment Token`.
2. ESMIR Central validates the enrollment token, verifies signature and quota, creates the `Asset` record, and signs the CSR via ESMIR's Internal Intermediate Certificate Authority (CA).
3. The signed client certificate (valid for 90 days) and dynamic CA bundle are returned to the agent.
4. The enrollment token is immediately revoked/invalidated.

### Step 4: Automatic Certificate Rotation
- At 60 days (30 days prior to expiration), the agent generates a fresh CSR and executes `POST /api/v1/agents/renew-cert` authenticated via its existing valid certificate.

---

## 4. Mutual TLS (mTLS) & Transport Security

All continuous telemetry ingestion, configuration updates, and heartbeat transmissions operate over **Strict Mutual TLS (mTLS)**:

- **Protocol Version**: TLS 1.3 mandatory; TLS 1.2 permitted only with forward-secrecy cipher suites (`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`).
- **Mutual Authentication**: Both ESMIR Gateway and Endpoint Agent present and verify certificates against the ESMIR Root CA.
- **Payload Compression**: Event batches are compressed using Zstandard (`zstd`) prior to transport encryption, cutting telemetry egress bandwidth by ~85%.
- **Connection Reuse**: HTTP/2 or gRPC bidirectional multiplexing maintains persistent persistent streams, reducing TCP and TLS handshake overhead on constrained enterprise networks.

---

## 5. Local Event Spooling & Offline Buffering

Network partitions, VPN disconnections, and branch office outages are inevitable. Agents must never drop forensic telemetry during disconnections:

1. **Local Persistent Storage**:
   - The agent writes normalized events to an embedded, encrypted SQLite database (`spool.db`) or LMDB key-value store using Write-Ahead Logging (WAL).
   - Encryption-at-Rest: AES-256-GCM using a host-derived cryptographic key stored in Windows DPAPI or Linux kernel keyring.
2. **Circular Disk Quota Management**:
   - Configurable storage ceiling (default: 500 MB; maximum 2 GB).
   - If the disk quota reaches 95% during an extended multi-day outage:
     - Informational debug and low-severity telemetry is dropped first using a priority eviction queue.
     - Critical, High, and File Tampering events are strictly preserved.
3. **Recovery & Replay**:
   - Upon reconnecting, the agent replays spooled events in chronological order.
   - Replayed events retain their original `timestamp` (UTC) to guarantee accurate correlation and rule evaluation in the central SIEM.

---

## 6. Rate Limiting, Backoff & Network Throttling

To prevent distributed denial-of-service (DDoS) against central ESMIR collectors during mass incident storms:

1. **Token Bucket Rate Limiting**:
   - Sustained baseline: 50 events/second per agent.
   - Burst allowance: 150 events/second for 10 seconds.
   - Throttled excess events are spooled locally rather than discarded.
2. **Exponential Backoff with Full Jitter**:
   - On connection failure or `HTTP 429 Too Many Requests` / `HTTP 503 Service Unavailable`:
     $$\text{WaitTime} = \min(M, B \times 2^{\text{attempt}}) \pm \text{RandomJitter}$$
     Where $B = 1\text{s}$ and $M = 300\text{s}$ (5 minutes maximum backoff).
3. **Heartbeat Cadence**:
   - Lightweight status beacons (`agent_id`, CPU%, RAM%, spool backlog size, FIM baseline revision) are transmitted every 30 seconds.
   - If 3 consecutive heartbeats are missed (90s), ESMIR triggers an `Asset Unresponsive` notification in the SOC console.

---

## 7. Endpoint Tamper Resistance & Defensive Boundaries

Endpoint detection agents are prime targets for adversary termination and evasion:

1. **Privileged Process Protection**:
   - **Windows**: Agent service runs under `NT AUTHORITY\SYSTEM` with a custom Security Descriptor Definition Language (SDDL) preventing non-elevated users and local administrators from stopping the service without specialized audit logging (`SeDebugPrivilege` monitoring).
   - **Linux**: Systemd unit configured with `ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges=yes`, and capability restrictions.
2. **Self-Integrity Watchdog**:
   - A secondary micro-daemon (`esmir-watchdog`) continuously verifies the digital signature (Authenticode on Windows, RPM/DEB GPG sign on Linux) and SHA-256 hash of the main agent binary.
   - If the primary collector process terminates unexpectedly, the watchdog logs a local crash marker and attempts an immediate restart.
3. **Safe Command Boundaries**:
   - **Strict Principle**: ESMIR endpoint agents are **observation and telemetry sensors**, not unconstrained remote execution shells.
   - If remediation actions (such as endpoint network isolation or baseline update) are enabled in future releases:
     - Arbitrary commands (`cmd.exe /c ...` or `bash -c ...`) are **strictly prohibited**.
     - Only deterministic, digitally-signed pre-compiled playbooks with strict whitelist parameter schemas are executed.
     - Dual-authorization ("two-man rule") is required from two distinct SOC analyst accounts for any host isolation action.

---

## 8. Development & Implementation Roadmap

| Phase | Milestone | Deliverables | Target Architecture |
| :--- | :--- | :--- | :--- |
| **Phase 1 (Current)** | Standalone Local Collectors | Python 3.12+ collector scripts, JSON/REST ingestion, local FIM hash engine, regex/Luhn DLP scans | Single-host / Lab / POC |
| **Phase 2** | Native Agent Core | Compiled Go/Rust agent daemon, Windows Service & Linux Systemd packages, local SQLite WAL spooling | Small fleet (1–100 hosts) |
| **Phase 3** | Secure Gateway & mTLS | Enrollment token issuance API, CA certificate rotation pipeline, gRPC event ingestion | Enterprise fleet (100–10,000 hosts) |
| **Phase 4** | Advanced Endpoint Taps | Windows Event Log ETW subscriptions, Linux eBPF syscall interception, real-time inotify FIM | High-frequency telemetry |
| **Phase 5** | Signed Response Playbooks | Dual-auth network isolation, approved memory dump trigger, automated quarantined file hashing | Managed Threat Response |

---

## 9. Conclusion

This architecture ensures that ESMIR's endpoint telemetry pipeline remains resilient against network interruptions, cryptographically verifiable against spoofing, scalable across thousands of nodes, and defensively engineered against adversarial tampering.
