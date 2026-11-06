# ESMIR Architecture & System Design Document

**Enterprise Security Monitoring & Incident Response Platform (ESMIR)** is a modular, defensive cybersecurity operations suite designed for security analysts, threat hunters, and SOC engineers.

---

## 1. High-Level Architecture

```
[ Telemetry Sources ]
  - Local OS Collector
  - Syslog / Windows Events
  - CSV Ingestion
  - Agent Heartbeats
          │
          ▼
┌─────────────────────────────────────────────────────────────┐
│                      ESMIR BACKEND                          │
│                                                             │
│  [ FastAPI API Gateway ]                                    │
│   ├── JWT / Bearer Authentication & RBAC                    │
│   ├── Strict Input Validation (Pydantic)                    │
│   └── Security Headers Middleware                           │
│                                                             │
│  [ SIEM & Detection Pipeline ]                              │
│   ├── Event Ingestion & Normalization                       │
│   ├── Ingestion Deduplication Engine                        │
│   ├── Threat Intel IOC Matcher (IPs, Hashes, Domains)       │
│   └── 10 Stateful Detection Rules                           │
│                                                             │
│  [ Defensive Subsystems ]                                   │
│   ├── FIM Engine: SHA-256 Baselining, HMAC, Reconciliation  │
│   ├── DLP Engine: Regex + Luhn + Document Text Parsers      │
│   ├── Vulnerability Matcher: Safe Audits & Advisory CVEs    │
│   ├── Incident Response: 7 Playbooks & Case Lifecycle       │
│   └── Tamper-Evident Audit Trail: SHA-256 Hash Chaining     │
│                                                             │
│  [ Storage Engine ]                                         │
│   └── SQLite (Local Dev) -> PostgreSQL (Enterprise Path)    │
└─────────────────────────────────────────────────────────────┘
          │
          ▼  RESTful JSON API + WebSocket / SSE Ready
┌─────────────────────────────────────────────────────────────┐
│                      ESMIR FRONTEND                         │
│                                                             │
│  [ React 19 + TypeScript + Vite Console ]                   │
│   ├── Dark Cyber Navy / Electric Blue SOC Aesthetic         │
│   ├── Real-Time Overview Dashboard (Recharts Visuals)       │
│   ├── Live Security Event Ingestion & Search               │
│   ├── Alert Center & Detection Rule Catalog                │
│   ├── Asset Inventory & Telemetry Posture                   │
│   ├── FIM Verification & Re-Baseline Workflows              │
│   ├── DLP Sensitive Data Discovery & Exposure Correlation   │
│   ├── Vulnerability Management & Risk Acceptance            │
│   ├── Case Management & Response Playbooks                  │
│   ├── Audit Trail Viewer & Cryptographic Verifier           │
│   └── System Diagnostics & IOC Feed Testing                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems

### 2.1 SIEM & Detection Pipeline
The ingestion pipeline follows a strict multi-stage lifecycle:
1. **Validation**: Pydantic schemas validate JSON types, IP addresses, and required fields. Invalid payloads are rejected with HTTP 422.
2. **Normalization**: Unifies timestamps to UTC ISO-8601, standardizes severity levels (`Critical`, `High`, `Medium`, `Low`, `Info`), and maps category taxonomy.
3. **Deduplication**: Identical events within a 5-second window are deduplicated, while rapid authentication events are preserved for brute-force tracking.
4. **Threat Intelligence Correlation**: Real-time cross-referencing against verified IOCs (`source_ip`, `destination_ip`, file hashes).
5. **Detection Rule Evaluation**: Configurable threshold, sequence, and anomaly rules.
6. **Alert Suppression**: Existing open alerts within a 10-minute window for the same rule and entity are updated with incremented counters rather than generating alert fatigue.

### 2.2 File Integrity Monitoring (FIM)
- **Baselining**: Recursively walks authorized directories, calculating SHA-256 cryptographic hashes, file sizes, and timestamps.
- **Integrity Signature**: Generates an HMAC-SHA256 signature across all baseline entries using the server secret key.
- **Reconciliation Scans**: Compares live filesystem state against baseline to detect:
  - `Modified`: SHA-256 hash or file size differs from baseline.
  - `Created`: File present on disk but absent in baseline.
  - `Deleted`: File recorded in baseline but missing from disk.
- **Controlled Re-Baselining**: Requires analyst justification and creates a version-incremented new baseline with immutable audit logging.

### 2.3 Sensitive Data Discovery (DLP)
- **Supported Formats**: `.txt`, `.csv`, `.json`, `.log`, `.env`, `.ini`, `.py`, `.js`, `.pdf` (via PyPDF), and `.docx` (via python-docx).
- **Pattern Matchers**:
  - Email addresses (RFC 5322 regex).
  - Phone numbers (international & domestic formats).
  - Aadhaar-like identifiers (12-digit format `XXXX XXXX XXXX`).
  - PAN-like identifiers (Indian Income Tax Permanent Account Number `[A-Z]{5}[0-9]{4}[A-Z]`).
  - Credit Card / Account numbers (13–19 digits validated with the Luhn mod-10 algorithm).
  - Cloud API Keys (AWS `AKIA...`, JWT bearer headers, GitHub personal access tokens).
- **Masking Engine**: Redacts sensitive values before storage and UI presentation (e.g., `user***@domain.com`, `4111-XXXX-XXXX-1111`).
- **Exposure Correlation**: Checks if sensitive files correlate with access logs, FIM changes, or egress network telemetry.

### 2.4 Incident Response Case Management
- **Workflow**: `New -> Triaged -> Investigating -> Containment -> Remediation -> Recovery -> Closed`.
- **Response Playbooks**: Pre-configured checklists for Credential Compromise, File Tampering, Sensitive Data Exposure, Malware Execution, and Security Logging Tampering.
- **Non-Destructive Principle**: Response actions provide investigation and containment recommendations. Destructive modifications (account deletion, process termination, network blocking) require explicit human operator approval and out-of-band execution.

### 2.5 Tamper-Evident Audit Trail
- Every security-relevant action (login, baseline creation, rule configuration change, case update, report export) produces an append-oriented audit log.
- Each record calculates:
  $$\text{record\_hash} = \text{SHA-256}(\text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{resource} \parallel \text{details} \parallel \text{previous\_hash})$$
- Cryptographic verification traverses from Genesis (`0000...`) to the latest record, detecting any post-hoc row modifications or deletions.

---

## 3. Database Migration Path

ESMIR uses an SQLAlchemy ORM layer. For local evaluation and development, SQLite is configured by default at `backend/data/esmir.db`.

To migrate to PostgreSQL in an enterprise deployment:
1. Install PostgreSQL driver: `pip install psycopg2-binary`.
2. Configure `.env`:
   ```env
   DATABASE_URL="postgresql+psycopg2://esmir_user:YourSecurePassword@db.corp.internal:5432/esmir_production"
   ```
3. Run Alembic or allow SQLAlchemy automatic initialization on startup.
