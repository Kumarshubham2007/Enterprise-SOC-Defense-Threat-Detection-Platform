# ESMIR REST API Reference Guide

All API endpoints are hosted at `/api` and require JSON payloads unless otherwise specified.

---

## 1. Authentication & RBAC

### `POST /api/auth/login`
Authenticates user credentials and returns a JWT bearer token.
- **Request Body**:
  ```json
  {
    "username": "admin",
    "password": "Admin@ESMIR2026!"
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "token_type": "bearer",
    "user": {
      "id": 1,
      "username": "admin",
      "email": "admin@esmir.soc.local",
      "role": "admin",
      "is_active": true
    }
  }
  ```

### `GET /api/auth/me`
Returns current operator profile.
- **Headers**: `Authorization: Bearer <token>`
- **Response**: `200 OK`

---

## 2. Security Events (SIEM Pipeline)

### `POST /api/events`
Ingests a single telemetry event.
- **Request Body**:
  ```json
  {
    "timestamp": "2026-10-22T10:00:00Z",
    "hostname": "dc01.corp.internal",
    "event_category": "Authentication",
    "severity": "Medium",
    "event_name": "Logon Failed - Bad Password",
    "username": "b.anderson",
    "source_ip": "10.0.1.88",
    "source": "local_collector",
    "details": { "logon_type": 3 }
  }
  ```
- **Response**: `200 OK`
  ```json
  {
    "status": "ingested",
    "event_id": "8a7c2b...",
    "alerts_triggered_count": 1,
    "alerts": [...]
  }
  ```

### `GET /api/events`
Query, filter, and paginate security events.
- **Parameters**: `page`, `limit`, `hostname`, `category`, `severity`, `username`, `search`.

### `POST /api/events/upload-csv`
Uploads a CSV file of events (multipart/form-data).

---

## 3. Alerts & Detection Rules

### `GET /api/alerts`
Retrieves generated alerts with filters for `severity`, `status`, `hostname`, `rule_id`.

### `PATCH /api/alerts/{alert_id}`
Updates alert status (`Triaged`, `Investigating`, `Resolved`, `False_Positive`).

### `GET /api/alerts/rules`
Lists all detection rules, thresholds, and time windows.

### `PATCH /api/alerts/rules/{rule_id}`
Enables/disables rule or updates threshold (Admin/Engineer only).

---

## 4. File Integrity Monitoring (FIM)

### `POST /api/fim/baseline`
Creates a cryptographic SHA-256 baseline for an authorized path.
- **Request Body**:
  ```json
  {
    "name": "Core Configs",
    "directory_path": "C:\\path\\to\\dir"
  }
  ```

### `POST /api/fim/scan`
Executes a reconciliation scan comparing filesystem state against baseline.
- **Request Body**: `{"baseline_id": 1}`

### `POST /api/fim/approve-update`
Controlled re-baselining after authorized modifications.
- **Request Body**: `{"baseline_id": 1, "justification": "CHG-2026-01 approved"}`

---

## 5. Data Loss Prevention (DLP)

### `POST /api/dlp/scan`
Scans an authorized directory for sensitive data (PII, credentials, cards).

### `GET /api/dlp/findings`
Retrieves masked sensitive data findings.

### `GET /api/dlp/findings/{id}/investigate`
Correlates sensitive findings with access logs and network transfers.

---

## 6. Incident Case Management

### `GET /api/incidents`
Lists incident cases.

### `POST /api/incidents`
Creates an incident from alerts or manual investigation.

### `PATCH /api/incidents/{id}`
Updates case lifecycle: `New -> Triaged -> Investigating -> Containment -> Remediation -> Recovery -> Closed`.

### `POST /api/incidents/{id}/comments`
Appends analyst investigation note to case timeline.

---

## 7. Reports & Tamper-Evident Audit

### `POST /api/reports/generate`
Generates comprehensive report JSON with executive KPIs.

### `POST /api/reports/export/csv`
Downloads CSV report export.

### `POST /api/reports/export/html`
Downloads formatted HTML report.

### `GET /api/audit/verify`
Traverses cryptographic SHA-256 chain and validates audit integrity.

---

## 8. System Diagnostics

### `GET /api/health`
Returns live subsystem status, database connectivity, and telemetry metrics.

### `POST /api/demo/seed`
Injects simulated adversary scenario with `is_demo=True`.
