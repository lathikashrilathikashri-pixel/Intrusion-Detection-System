# AI-Based Intrusion Detection System (AI-IDS)
## REST API Documentation & Endpoints Reference
**Project Code:** RW-CS-001 | **Base URL:** `/api`

Interactive Swagger Documentation is automatically available at:
`http://127.0.0.1:8000/docs` or `http://127.0.0.1:8000/redoc`

---

## 1. Authentication (`/api/auth`)

### `POST /api/auth/login`
Authenticate SOC operator and obtain JWT Bearer Token.
- **Request Body:**
```json
{
  "username": "admin",
  "password": "Admin@123"
}
```
- **Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1Ni...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "soc-admin@rw-solutions.com",
    "full_name": "Senior Security Analyst",
    "role": "ADMIN"
  }
}
```

### `GET /api/auth/me`
Retrieve currently logged-in user profile (Requires `Authorization: Bearer <token>`).

### `POST /api/auth/logout`
Terminates operator session.

---

## 2. SOC Dashboard Telemetry (`/api/dashboard`)

### `GET /api/dashboard/stats`
Fetches complete aggregated SOC telemetry, KPI metrics, attack distribution, timeline and recent alerts.
- **Headers:** `Authorization: Bearer <token>`
- **Response:**
  - `kpis`: Total connections, threats, normal %, suspicious %, critical alerts, open alerts.
  - `attack_distribution`: Per-class counts and percentages.
  - `traffic_timeline`: Chronological time series points for area chart.
  - `recent_activities`: Audit log stream of latest security incidents.
  - `soc_system_status`: Active ML model details and accuracy.

---

## 3. Network Traffic Monitoring (`/api/traffic`)

### `GET /api/traffic/records`
Query paginated network flow records.
- **Query Params:**
  - `skip` (int, default 0)
  - `limit` (int, default 50, max 500)
  - `threat_only` (bool, optional)
  - `attack_type` (string, optional)
  - `search_ip` (string, optional)

### `POST /api/traffic/upload-csv`
Upload a CSV flow file (multipart/form-data). Evaluates all records with Random Forest model, logs results and generates alerts.

### `GET /api/traffic/sample-files`
List bundled benchmark CSV flow datasets.

### `POST /api/traffic/load-sample/{filename}`
Directly ingest and classify one of the bundled benchmark files.

### `POST /api/traffic/toggle-live`
Enable or disable optional live traffic monitoring mode.
- **Query Params:** `enable=true|false`

### `POST /api/traffic/generate-live-flow`
Generate and classify a single live network flow event with real ML inference.

---

## 4. AI Threat Detection (`/api/detection`)

### `POST /api/detection/predict`
Executes real-time Random Forest inference on manual flow parameters.
- **Request Body:**
```json
{
  "src_ip": "185.220.101.5",
  "dst_ip": "192.168.1.10",
  "src_port": 41234,
  "dst_port": 80,
  "protocol": "TCP",
  "flow_duration": 6500000.0,
  "total_fwd_packets": 22,
  "total_bwd_packets": 1,
  "syn_flag_count": 1,
  "rst_flag_count": 1,
  "psh_flag_count": 1
}
```
- **Response:**
```json
{
  "predicted_attack": "DoS",
  "confidence": 0.94,
  "confidence_percentage": 94.0,
  "is_threat": true,
  "severity": "Critical",
  "probabilities": {
    "BENIGN": 0.01,
    "Botnet": 0.01,
    "Brute Force": 0.01,
    "DDoS": 0.02,
    "DoS": 0.94,
    "PortScan": 0.01,
    "Web Attack": 0.00
  },
  "flow_summary": { ... }
}
```

### `GET /api/detection/presets`
List of pre-configured attack test profiles for demonstration.

---

## 5. Security Alerts (`/api/alerts`)

### `GET /api/alerts`
Query security alerts with filters.
- **Query Params:** `severity=Critical|High|Medium|Low`, `status=New|Investigating|Resolved|False Positive`, `search=<term>`.

### `PATCH /api/alerts/{id}/status`
Update alert investigation status, assign analyst, or document mitigation actions.

### `GET /api/alerts/export/csv`
Download all security alerts in CSV format.

---

## 6. Model Performance (`/api/model`)

### `GET /api/model/performance`
Returns held-out test set accuracy, weighted/macro precision, recall, F1, multi-class confusion matrix, classification report, and top feature importances.

### `POST /api/model/retrain`
Admin-only endpoint to trigger automated Random Forest model retraining on the benchmark dataset.

---

## 7. Reports & Export (`/api/reports`)

### `GET /api/reports/summary`
Generates comprehensive executive summary report with threat history, top attacking IPs, and targeted ports.

### `GET /api/reports/export-traffic-csv`
Download flow records as CSV.

---

## 8. Settings & Diagnostics (`/api/settings`)

### `GET /api/settings/system`
Returns database record counts, SQLite file size, and ML model diagnostics.

### `POST /api/settings/profile`
Update analyst name, email, or change password.

### `POST /api/settings/seed-data`
Reloads sample benchmark flow records.

### `POST /api/settings/clear-data`
Purges traffic logs and alerts (preserves users and model).
