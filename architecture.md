# AI-Based Intrusion Detection System (AI-IDS)
## Enterprise Architecture & Technical Specification
**Project Code:** RW-CS-001  
**Organization:** RW Software Solutions  
**Category:** Cybersecurity + Artificial Intelligence  

---

## 1. System Overview

The **AI-Based Intrusion Detection System (AI-IDS)** is an enterprise Security Operations Center (SOC) platform designed to monitor, inspect, and classify network flows into 7 distinct traffic categories using a trained **Random Forest Classifier**.

The system provides:
1. **Glassmorphism SOC Interface:** Cyber-themed, dark navy canvas with real-time particle constellation animation, glowing telemetry metrics, and responsive Recharts visualizations.
2. **Machine Learning Pipeline:** Benchmark CICIDS2017 flow data generation, handling missing/infinite values, feature scaling with `StandardScaler`, multi-class label encoding, Random Forest ensemble training, test set evaluation, and persistent artifact serialization.
3. **High-Performance FastAPI Backend:** Modular REST APIs for token-based authentication, CSV file upload, live monitoring simulation, manual flow testing, incident alert triage, model performance analysis, and CSV reporting.
4. **Relational Database:** SQLite with SQLAlchemy ORM modeling Users, Analysis Jobs, Network Traffic Records, Security Alerts, and ML Metric Logs.

---

## 2. Architecture Diagram

```
+---------------------------------------------------------------------------------+
|                         CLIENT BROWSER (SOC OPERATOR)                           |
|       React 19 + Vite + Tailwind CSS + Lucide React Icons + Recharts            |
+---------------------------------------------------------------------------------+
                                       |
                   HTTP / REST API (JWT Bearer Auth)
                                       v
+---------------------------------------------------------------------------------+
|                             FASTAPI BACKEND SERVICE                             |
|                                                                                 |
|  [Routers]               [Services]               [Schemas]                     |
|  - Auth (/api/auth)      - AuthService            - UserLogin, Token            |
|  - Dashboard             - DashboardService       - DashboardStats, KPIs        |
|  - Traffic Ingestion     - TrafficService         - TrafficRecordResponse       |
|  - Threat Detection      - LiveMonitorService     - ManualFlowPredictRequest    |
|  - Incident Alerts       - AlertService           - AlertResponse, StatusUpdate |
|  - Model Evaluation                               - ModelPerformanceResponse    |
|  - Executive Reports                              - ReportSummary               |
|  - Settings & Profile                             - SystemSettings              |
+---------------------------------------------------------------------------------+
           |                                                 |
           v                                                 v
+-----------------------+                         +-------------------------------+
|   DATABASE (SQLite)   |                         |     MACHINE LEARNING ENGINE   |
|   SQLAlchemy Models:  |                         |                               |
|   - User              |                         |  - RandomForestClassifier     |
|   - AnalysisJob       |                         |  - StandardScaler             |
|   - TrafficRecord     |                         |  - LabelEncoder               |
|   - SecurityAlert     |                         |  - Feature Vector (43 cols)   |
|   - ModelMetricLog    |                         |  - CICIDS2017 Benchmark Flow  |
+-----------------------+                         +-------------------------------+
```

---

## 3. Supported Attack Categories (Multi-Class)

| Label Index | Category | Attack Description | Assigned SOC Severity |
| :--- | :--- | :--- | :--- |
| **0** | **BENIGN** | Normal, non-malicious corporate HTTP/HTTPS/DNS sessions | None / Clean |
| **1** | **DoS** | Denial of Service (SYN flood, Hulk, Slowloris, Slow HTTP) | High / Critical |
| **2** | **DDoS** | Distributed Denial of Service (UDP burst, LOIC, high packet volume) | Critical |
| **3** | **PortScan** | Network reconnaissance, host scanning, stealth SYN probes | Medium |
| **4** | **Brute Force** | Automated credential guessing on SSH (22), FTP (21), or RDP | High |
| **5** | **Botnet** | Command & Control (C2) heartbeat beaconing and infected bot comms | Critical |
| **6** | **Web Attack** | Web application exploits: SQL Injection (SQLi), XSS, traversal | High |

---

## 4. Database Schema

### `users`
- `id` (INTEGER, PK)
- `username` (VARCHAR(50), UNIQUE, Indexed)
- `email` (VARCHAR(100), UNIQUE, Indexed)
- `full_name` (VARCHAR(100))
- `hashed_password` (VARCHAR(255), PBKDF2 SHA-256)
- `role` (VARCHAR(20): ADMIN, SOC_ANALYST, AUDITOR)
- `is_active` (BOOLEAN)
- `created_at` (DATETIME)
- `last_login` (DATETIME)

### `analysis_jobs`
- `id` (INTEGER, PK)
- `job_uuid` (VARCHAR(50), UNIQUE, Indexed)
- `filename` (VARCHAR(255))
- `source_type` (VARCHAR(50): CSV_UPLOAD, SAMPLE_BENCHMARK, LIVE_STREAM)
- `total_records` (INTEGER)
- `benign_count` (INTEGER)
- `threat_count` (INTEGER)
- `status` (VARCHAR(30))
- `created_at` (DATETIME)

### `traffic_records`
- `id` (INTEGER, PK)
- `job_id` (INTEGER, FK -> analysis_jobs.id)
- `timestamp` (DATETIME, Indexed)
- `src_ip` (VARCHAR(45), Indexed)
- `dst_ip` (VARCHAR(45), Indexed)
- `src_port` (INTEGER)
- `dst_port` (INTEGER, Indexed)
- `protocol` (VARCHAR(10): TCP, UDP, ICMP)
- `flow_duration` (FLOAT)
- `total_fwd_packets` (INTEGER)
- `total_bwd_packets` (INTEGER)
- `flow_bytes_s` (FLOAT)
- `flow_packets_s` (FLOAT)
- `predicted_attack` (VARCHAR(50), Indexed)
- `confidence` (FLOAT)
- `is_threat` (BOOLEAN, Indexed)
- `severity` (VARCHAR(20): Low, Medium, High, Critical)
- `probabilities` (JSON: dictionary of probability per class)

### `security_alerts`
- `id` (INTEGER, PK)
- `alert_id` (VARCHAR(50), UNIQUE, Indexed)
- `traffic_record_id` (INTEGER, FK -> traffic_records.id)
- `timestamp` (DATETIME, Indexed)
- `src_ip` (VARCHAR(45))
- `dst_ip` (VARCHAR(45))
- `dst_port` (INTEGER)
- `protocol` (VARCHAR(10))
- `attack_category` (VARCHAR(50))
- `severity` (VARCHAR(20): Low, Medium, High, Critical)
- `confidence_score` (FLOAT)
- `status` (VARCHAR(30): New, Investigating, Resolved, False Positive)
- `assigned_to` (VARCHAR(50))
- `notes` (TEXT)
- `mitigation_action` (VARCHAR(255))
- `updated_at` (DATETIME)
