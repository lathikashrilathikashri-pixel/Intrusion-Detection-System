# AI-Based Intrusion Detection System (AI-IDS)
## Verification & Testing Guide
**Project Code:** RW-CS-001 | **Test Harness:** Pytest + Integration Suite

---

## 1. Running Automated Backend Tests

The automated test suite in `tests/test_backend.py` validates the entire integration stack:
- Machine Learning model loading, 43-feature vectors, and label encoders.
- Genuine multi-class inference on both benign flows and attack flows.
- User password hashing (PBKDF2 SHA-256) and JWT token creation/decoding.
- SOC dashboard telemetry calculations and timeline partition.
- Security alert query filters and incident triage status updates.
- Security alert CSV export formatting.

Run the test suite with:

```bash
# From the project root
python -m pytest tests/test_backend.py -v
```

---

## 2. End-to-End Manual Testing Scenarios

### Scenario A: Authentication & Session Verification
1. Open `http://127.0.0.1:8000` in your web browser.
2. Click **"Fill Default Admin"** or enter `admin` / `Admin@123`.
3. Click **"Authenticate & Enter SOC"**.
4. Verify you land on the **SOC Command Center** with live telemetry gauges and particle canvas animations.

### Scenario B: Offline Flow Batch Ingestion (CSV Upload)
1. Navigate to **Traffic Monitor** tab in the sidebar.
2. Under "Load Benchmark Samples", click on `cicids2017_sample_flows.csv` or `mixed_attack_traffic.csv`.
3. Notice the progress notification confirming records processed, benign counts, and threats identified.
4. Verify that the table immediately populates with flow records and colored threat badges.
5. Click **"Inspect"** on any flow to open the **Flow Telemetry Inspector** showing 5-tuple attributes, control flags, and model probability distribution.

### Scenario C: Live Traffic Monitor Simulation
1. Click the **"Live Monitor: OFF"** button in the header or in the Traffic Monitor panel.
2. Watch the status transition to **"LIVE MONITOR: ON"** with glowing animated indicators.
3. Every 2.5-3 seconds, a simulated internal packet flow is passed to the real Random Forest model, and if anomalous, triggers a real-time security alert!
4. Click **"Stop Live Monitoring"** to pause.

### Scenario D: AI Manual Flow Classifier & Attack Presets
1. Navigate to **AI Threat Classifier** tab.
2. Click on the **"DoS Attack (Hulk / Slow HTTP)"** preset.
3. Observe all flow attributes auto-fill.
4. Click **"Execute Random Forest Prediction"**.
5. Observe the live result: classified as `DoS` with high confidence, probability bar chart, and remediation advice.
6. Try other presets (`Stealth PortScan Probe`, `SSH Credential Brute Force`, `Web Attack`, or `Legitimate HTTPS Browsing`).

### Scenario E: Security Alert Incident Triage
1. Navigate to **Security Alerts** tab.
2. Filter by Severity (e.g. `Critical` or `High`) or status (`New`).
3. Click **"Triage"** on any alert to open the incident modal.
4. Change status from `New` to `Investigating` or `Resolved`, assign an analyst, and save.
5. Click **"Export Alerts CSV"** to download the security audit CSV file.

### Scenario F: AI Model Evaluation Suite
1. Navigate to **Model Performance** tab.
2. Review test set Accuracy (99.90%), Precision, Recall, and F1-score.
3. Examine the 7x7 interactive **Confusion Matrix Heatmap**.
4. Check the **Classification Report** per category and the **Top Feature Importances** chart.
