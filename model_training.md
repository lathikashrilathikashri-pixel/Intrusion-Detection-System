# AI-Based Intrusion Detection System (AI-IDS)
## Machine Learning Training & Model Specification
**Project Code:** RW-CS-001 | **Model:** Multi-Class Random Forest Classifier

---

## 1. Dataset Formulation (CICIDS2017 Benchmark)

The ML pipeline utilizes flow benchmark parameters derived from the Canadian Institute for Cybersecurity (CICIDS2017) intrusion benchmark:
- **Sample Size:** 25,000 synthetic flow records with real empirical probability distributions.
- **Feature Space:** 43 continuous and discrete numerical flow features including Flow Duration, Packet Lengths, IAT (Inter-Arrival Time), Bandwidth metrics, and TCP Control Flags (FIN, SYN, RST, PSH, ACK, URG).
- **Target Variable:** 7 classes (`BENIGN`, `DoS`, `DDoS`, `PortScan`, `Brute Force`, `Botnet`, `Web Attack`).

---

## 2. Preprocessing & Data Cleaning

1. **Column Sanitization:** Whitespace stripped from column headers.
2. **Infinite Values Handling:** `np.inf` and `-np.inf` values converted to `np.nan`.
3. **Missing Value Imputation:** NaNs replaced with median value of the respective feature column.
4. **Stratified Split:** 80% Training Set (20,000 records) and 20% Test Set (5,000 records) stratified by class.
5. **Feature Standardization:** Scikit-learn's `StandardScaler` fit exclusively on the training partition and applied to the test set to avoid data leakage.
6. **Label Encoding:** Scikit-learn's `LabelEncoder` ensures consistent class indexing.

---

## 3. Algorithm Configuration

```python
RandomForestClassifier(
    n_estimators=100,
    max_depth=22,
    min_samples_split=4,
    min_samples_leaf=2,
    class_weight='balanced',
    random_state=42,
    n_jobs=-1
)
```

**Why Random Forest?**
- Resilient against feature collinearity and outliers common in network flow metrics.
- Computes non-linear decision boundaries for complex traffic patterns.
- Inherently provides Gini feature importance rankings.
- Ultra-fast sub-millisecond inference time suitable for real-time packet processing.

---

## 4. Model Evaluation Results (Held-Out Test Set)

- **Overall Accuracy:** 99.90%
- **Weighted Precision:** 99.90%
- **Weighted Recall:** 99.90%
- **Weighted F1-Score:** 99.90%
- **Macro F1-Score:** 99.85%

### Classification Report Summary

| Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| **BENIGN** | 99.96% | 99.96% | 99.96% | 2,400 |
| **DoS** | 100.00% | 99.83% | 99.92% | 600 |
| **DDoS** | 99.83% | 100.00% | 99.92% | 600 |
| **PortScan** | 100.00% | 100.00% | 100.00% | 500 |
| **Brute Force** | 99.71% | 100.00% | 99.86% | 350 |
| **Botnet** | 99.67% | 100.00% | 99.83% | 300 |
| **Web Attack** | 100.00% | 99.20% | 99.60% | 250 |

---

## 5. Running Model Training

To retrain the model manually from the command line:

```bash
# Navigate to the ml directory
cd ml

# Run training pipeline
python train.py
```

All artifacts will be saved to `ml/models/`:
- `rf_ids_model.joblib`: Trained Random Forest model weights
- `scaler.joblib`: Fitted StandardScaler parameters
- `label_encoder.joblib`: LabelEncoder class mapping
- `features.json`: Ordered list of 43 features
- `metrics.json`: Full evaluation results and confusion matrix
