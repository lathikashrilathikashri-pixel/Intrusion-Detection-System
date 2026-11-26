"""
AI-Based Intrusion Detection System (AI-IDS)
Project Code: RW-CS-001 | RW Software Solutions
ML Model Training & Evaluation Pipeline
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

from dataset_generator import generate_flow_dataset, FEATURE_COLUMNS, ATTACK_CLASSES

def clean_data(df: pd.DataFrame, feature_cols: list):
    """Clean infinite and missing values from dataset."""
    df_clean = df.copy()
    
    # Standardize column names (strip whitespace)
    df_clean.columns = df_clean.columns.str.strip()
    
    # Replace inf and -inf with NaN
    for col in feature_cols:
        if col in df_clean.columns:
            df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce')
            df_clean[col] = df_clean[col].replace([np.inf, -np.inf], np.nan)
            median_val = df_clean[col].median()
            df_clean[col] = df_clean[col].fillna(median_val if not np.isnan(median_val) else 0.0)
            
    return df_clean

def train_ids_model(n_samples=25000, random_state=42):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, 'data')
    models_dir = os.path.join(base_dir, 'models')
    sample_dir = os.path.join(base_dir, 'sample_data')
    
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(models_dir, exist_ok=True)
    os.makedirs(sample_dir, exist_ok=True)
    
    csv_path = os.path.join(data_dir, 'cicids2017_benchmark.csv')
    
    if not os.path.exists(csv_path):
        print(f"Synthesizing benchmark dataset ({n_samples} samples)...")
        df = generate_flow_dataset(n_samples=n_samples, random_state=random_state)
        df.to_csv(csv_path, index=False)
    else:
        print(f"Loading existing benchmark dataset from {csv_path}...")
        df = pd.read_csv(csv_path)
        
    print(f"Dataset shape: {df.shape}")
    
    # Preprocess & Clean
    print("Preprocessing & handling missing/infinite values...")
    df_clean = clean_data(df, FEATURE_COLUMNS)
    
    X = df_clean[FEATURE_COLUMNS]
    y = df_clean['Label']
    
    # Label Encoding
    le = LabelEncoder()
    # Fit with the strict list of classes so ordering is deterministic
    le.fit(ATTACK_CLASSES)
    y_encoded = le.transform(y)
    
    # Stratified Train-Test Split (80% train, 20% test)
    print("Splitting dataset (80% Train, 20% Test Stratified)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.20, random_state=random_state, stratify=y_encoded
    )
    print(f"Training set: {X_train.shape[0]} samples, Test set: {X_test.shape[0]} samples")
    
    # Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Model Training: Random Forest Classifier
    print("Training Random Forest Classifier (100 estimators, max_depth=22)...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=22,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=random_state,
        n_jobs=-1
    )
    rf.fit(X_train_scaled, y_train)
    print("Training complete!")
    
    # Model Evaluation on held-out test set
    print("Evaluating model on held-out test dataset...")
    y_pred = rf.predict(X_test_scaled)
    y_prob = rf.predict_proba(X_test_scaled)
    
    accuracy = float(accuracy_score(y_test, y_pred))
    precision_weighted = float(precision_score(y_test, y_pred, average='weighted', zero_division=0))
    precision_macro = float(precision_score(y_test, y_pred, average='macro', zero_division=0))
    recall_weighted = float(recall_score(y_test, y_pred, average='weighted', zero_division=0))
    recall_macro = float(recall_score(y_test, y_pred, average='macro', zero_division=0))
    f1_weighted = float(f1_score(y_test, y_pred, average='weighted', zero_division=0))
    f1_macro = float(f1_score(y_test, y_pred, average='macro', zero_division=0))
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred, labels=range(len(ATTACK_CLASSES)))
    cm_list = cm.tolist()
    
    # Per-class classification report
    report_dict = classification_report(
        y_test, y_pred,
        target_names=ATTACK_CLASSES,
        output_dict=True,
        zero_division=0
    )
    
    # Feature importances
    importances = rf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]
    top_features = [
        {"feature": FEATURE_COLUMNS[idx], "importance": float(importances[idx])}
        for idx in sorted_idx[:15]
    ]
    
    metrics = {
        "model_name": "Random Forest Classifier",
        "algorithm": "RandomForestClassifier",
        "parameters": {
            "n_estimators": 100,
            "max_depth": 22,
            "min_samples_split": 4,
            "min_samples_leaf": 2,
            "class_weight": "balanced"
        },
        "classes": ATTACK_CLASSES,
        "n_samples_train": int(X_train.shape[0]),
        "n_samples_test": int(X_test.shape[0]),
        "accuracy": accuracy,
        "precision_weighted": precision_weighted,
        "precision_macro": precision_macro,
        "recall_weighted": recall_weighted,
        "recall_macro": recall_macro,
        "f1_score_weighted": f1_weighted,
        "f1_score_macro": f1_macro,
        "confusion_matrix": cm_list,
        "classification_report": report_dict,
        "top_features": top_features,
        "trained_at": pd.Timestamp.now().isoformat()
    }
    
    print(f"\n================ MODEL EVALUATION RESULTS ================")
    print(f"Accuracy:          {accuracy * 100:.2f}%")
    print(f"Weighted Precision: {precision_weighted * 100:.2f}%")
    print(f"Weighted Recall:    {recall_weighted * 100:.2f}%")
    print(f"Weighted F1-Score:  {f1_weighted * 100:.2f}%")
    print(f"Macro F1-Score:     {f1_macro * 100:.2f}%")
    print("==========================================================\n")
    
    # Persist model artifacts
    print("Saving model artifacts...")
    joblib.dump(rf, os.path.join(models_dir, 'rf_ids_model.joblib'))
    joblib.dump(scaler, os.path.join(models_dir, 'scaler.joblib'))
    joblib.dump(le, os.path.join(models_dir, 'label_encoder.joblib'))
    
    with open(os.path.join(models_dir, 'features.json'), 'w') as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)
        
    with open(os.path.join(models_dir, 'metrics.json'), 'w') as f:
        json.dump(metrics, f, indent=2)
        
    print(f"Model and artifacts successfully serialized to {models_dir}")
    
    # Generate test sample CSV datasets with IP addresses, protocols, and metadata
    generate_sample_traffic_csvs(sample_dir, df_clean)
    
    return metrics

def generate_sample_traffic_csvs(sample_dir: str, df: pd.DataFrame):
    """Generates user-testable sample flow CSV files containing IPs, ports, and protocols."""
    print("Generating user sample traffic CSV files...")
    
    src_ips = [
        "192.168.1.105", "192.168.1.112", "192.168.1.140", "10.0.0.45",
        "172.16.0.22", "192.168.10.88", "198.51.100.4", "203.0.113.19",
        "45.33.32.156", "185.220.101.5", "91.189.91.43", "192.168.1.250"
    ]
    dst_ips = [
        "192.168.1.1", "192.168.1.10", "192.168.1.20", "10.0.0.1",
        "172.16.0.1", "10.10.10.50", "192.168.100.1", "10.0.1.25"
    ]
    protocols = ["TCP", "UDP", "ICMP"]
    
    # 1. cicids2017_sample_flows.csv: 150 diverse flows
    sample_df = df.sample(n=180, random_state=123).copy()
    n = len(sample_df)
    
    sample_df['Source IP'] = [np.random.choice(src_ips) for _ in range(n)]
    sample_df['Destination IP'] = [np.random.choice(dst_ips) for _ in range(n)]
    sample_df['Source Port'] = np.random.randint(1024, 65535, size=n)
    sample_df['Protocol'] = [np.random.choice(protocols, p=[0.75, 0.22, 0.03]) for _ in range(n)]
    sample_df['Timestamp'] = pd.date_range(end=pd.Timestamp.now(), periods=n, freq='30s').strftime('%Y-%m-%d %H:%M:%S')
    
    # Reorder columns with IP info first
    metadata_cols = ['Timestamp', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol']
    remaining_cols = [c for c in sample_df.columns if c not in metadata_cols and c != 'Label']
    final_cols = metadata_cols + remaining_cols + (['Label'] if 'Label' in sample_df.columns else [])
    sample_df = sample_df[final_cols]
    
    sample_path = os.path.join(sample_dir, 'cicids2017_sample_flows.csv')
    sample_df.to_csv(sample_path, index=False)
    print(f"Created sample dataset: {sample_path} ({len(sample_df)} records)")
    
    # 2. mixed_attack_traffic.csv: 80 high-threat flows
    attacks_df = df[df['Label'] != 'BENIGN'].sample(n=80, random_state=456).copy()
    m = len(attacks_df)
    attacks_df['Source IP'] = [np.random.choice(["45.33.32.156", "185.220.101.5", "194.26.29.112", "198.51.100.4", "103.203.57.18"]) for _ in range(m)]
    attacks_df['Destination IP'] = [np.random.choice(dst_ips) for _ in range(m)]
    attacks_df['Source Port'] = np.random.randint(1024, 65535, size=m)
    attacks_df['Protocol'] = [np.random.choice(["TCP", "UDP"], p=[0.85, 0.15]) for _ in range(m)]
    attacks_df['Timestamp'] = pd.date_range(end=pd.Timestamp.now(), periods=m, freq='15s').strftime('%Y-%m-%d %H:%M:%S')
    attacks_df = attacks_df[final_cols]
    
    attack_path = os.path.join(sample_dir, 'mixed_attack_traffic.csv')
    attacks_df.to_csv(attack_path, index=False)
    print(f"Created sample attack dataset: {attack_path} ({len(attacks_df)} records)")
    
    # 3. normal_corporate_traffic.csv: 100 benign flows
    benign_df = df[df['Label'] == 'BENIGN'].sample(n=100, random_state=789).copy()
    k = len(benign_df)
    benign_df['Source IP'] = [np.random.choice(["192.168.1.101", "192.168.1.102", "192.168.1.103", "192.168.1.104"]) for _ in range(k)]
    benign_df['Destination IP'] = [np.random.choice(["192.168.1.1", "8.8.8.8", "1.1.1.1", "142.250.190.46"]) for _ in range(k)]
    benign_df['Source Port'] = np.random.randint(1024, 65535, size=k)
    benign_df['Protocol'] = [np.random.choice(["TCP", "UDP"], p=[0.7, 0.3]) for _ in range(k)]
    benign_df['Timestamp'] = pd.date_range(end=pd.Timestamp.now(), periods=k, freq='20s').strftime('%Y-%m-%d %H:%M:%S')
    benign_df = benign_df[final_cols]
    
    benign_path = os.path.join(sample_dir, 'normal_corporate_traffic.csv')
    benign_df.to_csv(benign_path, index=False)
    print(f"Created sample normal dataset: {benign_path} ({len(benign_df)} records)")

if __name__ == '__main__':
    train_ids_model()
