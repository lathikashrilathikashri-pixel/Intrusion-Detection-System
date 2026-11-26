"""
AI-Based Intrusion Detection System (AI-IDS)
Project Code: RW-CS-001 | RW Software Solutions
ML Inference & Threat Classification Engine
"""

import os
import json
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple

class IDSInferenceEngine:
    _instance = None

    def __init__(self, models_dir: str = None):
        if models_dir is None:
            models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
        self.models_dir = models_dir
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_columns: List[str] = []
        self.metrics: Dict[str, Any] = {}
        self.is_loaded = False
        self.load_artifacts()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = IDSInferenceEngine()
        return cls._instance

    def load_artifacts(self) -> bool:
        try:
            model_path = os.path.join(self.models_dir, 'rf_ids_model.joblib')
            scaler_path = os.path.join(self.models_dir, 'scaler.joblib')
            le_path = os.path.join(self.models_dir, 'label_encoder.joblib')
            feat_path = os.path.join(self.models_dir, 'features.json')
            metrics_path = os.path.join(self.models_dir, 'metrics.json')

            if not (os.path.exists(model_path) and os.path.exists(scaler_path) and os.path.exists(le_path)):
                print(f"[IDSInferenceEngine] Artifacts missing in {self.models_dir}. Run ml/train.py first.")
                self.is_loaded = False
                return False

            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(le_path)

            with open(feat_path, 'r') as f:
                self.feature_columns = json.load(f)

            if os.path.exists(metrics_path):
                with open(metrics_path, 'r') as f:
                    self.metrics = json.load(f)

            self.is_loaded = True
            print(f"[IDSInferenceEngine] Successfully loaded Random Forest model ({len(self.feature_columns)} features, {len(self.label_encoder.classes_)} classes).")
            return True
        except Exception as e:
            print(f"[IDSInferenceEngine] Error loading model artifacts: {e}")
            self.is_loaded = False
            return False

    def _determine_severity(self, attack_category: str, confidence: float) -> str:
        """Assign standardized SOC severity level based on attack type and model confidence."""
        if attack_category == 'BENIGN':
            return 'Low'
        if attack_category in ['DDoS', 'Botnet']:
            return 'Critical'
        if attack_category in ['DoS', 'Web Attack']:
            return 'Critical' if confidence >= 0.88 else 'High'
        if attack_category == 'Brute Force':
            return 'High' if confidence >= 0.80 else 'Medium'
        if attack_category == 'PortScan':
            return 'Medium'
        return 'Medium'

    def predict_flow(self, flow_data: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single network flow record."""
        if not self.is_loaded:
            if not self.load_artifacts():
                raise RuntimeError("Machine Learning model is not trained or loaded. Run ml/train.py first.")

        # Construct feature vector
        vector = []
        for feat in self.feature_columns:
            val = flow_data.get(feat, 0.0)
            try:
                num_val = float(val)
                if np.isnan(num_val) or np.isneginf(num_val) or np.isposinf(num_val):
                    num_val = 0.0
            except (ValueError, TypeError):
                num_val = 0.0
            vector.append(num_val)

        X_df = pd.DataFrame([vector], columns=self.feature_columns)
        X_scaled = self.scaler.transform(X_df)

        y_pred = self.model.predict(X_scaled)[0]
        y_prob = self.model.predict_proba(X_scaled)[0]

        predicted_class = self.label_encoder.inverse_transform([y_pred])[0]
        confidence = float(np.max(y_prob))

        # Probability distribution across all supported classes
        classes = self.label_encoder.classes_
        prob_dict = {str(cls_name): float(prob) for cls_name, prob in zip(classes, y_prob)}

        is_threat = (predicted_class != 'BENIGN')
        severity = self._determine_severity(predicted_class, confidence)

        return {
            "predicted_attack": str(predicted_class),
            "confidence": round(confidence, 4),
            "confidence_percentage": round(confidence * 100, 2),
            "is_threat": is_threat,
            "severity": severity,
            "probabilities": prob_dict
        }

    def predict_batch(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Classify a batch of flow records (e.g. from CSV upload)."""
        if not self.is_loaded:
            if not self.load_artifacts():
                raise RuntimeError("Machine Learning model is not trained or loaded.")

        df_work = df.copy()
        df_work.columns = df_work.columns.str.strip()

        # Build feature matrix
        matrix = []
        for feat in self.feature_columns:
            if feat in df_work.columns:
                series = pd.to_numeric(df_work[feat], errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0.0)
                matrix.append(series.values)
            else:
                matrix.append(np.zeros(len(df_work)))

        X_df = pd.DataFrame(np.column_stack(matrix), columns=self.feature_columns)
        X_scaled = self.scaler.transform(X_df)

        preds = self.model.predict(X_scaled)
        probs = self.model.predict_proba(X_scaled)
        classes = self.label_encoder.classes_

        results = []
        for i in range(len(df_work)):
            pred_idx = preds[i]
            predicted_class = str(self.label_encoder.inverse_transform([pred_idx])[0])
            confidence = float(np.max(probs[i]))
            is_threat = (predicted_class != 'BENIGN')
            severity = self._determine_severity(predicted_class, confidence)

            prob_dict = {str(cls_name): float(probs[i][j]) for j, cls_name in enumerate(classes)}

            results.append({
                "predicted_attack": predicted_class,
                "confidence": round(confidence, 4),
                "confidence_percentage": round(confidence * 100, 2),
                "is_threat": is_threat,
                "severity": severity,
                "probabilities": prob_dict
            })

        return results
