"""
AI-Based Intrusion Detection System (AI-IDS)
Project Code: RW-CS-001 | RW Software Solutions
Automated Test Suite (Direct Integration Tests)
"""

import os
import sys
import pytest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.join(BASE_DIR, 'backend'))
sys.path.append(BASE_DIR)

from app.database import SessionLocal, engine, Base
from app.models.user import User
from app.models.traffic import TrafficRecord, SecurityAlert, AnalysisJob
from app.schemas.auth_schemas import UserLogin, UserProfileUpdate
from app.schemas.traffic_schemas import ManualFlowPredictRequest
from app.schemas.alert_schemas import AlertStatusUpdate
from app.services.auth_service import verify_password, hash_password, create_access_token, decode_access_token
from app.services.traffic_service import TrafficService
from app.services.alert_service import AlertService
from app.services.dashboard_service import DashboardService
from ml.predictor import IDSInferenceEngine

@pytest.fixture(scope="module")
def db_session():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()

def test_ml_model_artifacts():
    """Verify that Random Forest model artifacts are loaded and calibrated."""
    engine_ml = IDSInferenceEngine.get_instance()
    assert engine_ml.is_loaded is True
    assert len(engine_ml.feature_columns) == 43
    assert len(engine_ml.label_encoder.classes_) == 7
    assert engine_ml.metrics["accuracy"] >= 0.95

def test_ml_prediction_benign():
    """Verify inference classifies standard web browsing flow."""
    engine_ml = IDSInferenceEngine.get_instance()
    flow = {
        'Destination Port': 443,
        'Flow Duration': 180000.0,
        'Total Fwd Packets': 12,
        'Total Backward Packets': 14,
        'SYN Flag Count': 1,
        'ACK Flag Count': 1,
        'PSH Flag Count': 1
    }
    pred = engine_ml.predict_flow(flow)
    assert "predicted_attack" in pred
    assert "confidence" in pred
    assert "probabilities" in pred
    assert 0.0 <= pred["confidence"] <= 1.0

def test_ml_prediction_dos():
    """Verify inference classifies DoS slowloris characteristics."""
    engine_ml = IDSInferenceEngine.get_instance()
    flow = {
        'Destination Port': 80,
        'Flow Duration': 6500000.0,
        'Total Fwd Packets': 20,
        'Total Backward Packets': 1,
        'SYN Flag Count': 1,
        'RST Flag Count': 1,
        'PSH Flag Count': 1,
        'Down/Up Ratio': 0.05
    }
    pred = engine_ml.predict_flow(flow)
    assert pred["is_threat"] is True
    assert pred["severity"] in ["Medium", "High", "Critical"]

def test_auth_service():
    """Verify password hashing, verification, and JWT creation/decoding."""
    password = "TestAdminSecurePassword@2026"
    hashed = hash_password(password)
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword", hashed) is False

    token = create_access_token({"sub": "admin", "role": "ADMIN"})
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "admin"
    assert payload["role"] == "ADMIN"

def test_dashboard_service(db_session):
    """Verify SOC dashboard metrics calculation and aggregations."""
    stats = DashboardService.get_dashboard_summary(db_session)
    assert "kpis" in stats
    assert "attack_distribution" in stats
    assert "traffic_timeline" in stats
    assert "recent_activities" in stats
    assert stats["kpis"]["total_connections"] > 0
    assert stats["kpis"]["normal_percentage"] + stats["kpis"]["suspicious_percentage"] <= 100.1

def test_alert_service(db_session):
    """Verify alert retrieval, filtering, and status updates."""
    alerts, total = AlertService.get_alerts(db_session, skip=0, limit=10)
    assert total > 0
    assert len(alerts) > 0

    first_alert = alerts[0]
    update_data = AlertStatusUpdate(
        status="Investigating",
        assigned_to="SOC Analyst Delta",
        notes="Under initial triage"
    )
    updated = AlertService.update_alert(db_session, first_alert.id, update_data)
    assert updated.status == "Investigating"
    assert updated.assigned_to == "SOC Analyst Delta"

def test_alert_export_csv(db_session):
    """Verify security alerts CSV export formatting."""
    csv_str = AlertService.export_alerts_csv(db_session)
    assert "Alert ID" in csv_str
    assert "Attack Category" in csv_str
    assert "Confidence Score" in csv_str
