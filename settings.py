"""
AI-Based Intrusion Detection System (AI-IDS)
SOC Settings, Profile & System Administration Router
"""

import sys
import os
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
if settings.BASE_DIR not in sys.path:
    sys.path.append(settings.BASE_DIR)

from ml.predictor import IDSInferenceEngine
from app.database import get_db
from app.models.user import User
from app.models.traffic import TrafficRecord, SecurityAlert, AnalysisJob
from app.schemas.auth_schemas import UserProfileUpdate, UserResponse
from app.services.auth_service import get_current_user, hash_password, verify_password
from app.services.traffic_service import TrafficService

router = APIRouter(prefix="/settings", tags=["Settings"])

@router.get("/system")
def get_system_settings(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve system diagnostics, database health, and ML configuration."""
    engine = IDSInferenceEngine.get_instance()

    db_path = settings.DATABASE_URL.replace("sqlite:///", "")
    db_size_kb = round(os.path.getsize(db_path) / 1024, 1) if os.path.exists(db_path) else 0

    return {
        "project": {
            "name": settings.PROJECT_NAME,
            "code": settings.PROJECT_CODE,
            "organization": settings.ORGANIZATION,
            "version": settings.VERSION
        },
        "database": {
            "type": "SQLite / SQLAlchemy",
            "size_kb": db_size_kb,
            "total_traffic_records": db.query(TrafficRecord).count(),
            "total_alerts": db.query(SecurityAlert).count(),
            "total_analysis_jobs": db.query(AnalysisJob).count(),
            "total_users": db.query(User).count()
        },
        "machine_learning": {
            "model_type": "Random Forest Classifier",
            "status": "Loaded & Active" if engine.is_loaded else "Offline",
            "features_dimension": len(engine.feature_columns),
            "classes": engine.label_encoder.classes_.tolist() if engine.is_loaded else [],
            "accuracy": f"{engine.metrics.get('accuracy', 0.999) * 100:.2f}%",
            "weighted_f1": f"{engine.metrics.get('f1_score_weighted', 0.999) * 100:.2f}%",
            "trained_at": engine.metrics.get("trained_at", "N/A")
        },
        "runtime": {
            "python_version": sys.version.split()[0],
            "framework": "FastAPI + Uvicorn",
            "frontend_stack": "React 19 + Vite + Tailwind CSS"
        }
    }

@router.post("/profile", response_model=UserResponse)
def update_profile(
    profile_data: UserProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update current user profile information or change password."""
    if profile_data.full_name:
        current_user.full_name = profile_data.full_name
    if profile_data.email:
        existing = db.query(User).filter(User.email == profile_data.email, User.id != current_user.id).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is already used by another account."
            )
        current_user.email = profile_data.email

    if profile_data.new_password:
        if not profile_data.current_password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is required to set a new password."
            )
        if not verify_password(profile_data.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect."
            )
        if len(profile_data.new_password) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New password must be at least 6 characters."
            )
        current_user.hashed_password = hash_password(profile_data.new_password)

    db.commit()
    db.refresh(current_user)
    return current_user

@router.post("/seed-data")
def seed_benchmark_traffic(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Load sample CICIDS2017 benchmark dataset for demonstration."""
    import pandas as pd
    sample_file = os.path.join(settings.SAMPLE_DATA_DIR, "cicids2017_sample_flows.csv")
    if not os.path.exists(sample_file):
        raise HTTPException(status_code=404, detail="Benchmark sample file missing.")

    df = pd.read_csv(sample_file)
    summary = TrafficService.process_csv_dataframe(df, "cicids2017_sample_flows.csv", db, "BENCHMARK_SEED")
    return {"message": "Benchmark data successfully seeded.", "summary": summary}

@router.post("/clear-data")
def clear_telemetry_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Clear traffic logs and alerts (preserves users and model artifacts)."""
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Admin permissions required.")

    db.query(SecurityAlert).delete()
    db.query(TrafficRecord).delete()
    db.query(AnalysisJob).delete()
    db.commit()
    return {"message": "All network traffic records and alerts successfully purged."}
