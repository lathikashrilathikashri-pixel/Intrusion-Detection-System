"""
AI-Based Intrusion Detection System (AI-IDS)
AI Model Evaluation & Performance Metrics Router
"""

import sys
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.config import settings
if settings.BASE_DIR not in sys.path:
    sys.path.append(settings.BASE_DIR)

from ml.predictor import IDSInferenceEngine
from app.schemas.model_schemas import ModelPerformanceResponse
from app.services.auth_service import get_current_user
from app.models.user import User

router = APIRouter(prefix="/model", tags=["AI Model Performance"])

@router.get("/performance", response_model=ModelPerformanceResponse)
def get_model_performance(current_user: User = Depends(get_current_user)):
    """
    Retrieve genuine machine learning evaluation metrics, confusion matrix,
    per-class precision/recall/F1 and feature importances calculated on the held-out test set.
    """
    engine = IDSInferenceEngine.get_instance()
    if not engine.is_loaded:
        if not engine.load_artifacts():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Model artifacts could not be loaded."
            )

    m = engine.metrics
    if not m:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evaluation metrics are not yet calculated."
        )

    return {
        "model_name": m.get("model_name", "Random Forest Classifier"),
        "algorithm": m.get("algorithm", "RandomForestClassifier"),
        "parameters": m.get("parameters", {}),
        "classes": m.get("classes", []),
        "n_samples_train": m.get("n_samples_train", 0),
        "n_samples_test": m.get("n_samples_test", 0),
        "accuracy": m.get("accuracy", 0.0),
        "precision_weighted": m.get("precision_weighted", 0.0),
        "precision_macro": m.get("precision_macro", 0.0),
        "recall_weighted": m.get("recall_weighted", 0.0),
        "recall_macro": m.get("recall_macro", 0.0),
        "f1_score_weighted": m.get("f1_score_weighted", 0.0),
        "f1_score_macro": m.get("f1_score_macro", 0.0),
        "confusion_matrix": m.get("confusion_matrix", []),
        "classification_report": m.get("classification_report", {}),
        "top_features": m.get("top_features", []),
        "trained_at": m.get("trained_at", "Unknown"),
        "is_active": engine.is_loaded
    }

@router.post("/retrain")
def retrain_model(current_user: User = Depends(get_current_user)):
    """Retrain Random Forest model on benchmark dataset and re-evaluate test set."""
    if current_user.role != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can trigger model retraining."
        )

    from ml.train import train_ids_model
    try:
        metrics = train_ids_model(n_samples=25000)
        # Reload engine artifacts
        engine = IDSInferenceEngine.get_instance()
        engine.load_artifacts()
        return {
            "message": "Model retrained and artifacts successfully reloaded.",
            "accuracy": metrics["accuracy"],
            "f1_score": metrics["f1_score_weighted"]
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model retraining failed: {str(e)}"
        )
