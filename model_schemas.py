"""
AI-Based Intrusion Detection System (AI-IDS)
Model Performance & Evaluation Schemas
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional

class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float

class ModelPerformanceResponse(BaseModel):
    model_name: str
    algorithm: str
    parameters: Dict[str, Any]
    classes: List[str]
    n_samples_train: int
    n_samples_test: int
    accuracy: float
    precision_weighted: float
    precision_macro: float
    recall_weighted: float
    recall_macro: float
    f1_score_weighted: float
    f1_score_macro: float
    confusion_matrix: List[List[int]]
    classification_report: Dict[str, Any]
    top_features: List[FeatureImportanceItem]
    trained_at: str
    is_active: bool
