"""
AI-Based Intrusion Detection System (AI-IDS)
Security Alert Pydantic Schemas
"""

from pydantic import BaseModel, ConfigDict
from typing import Optional
from datetime import datetime

class AlertResponse(BaseModel):
    id: int
    alert_id: str
    traffic_record_id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    attack_category: str
    severity: str
    confidence_score: float
    status: str
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    mitigation_action: Optional[str] = None
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class AlertStatusUpdate(BaseModel):
    status: str # New, Investigating, Resolved, False Positive
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    mitigation_action: Optional[str] = None
