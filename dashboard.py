"""
AI-Based Intrusion Detection System (AI-IDS)
Dashboard Router
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.dashboard_schemas import DashboardStats
from app.services.dashboard_service import DashboardService
from app.services.auth_service import get_current_user
from app.models.user import User

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats", response_model=DashboardStats)
def get_stats(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieve full SOC telemetry, KPIs, attack distribution, timeline and feeds."""
    return DashboardService.get_dashboard_summary(db)
