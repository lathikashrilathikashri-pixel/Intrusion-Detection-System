"""
AI-Based Intrusion Detection System (AI-IDS)
Security Alerts Incident Management Router
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.user import User
from app.schemas.alert_schemas import AlertResponse, AlertStatusUpdate
from app.services.alert_service import AlertService
from app.services.auth_service import get_current_user

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])

@router.get("", response_model=List[AlertResponse])
def get_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Query security alerts with severity, status and search filters."""
    alerts, _ = AlertService.get_alerts(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
        search=search
    )
    return alerts

@router.get("/export/csv")
def export_alerts_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Download security alerts in CSV format for audit reporting."""
    csv_data = AlertService.export_alerts_csv(db)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=security_alerts_export.csv"}
    )

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_detail(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve detailed telemetry for a single security alert."""
    alert = AlertService.get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert #{alert_id} not found."
        )
    return alert

@router.patch("/{alert_id}/status", response_model=AlertResponse)
def update_alert_status(
    alert_id: int,
    update_data: AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update investigation status, assign analyst, or document mitigation actions."""
    if not update_data.assigned_to:
        update_data.assigned_to = current_user.full_name

    updated = AlertService.update_alert(db, alert_id, update_data)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert #{alert_id} not found."
        )
    return updated
