"""
AI-Based Intrusion Detection System (AI-IDS)
Security Alert Management & Remediation Service
"""

import io
import csv
from datetime import datetime
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.traffic import SecurityAlert
from app.schemas.alert_schemas import AlertStatusUpdate

class AlertService:
    @staticmethod
    def get_alerts(
        db: Session,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None
    ) -> Tuple[List[SecurityAlert], int]:
        """Query security alerts with filtering, search, and pagination."""
        query = db.query(SecurityAlert)

        if severity and severity.upper() != "ALL":
            query = query.filter(SecurityAlert.severity.ilike(severity))
        if status and status.upper() != "ALL":
            query = query.filter(SecurityAlert.status.ilike(status))
        if search:
            search_pattern = f"%{search}%"
            query = query.filter(
                (SecurityAlert.alert_id.ilike(search_pattern)) |
                (SecurityAlert.src_ip.ilike(search_pattern)) |
                (SecurityAlert.dst_ip.ilike(search_pattern)) |
                (SecurityAlert.attack_category.ilike(search_pattern)) |
                (SecurityAlert.notes.ilike(search_pattern))
            )

        total_count = query.count()
        alerts = query.order_by(desc(SecurityAlert.timestamp)).offset(skip).limit(limit).all()
        return alerts, total_count

    @staticmethod
    def get_alert_by_id(db: Session, alert_id: int) -> Optional[SecurityAlert]:
        return db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()

    @staticmethod
    def update_alert(db: Session, alert_id: int, update_data: AlertStatusUpdate) -> Optional[SecurityAlert]:
        alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
        if not alert:
            return None

        if update_data.status:
            alert.status = update_data.status
        if update_data.assigned_to is not None:
            alert.assigned_to = update_data.assigned_to
        if update_data.notes is not None:
            alert.notes = update_data.notes
        if update_data.mitigation_action is not None:
            alert.mitigation_action = update_data.mitigation_action

        alert.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(alert)
        return alert

    @staticmethod
    def export_alerts_csv(db: Session) -> str:
        """Export all alerts into a RFC 4180 CSV string for download."""
        alerts = db.query(SecurityAlert).order_by(desc(SecurityAlert.timestamp)).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Alert ID", "Timestamp", "Source IP", "Destination IP", "Port",
            "Protocol", "Attack Category", "Severity", "Confidence Score",
            "Investigation Status", "Assigned Analyst", "Mitigation Action", "Analyst Notes"
        ])

        for a in alerts:
            writer.writerow([
                a.alert_id,
                a.timestamp.strftime("%Y-%m-%d %H:%M:%S") if a.timestamp else "",
                a.src_ip,
                a.dst_ip,
                a.dst_port,
                a.protocol,
                a.attack_category,
                a.severity,
                f"{a.confidence_score * 100:.2f}%",
                a.status,
                a.assigned_to or "Unassigned",
                a.mitigation_action or "",
                a.notes or ""
            ])

        return output.getvalue()
