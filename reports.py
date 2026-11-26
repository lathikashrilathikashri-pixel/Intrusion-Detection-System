"""
AI-Based Intrusion Detection System (AI-IDS)
Security Intelligence & Executive Reports Router
"""

import io
import csv
from datetime import datetime
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.database import get_db
from app.models.traffic import TrafficRecord, SecurityAlert, AnalysisJob
from app.models.user import User
from app.services.auth_service import get_current_user
from app.services.alert_service import AlertService

router = APIRouter(prefix="/reports", tags=["Reports & Intelligence"])

@router.get("/summary")
def get_executive_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Generate an executive threat intelligence summary report including
    overall posture, top targeted ports, top attacking IPs, and severity breakdowns.
    """
    total_flows = db.query(TrafficRecord).count()
    threat_flows = db.query(TrafficRecord).filter(TrafficRecord.is_threat == True).count()
    benign_flows = total_flows - threat_flows

    total_alerts = db.query(SecurityAlert).count()
    resolved_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "Resolved").count()
    investigating_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "Investigating").count()
    new_alerts = db.query(SecurityAlert).filter(SecurityAlert.status == "New").count()
    false_positives = db.query(SecurityAlert).filter(SecurityAlert.status == "False Positive").count()

    # Top Attacking IPs
    top_attackers_query = (
        db.query(TrafficRecord.src_ip, func.count(TrafficRecord.id).label("count"))
        .filter(TrafficRecord.is_threat == True)
        .group_by(TrafficRecord.src_ip)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    top_attackers = [{"ip": ip, "threats": cnt} for ip, cnt in top_attackers_query]

    # Top Targeted Ports
    top_ports_query = (
        db.query(TrafficRecord.dst_port, func.count(TrafficRecord.id).label("count"))
        .filter(TrafficRecord.is_threat == True)
        .group_by(TrafficRecord.dst_port)
        .order_by(desc("count"))
        .limit(5)
        .all()
    )
    top_ports = [{"port": port, "threats": cnt} for port, cnt in top_ports_query]

    # Severity Breakdown
    severities = ["Critical", "High", "Medium", "Low"]
    severity_breakdown = {}
    for s in severities:
        count = db.query(SecurityAlert).filter(SecurityAlert.severity == s).count()
        severity_breakdown[s] = count

    # Protocol Breakdown
    protocols_query = (
        db.query(TrafficRecord.protocol, func.count(TrafficRecord.id).label("count"))
        .group_by(TrafficRecord.protocol)
        .all()
    )
    protocols = {proto: cnt for proto, cnt in protocols_query}

    # Analysis Jobs History
    jobs = (
        db.query(AnalysisJob)
        .order_by(desc(AnalysisJob.created_at))
        .limit(10)
        .all()
    )
    job_history = [
        {
            "job_uuid": j.job_uuid,
            "filename": j.filename,
            "total_records": j.total_records,
            "threat_count": j.threat_count,
            "benign_count": j.benign_count,
            "source_type": j.source_type,
            "created_at": j.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for j in jobs
    ]

    return {
        "report_id": f"SOC-RPT-{datetime.utcnow().strftime('%Y%m%d%H%M')}",
        "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "analyst": current_user.full_name,
        "organization": "RW Software Solutions",
        "project_code": "RW-CS-001",
        "posture": {
            "total_traffic_analysed": total_flows,
            "benign_connections": benign_flows,
            "threats_detected": threat_flows,
            "threat_ratio_percent": round((threat_flows / total_flows * 100), 2) if total_flows > 0 else 0.0,
            "total_security_alerts": total_alerts,
            "resolution_rate_percent": round((resolved_alerts / total_alerts * 100), 2) if total_alerts > 0 else 100.0
        },
        "alert_status_breakdown": {
            "New": new_alerts,
            "Investigating": investigating_alerts,
            "Resolved": resolved_alerts,
            "False_Positive": false_positives
        },
        "severity_breakdown": severity_breakdown,
        "protocol_breakdown": protocols,
        "top_attacking_ips": top_attackers,
        "top_targeted_ports": top_ports,
        "recent_ingestion_jobs": job_history
    }

@router.get("/export-traffic-csv")
def export_traffic_csv(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Export network flow records to CSV."""
    records = db.query(TrafficRecord).order_by(desc(TrafficRecord.timestamp)).limit(1000).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Record ID", "Timestamp", "Source IP", "Destination IP", "Source Port",
        "Destination Port", "Protocol", "Duration", "Packets", "Bytes/s",
        "Predicted Attack", "Confidence", "Is Threat", "Severity"
    ])

    for r in records:
        writer.writerow([
            r.id,
            r.timestamp.strftime("%Y-%m-%d %H:%M:%S") if r.timestamp else "",
            r.src_ip,
            r.dst_ip,
            r.src_port,
            r.dst_port,
            r.protocol,
            r.flow_duration,
            r.total_fwd_packets + r.total_bwd_packets,
            r.flow_bytes_s,
            r.predicted_attack,
            f"{r.confidence * 100:.2f}%",
            "YES" if r.is_threat else "NO",
            r.severity
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=traffic_flows_export.csv"}
    )
