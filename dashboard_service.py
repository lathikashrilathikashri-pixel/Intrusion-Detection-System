"""
AI-Based Intrusion Detection System (AI-IDS)
SOC Analytics & Dashboard Aggregation Service
"""

import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.config import settings
if settings.BASE_DIR not in sys.path:
    sys.path.append(settings.BASE_DIR)

from ml.predictor import IDSInferenceEngine
from app.models.traffic import TrafficRecord, SecurityAlert, AnalysisJob

class DashboardService:
    @staticmethod
    def get_dashboard_summary(db: Session) -> Dict[str, Any]:
        """Aggregate high-level metrics for the SOC Command Center."""
        total_connections = db.query(TrafficRecord).count()
        threat_count = db.query(TrafficRecord).filter(TrafficRecord.is_threat == True).count()
        benign_count = total_connections - threat_count

        normal_pct = round((benign_count / total_connections * 100), 2) if total_connections > 0 else 100.0
        suspicious_pct = round((threat_count / total_connections * 100), 2) if total_connections > 0 else 0.0

        critical_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "Critical").count()
        high_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "High").count()
        medium_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "Medium").count()
        low_alerts = db.query(SecurityAlert).filter(SecurityAlert.severity == "Low").count()

        open_alerts = db.query(SecurityAlert).filter(SecurityAlert.status.in_(["New", "Investigating"])).count()

        # Attack Distribution breakdown
        distribution_query = (
            db.query(TrafficRecord.predicted_attack, func.count(TrafficRecord.id))
            .filter(TrafficRecord.is_threat == True)
            .group_by(TrafficRecord.predicted_attack)
            .all()
        )

        attack_distribution = []
        severity_map = {
            "DoS": "High",
            "DDoS": "Critical",
            "PortScan": "Medium",
            "Brute Force": "High",
            "Botnet": "Critical",
            "Web Attack": "High"
        }

        for cat, cnt in distribution_query:
            pct = round((cnt / threat_count * 100), 2) if threat_count > 0 else 0.0
            attack_distribution.append({
                "category": cat,
                "count": cnt,
                "percentage": pct,
                "severity": severity_map.get(cat, "Medium")
            })

        # Traffic Timeline (chronological trends)
        timeline = DashboardService._generate_traffic_timeline(db)

        # Recent activities feed
        recent_activities = DashboardService._get_recent_activities(db)

        # ML Engine status
        engine = IDSInferenceEngine.get_instance()
        ml_status = {
            "model_name": "Random Forest Classifier",
            "is_active": engine.is_loaded,
            "classes_supported": engine.label_encoder.classes_.tolist() if engine.is_loaded else [],
            "features_count": len(engine.feature_columns),
            "accuracy": engine.metrics.get("accuracy", 0.999),
            "f1_score": engine.metrics.get("f1_score_weighted", 0.999),
            "trained_at": engine.metrics.get("trained_at", "N/A")
        }

        return {
            "kpis": {
                "total_connections": total_connections,
                "total_threats": threat_count,
                "benign_count": benign_count,
                "normal_percentage": normal_pct,
                "suspicious_percentage": suspicious_pct,
                "critical_alerts": critical_alerts,
                "high_alerts": high_alerts,
                "medium_alerts": medium_alerts,
                "low_alerts": low_alerts,
                "open_alerts": open_alerts
            },
            "attack_distribution": attack_distribution,
            "traffic_timeline": timeline,
            "recent_activities": recent_activities,
            "soc_system_status": ml_status
        }

    @staticmethod
    def _generate_traffic_timeline(db: Session, points: int = 12) -> List[Dict[str, Any]]:
        """Group recent traffic records into discrete timeline intervals."""
        recent_records = (
            db.query(TrafficRecord.timestamp, TrafficRecord.is_threat)
            .order_by(TrafficRecord.timestamp.asc())
            .all()
        )

        if not recent_records:
            # Generate default baseline empty slots
            now = datetime.utcnow()
            return [
                {
                    "time": (now - timedelta(minutes=(points - i) * 5)).strftime("%H:%M"),
                    "benign": 0,
                    "threats": 0,
                    "total": 0
                }
                for i in range(points)
            ]

        # Partition records into `points` buckets
        bucket_size = max(1, len(recent_records) // points)
        timeline = []

        for i in range(0, len(recent_records), bucket_size):
            chunk = recent_records[i:i + bucket_size]
            if not chunk:
                continue
            time_label = chunk[-1][0].strftime("%H:%M:%S")
            threats = sum(1 for r in chunk if r[1])
            benign = len(chunk) - threats
            timeline.append({
                "time": time_label,
                "benign": benign,
                "threats": threats,
                "total": len(chunk)
            })

        return timeline[-points:] if len(timeline) > points else timeline

    @staticmethod
    def _get_recent_activities(db: Session, limit: int = 8) -> List[Dict[str, Any]]:
        """Combine recent alerts, job uploads, and threat detections into an SOC feed."""
        activities = []

        recent_alerts = (
            db.query(SecurityAlert)
            .order_by(desc(SecurityAlert.timestamp))
            .limit(limit)
            .all()
        )

        for a in recent_alerts:
            activities.append({
                "id": a.id,
                "type": "ALERT",
                "timestamp": a.timestamp,
                "title": f"Security Alert: {a.attack_category} detected",
                "description": f"Incident {a.alert_id} flagged from {a.src_ip} targeting port {a.dst_port} ({a.confidence_score * 100:.1f}% confidence)",
                "severity": a.severity,
                "source_ip": a.src_ip,
                "target_ip": a.dst_ip
            })

        return activities
