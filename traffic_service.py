"""
AI-Based Intrusion Detection System (AI-IDS)
Traffic Ingestion, Prediction & Storage Service
"""

import os
import sys
import uuid
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.config import settings
if settings.BASE_DIR not in sys.path:
    sys.path.append(settings.BASE_DIR)

from ml.predictor import IDSInferenceEngine
from app.models.traffic import AnalysisJob, TrafficRecord, SecurityAlert

class TrafficService:
    @staticmethod
    def process_csv_dataframe(
        df: pd.DataFrame,
        filename: str,
        db: Session,
        source_type: str = "CSV_UPLOAD"
    ) -> Dict[str, Any]:
        """Ingest, run AI classification, and persist flow records and alerts."""
        engine = IDSInferenceEngine.get_instance()
        if not engine.is_loaded:
            engine.load_artifacts()

        job_uuid = f"JOB-{uuid.uuid4().hex[:8].upper()}"
        df_clean = df.copy()
        df_clean.columns = df_clean.columns.str.strip()

        # Run model batch prediction
        predictions = engine.predict_batch(df_clean)

        total_records = len(predictions)
        benign_count = sum(1 for p in predictions if not p["is_threat"])
        threat_count = total_records - benign_count

        # Create Analysis Job record
        job = AnalysisJob(
            job_uuid=job_uuid,
            filename=filename,
            source_type=source_type,
            total_records=total_records,
            benign_count=benign_count,
            threat_count=threat_count,
            status="COMPLETED",
            created_at=datetime.utcnow()
        )
        db.add(job)
        db.flush() # flush to get job.id

        # Determine column mappings for network headers
        ip_src_col = next((c for c in df_clean.columns if c.lower() in ['source ip', 'src_ip', 'src ip', 'sourceip']), None)
        ip_dst_col = next((c for c in df_clean.columns if c.lower() in ['destination ip', 'dst_ip', 'dst ip', 'destinationip']), None)
        port_src_col = next((c for c in df_clean.columns if c.lower() in ['source port', 'src_port', 'src port']), None)
        port_dst_col = next((c for c in df_clean.columns if c.lower() in ['destination port', 'dst_port', 'dst port', 'destinationport']), None)
        proto_col = next((c for c in df_clean.columns if c.lower() in ['protocol', 'proto']), None)
        time_col = next((c for c in df_clean.columns if c.lower() in ['timestamp', 'time']), None)

        default_src_ips = ["192.168.1.105", "192.168.1.112", "10.0.0.45", "172.16.0.22", "198.51.100.4", "45.33.32.156"]
        default_dst_ips = ["192.168.1.1", "192.168.1.10", "10.0.0.1", "172.16.0.1"]

        attack_breakdown: Dict[str, int] = {}
        alerts_created = 0

        # Batch insert records
        for i, pred in enumerate(predictions):
            row = df_clean.iloc[i]

            src_ip = str(row[ip_src_col]) if ip_src_col else default_src_ips[i % len(default_src_ips)]
            dst_ip = str(row[ip_dst_col]) if ip_dst_col else default_dst_ips[i % len(default_dst_ips)]
            src_port = int(row[port_src_col]) if port_src_col and pd.notnull(row[port_src_col]) else int(49152 + (i % 1000))
            dst_port = int(row[port_dst_col]) if port_dst_col and pd.notnull(row[port_dst_col]) else int(row.get('Destination Port', 80))
            protocol = str(row[proto_col]) if proto_col else "TCP"

            record_time = datetime.utcnow() - timedelta(seconds=(total_records - i) * 10)
            if time_col and pd.notnull(row[time_col]):
                try:
                    record_time = pd.to_datetime(row[time_col]).to_pydatetime()
                except Exception:
                    pass

            duration = float(row.get('Flow Duration', 0.0))
            fwd_pkts = int(row.get('Total Fwd Packets', 1))
            bwd_pkts = int(row.get('Total Backward Packets', 0))
            bytes_s = float(row.get('Flow Bytes/s', 0.0))
            pkts_s = float(row.get('Flow Packets/s', 0.0))

            attack_name = pred["predicted_attack"]
            attack_breakdown[attack_name] = attack_breakdown.get(attack_name, 0) + 1

            record = TrafficRecord(
                job_id=job.id,
                timestamp=record_time,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                flow_duration=duration,
                total_fwd_packets=fwd_pkts,
                total_bwd_packets=bwd_pkts,
                flow_bytes_s=bytes_s,
                flow_packets_s=pkts_s,
                predicted_attack=attack_name,
                confidence=pred["confidence"],
                is_threat=pred["is_threat"],
                severity=pred["severity"],
                probabilities=pred["probabilities"]
            )
            db.add(record)
            db.flush() # get record.id

            # Generate Security Alert for malicious traffic
            if pred["is_threat"]:
                alerts_created += 1
                alert_id = f"ALT-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
                
                mitigation_map = {
                    "DoS": f"Rate-limit incoming requests from {src_ip} and inspect firewall SYN flood rules on port {dst_port}.",
                    "DDoS": f"Trigger automated DDoS scrubbing profile, apply geo-blocking and null-route traffic targeting port {dst_port}.",
                    "PortScan": f"Temporarily blacklist host {src_ip} in perimeter firewall and drop stealth reconnaissance probe packets.",
                    "Brute Force": f"Enable fail2ban lockdown on host {src_ip}, enforce multi-factor authentication on port {dst_port}.",
                    "Botnet": f"Isolate compromised endpoint, block Command & Control IP {src_ip} at egress DNS proxy.",
                    "Web Attack": f"Deploy WAF signature blocking for SQLi/XSS on port {dst_port} and inspect web application input sanitation."
                }
                
                alert = SecurityAlert(
                    alert_id=alert_id,
                    traffic_record_id=record.id,
                    timestamp=record_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    protocol=protocol,
                    attack_category=attack_name,
                    severity=pred["severity"],
                    confidence_score=pred["confidence"],
                    status="New",
                    assigned_to=None,
                    notes=f"AI-IDS detected high-probability {attack_name} threat ({pred['confidence_percentage']}% confidence).",
                    mitigation_action=mitigation_map.get(attack_name, "Investigate endpoint flow activity.")
                )
                db.add(alert)

        db.commit()

        return {
            "job_uuid": job_uuid,
            "filename": filename,
            "total_records": total_records,
            "benign_count": benign_count,
            "threat_count": threat_count,
            "threat_percentage": round((threat_count / total_records * 100), 2) if total_records > 0 else 0.0,
            "attack_breakdown": attack_breakdown,
            "alerts_generated": alerts_created,
            "processed_at": job.created_at
        }

    @staticmethod
    def get_traffic_records(
        db: Session,
        skip: int = 0,
        limit: int = 100,
        threat_only: Optional[bool] = None,
        attack_type: Optional[str] = None,
        search_ip: Optional[str] = None
    ) -> List[TrafficRecord]:
        """Fetch network traffic records with filtering and pagination."""
        query = db.query(TrafficRecord)

        if threat_only is not None:
            query = query.filter(TrafficRecord.is_threat == threat_only)
        if attack_type:
            query = query.filter(TrafficRecord.predicted_attack.ilike(f"%{attack_type}%"))
        if search_ip:
            query = query.filter((TrafficRecord.src_ip.ilike(f"%{search_ip}%")) | (TrafficRecord.dst_ip.ilike(f"%{search_ip}%")))

        return query.order_by(desc(TrafficRecord.timestamp)).offset(skip).limit(limit).all()

    @staticmethod
    def seed_initial_sample_data(db: Session) -> bool:
        """Seed sample traffic if database is freshly initialized."""
        existing_count = db.query(TrafficRecord).count()
        if existing_count > 0:
            return False

        sample_file = os.path.join(settings.SAMPLE_DATA_DIR, "cicids2017_sample_flows.csv")
        if os.path.exists(sample_file):
            print(f"[TrafficService] Seeding initial sample traffic from {sample_file}...")
            df = pd.read_csv(sample_file)
            TrafficService.process_csv_dataframe(df, "cicids2017_sample_flows.csv", db, "BENCHMARK_SEED")
            return True
        return False
