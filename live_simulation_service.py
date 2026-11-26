"""
AI-Based Intrusion Detection System (AI-IDS)
Live Traffic Simulation & Monitor Service
"""

import sys
import random
from datetime import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.config import settings
if settings.BASE_DIR not in sys.path:
    sys.path.append(settings.BASE_DIR)

from ml.predictor import IDSInferenceEngine
from app.models.traffic import TrafficRecord, SecurityAlert

class LiveMonitorService:
    _is_running = False

    @classmethod
    def is_active(cls) -> bool:
        return cls._is_running

    @classmethod
    def set_active(cls, active: bool):
        cls._is_running = active

    @classmethod
    def generate_single_live_flow(cls, db: Session) -> Dict[str, Any]:
        """
        Synthesizes a realistic live flow packet, runs real Random Forest inference,
        and records it in the database with an alert if malicious.
        """
        engine = IDSInferenceEngine.get_instance()
        if not engine.is_loaded:
            engine.load_artifacts()

        # Decide whether this packet simulates normal traffic (75%) or an attack (25%)
        is_attack_sim = random.random() < 0.28
        
        src_pool = [
            "192.168.1.102", "192.168.1.108", "192.168.1.145", "10.0.0.18",
            "185.220.101.5", "45.33.32.156", "198.51.100.4", "103.203.57.18"
        ]
        dst_pool = ["192.168.1.1", "192.168.1.10", "192.168.1.25", "10.0.0.1"]

        src_ip = random.choice(src_pool)
        dst_ip = random.choice(dst_pool)
        src_port = random.randint(1024, 65535)
        protocol = random.choice(["TCP", "TCP", "TCP", "UDP"])

        flow_dict = {}

        if not is_attack_sim:
            dst_port = random.choice([80, 443, 53, 22, 8080])
            duration = float(random.randint(15000, 250000))
            fwd_pkts = random.randint(3, 15)
            bwd_pkts = random.randint(2, 14)
            flow_dict = {
                'Destination Port': dst_port,
                'Flow Duration': duration,
                'Total Fwd Packets': fwd_pkts,
                'Total Backward Packets': bwd_pkts,
                'Total Length of Fwd Packets': fwd_pkts * 240,
                'Total Length of Bwd Packets': bwd_pkts * 550,
                'Fwd Packet Length Max': 600,
                'Fwd Packet Length Min': 32,
                'Fwd Packet Length Mean': 240,
                'Fwd Packet Length Std': 80,
                'Bwd Packet Length Max': 1200,
                'Bwd Packet Length Min': 40,
                'Bwd Packet Length Mean': 550,
                'Bwd Packet Length Std': 150,
                'Flow Bytes/s': (fwd_pkts * 240 + bwd_pkts * 550) / (duration / 1e6),
                'Flow Packets/s': (fwd_pkts + bwd_pkts) / (duration / 1e6),
                'Flow IAT Mean': duration / (fwd_pkts + bwd_pkts + 1),
                'Flow IAT Std': 500,
                'Flow IAT Max': 1500,
                'Flow IAT Min': 20,
                'Fwd IAT Total': duration * 0.9,
                'Fwd IAT Mean': duration / fwd_pkts,
                'Bwd IAT Total': duration * 0.8,
                'Bwd IAT Mean': duration / bwd_pkts,
                'Fwd Header Length': fwd_pkts * 32,
                'Bwd Header Length': bwd_pkts * 32,
                'Fwd Packets/s': fwd_pkts / (duration / 1e6),
                'Bwd Packets/s': bwd_pkts / (duration / 1e6),
                'Min Packet Length': 32,
                'Max Packet Length': 1200,
                'Packet Length Mean': 400,
                'Packet Length Std': 120,
                'FIN Flag Count': 0,
                'SYN Flag Count': 1,
                'RST Flag Count': 0,
                'PSH Flag Count': 1,
                'ACK Flag Count': 1,
                'URG Flag Count': 0,
                'Down/Up Ratio': 1.2,
                'Average Packet Size': 400,
                'Init_Win_bytes_forward': 29200,
                'Init_Win_bytes_backward': 29200,
                'min_seg_size_forward': 32
            }
        else:
            # Inject an attack scenario
            scenario = random.choice(["DoS", "PortScan", "Brute Force", "DDoS", "Botnet", "Web Attack"])
            if scenario == "PortScan":
                dst_port = random.randint(1, 1024)
                duration = float(random.randint(50, 600))
                flow_dict = {
                    'Destination Port': dst_port,
                    'Flow Duration': duration,
                    'Total Fwd Packets': 2,
                    'Total Backward Packets': 0,
                    'Total Length of Fwd Packets': 80,
                    'Total Length of Bwd Packets': 0,
                    'Fwd Packet Length Max': 40,
                    'Fwd Packet Length Min': 40,
                    'Fwd Packet Length Mean': 40,
                    'Fwd Packet Length Std': 0,
                    'Bwd Packet Length Max': 0,
                    'Bwd Packet Length Min': 0,
                    'Bwd Packet Length Mean': 0,
                    'Bwd Packet Length Std': 0,
                    'Flow Bytes/s': 80 / (duration / 1e6),
                    'Flow Packets/s': 2 / (duration / 1e6),
                    'Flow IAT Mean': duration / 2,
                    'Flow IAT Std': 0,
                    'Flow IAT Max': duration,
                    'Flow IAT Min': duration,
                    'Fwd IAT Total': duration,
                    'Fwd IAT Mean': duration,
                    'Bwd IAT Total': 0,
                    'Bwd IAT Mean': 0,
                    'Fwd Header Length': 40,
                    'Bwd Header Length': 0,
                    'Fwd Packets/s': 2 / (duration / 1e6),
                    'Bwd Packets/s': 0,
                    'Min Packet Length': 40,
                    'Max Packet Length': 40,
                    'Packet Length Mean': 40,
                    'Packet Length Std': 0,
                    'FIN Flag Count': 0,
                    'SYN Flag Count': 1,
                    'RST Flag Count': 0,
                    'PSH Flag Count': 0,
                    'ACK Flag Count': 0,
                    'URG Flag Count': 0,
                    'Down/Up Ratio': 0.0,
                    'Average Packet Size': 40,
                    'Init_Win_bytes_forward': 1024,
                    'Init_Win_bytes_backward': 0,
                    'min_seg_size_forward': 20
                }
            elif scenario == "DoS":
                dst_port = 80
                duration = 5000000.0
                fwd_pkts = 18
                bwd_pkts = 1
                flow_dict = {
                    'Destination Port': dst_port,
                    'Flow Duration': duration,
                    'Total Fwd Packets': fwd_pkts,
                    'Total Backward Packets': bwd_pkts,
                    'Total Length of Fwd Packets': fwd_pkts * 180,
                    'Total Length of Bwd Packets': 30,
                    'Fwd Packet Length Max': 220,
                    'Fwd Packet Length Min': 30,
                    'Fwd Packet Length Mean': 180,
                    'Fwd Packet Length Std': 30,
                    'Bwd Packet Length Max': 30,
                    'Bwd Packet Length Min': 0,
                    'Bwd Packet Length Mean': 30,
                    'Bwd Packet Length Std': 0,
                    'Flow Bytes/s': (fwd_pkts * 180) / 5.0,
                    'Flow Packets/s': (fwd_pkts + 1) / 5.0,
                    'Flow IAT Mean': duration / (fwd_pkts + 1),
                    'Flow IAT Std': 15000,
                    'Flow IAT Max': 45000,
                    'Flow IAT Min': 500,
                    'Fwd IAT Total': duration * 0.95,
                    'Fwd IAT Mean': duration / fwd_pkts,
                    'Bwd IAT Total': 1000,
                    'Bwd IAT Mean': 1000,
                    'Fwd Header Length': fwd_pkts * 32,
                    'Bwd Header Length': 32,
                    'Fwd Packets/s': fwd_pkts / 5.0,
                    'Bwd Packets/s': 0.2,
                    'Min Packet Length': 0,
                    'Max Packet Length': 220,
                    'Packet Length Mean': 160,
                    'Packet Length Std': 50,
                    'FIN Flag Count': 0,
                    'SYN Flag Count': 1,
                    'RST Flag Count': 1,
                    'PSH Flag Count': 1,
                    'ACK Flag Count': 0,
                    'URG Flag Count': 0,
                    'Down/Up Ratio': 0.05,
                    'Average Packet Size': 160,
                    'Init_Win_bytes_forward': 512,
                    'Init_Win_bytes_backward': 0,
                    'min_seg_size_forward': 32
                }
            else: # Default attack simulation
                dst_port = 443
                duration = 1500000.0
                fwd_pkts = 80
                bwd_pkts = 2
                flow_dict = {
                    'Destination Port': dst_port,
                    'Flow Duration': duration,
                    'Total Fwd Packets': fwd_pkts,
                    'Total Backward Packets': bwd_pkts,
                    'Total Length of Fwd Packets': fwd_pkts * 450,
                    'Total Length of Bwd Packets': 30,
                    'Fwd Packet Length Max': 550,
                    'Fwd Packet Length Min': 64,
                    'Fwd Packet Length Mean': 450,
                    'Fwd Packet Length Std': 60,
                    'Bwd Packet Length Max': 30,
                    'Bwd Packet Length Min': 0,
                    'Bwd Packet Length Mean': 15,
                    'Bwd Packet Length Std': 5,
                    'Flow Bytes/s': 450000.0,
                    'Flow Packets/s': 1200.0,
                    'Flow IAT Mean': 20.0,
                    'Flow IAT Std': 5.0,
                    'Flow IAT Max': 50.0,
                    'Flow IAT Min': 2.0,
                    'Fwd IAT Total': duration * 0.95,
                    'Fwd IAT Mean': 20.0,
                    'Bwd IAT Total': 500,
                    'Bwd IAT Mean': 250,
                    'Fwd Header Length': fwd_pkts * 20,
                    'Bwd Header Length': bwd_pkts * 20,
                    'Fwd Packets/s': 1180.0,
                    'Bwd Packets/s': 20.0,
                    'Min Packet Length': 40,
                    'Max Packet Length': 550,
                    'Packet Length Mean': 440,
                    'Packet Length Std': 70,
                    'FIN Flag Count': 0,
                    'SYN Flag Count': 1,
                    'RST Flag Count': 1,
                    'PSH Flag Count': 0,
                    'ACK Flag Count': 0,
                    'URG Flag Count': 0,
                    'Down/Up Ratio': 0.0,
                    'Average Packet Size': 440,
                    'Init_Win_bytes_forward': 1024,
                    'Init_Win_bytes_backward': 0,
                    'min_seg_size_forward': 20
                }

        # Run REAL Model Prediction
        prediction = engine.predict_flow(flow_dict)

        now = datetime.utcnow()
        record = TrafficRecord(
            timestamp=now,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            flow_duration=float(flow_dict.get('Flow Duration', 0.0)),
            total_fwd_packets=int(flow_dict.get('Total Fwd Packets', 1)),
            total_bwd_packets=int(flow_dict.get('Total Backward Packets', 0)),
            flow_bytes_s=float(flow_dict.get('Flow Bytes/s', 0.0)),
            flow_packets_s=float(flow_dict.get('Flow Packets/s', 0.0)),
            predicted_attack=prediction["predicted_attack"],
            confidence=prediction["confidence"],
            is_threat=prediction["is_threat"],
            severity=prediction["severity"],
            probabilities=prediction["probabilities"]
        )
        db.add(record)
        db.flush()

        alert_data = None
        if prediction["is_threat"]:
            import uuid
            alert_id = f"ALT-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
            alert = SecurityAlert(
                alert_id=alert_id,
                traffic_record_id=record.id,
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=protocol,
                attack_category=prediction["predicted_attack"],
                severity=prediction["severity"],
                confidence_score=prediction["confidence"],
                status="New",
                notes=f"Live stream AI detection: {prediction['predicted_attack']} classified with {prediction['confidence_percentage']}% confidence."
            )
            db.add(alert)
            db.flush()
            alert_data = {
                "id": alert.id,
                "alert_id": alert.alert_id,
                "attack_category": alert.attack_category,
                "severity": alert.severity,
                "confidence_score": alert.confidence_score
            }

        db.commit()

        return {
            "record_id": record.id,
            "timestamp": now.isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "predicted_attack": prediction["predicted_attack"],
            "confidence": prediction["confidence"],
            "is_threat": prediction["is_threat"],
            "severity": prediction["severity"],
            "probabilities": prediction["probabilities"],
            "alert": alert_data
        }
