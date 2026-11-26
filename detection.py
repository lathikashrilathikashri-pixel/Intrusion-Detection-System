"""
AI-Based Intrusion Detection System (AI-IDS)
AI Threat Detection & Single-Flow Classifier Router
"""

import sys
from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any

from app.config import settings
if settings.BASE_DIR not in sys.path:
    sys.path.append(settings.BASE_DIR)

from ml.predictor import IDSInferenceEngine
from app.schemas.traffic_schemas import ManualFlowPredictRequest, FlowPredictResponse
from app.services.auth_service import get_current_user
from app.models.user import User

router = APIRouter(prefix="/detection", tags=["AI Threat Detection"])

@router.post("/predict", response_model=FlowPredictResponse)
def predict_flow(
    req: ManualFlowPredictRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Classify incoming network-flow parameters using the trained Random Forest model.
    Returns predicted attack category, confidence score, and full multi-class probability distribution.
    """
    engine = IDSInferenceEngine.get_instance()
    if not engine.is_loaded:
        if not engine.load_artifacts():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Machine learning model is not available or not trained yet."
            )

    # Build flow dictionary for ML features
    flow_dict = {}
    if req.raw_features:
        flow_dict.update(req.raw_features)

    # Populate explicit fields
    flow_dict['Destination Port'] = req.dst_port
    flow_dict['Flow Duration'] = req.flow_duration
    flow_dict['Total Fwd Packets'] = req.total_fwd_packets
    flow_dict['Total Backward Packets'] = req.total_bwd_packets
    flow_dict['Total Length of Fwd Packets'] = req.total_len_fwd_packets or (req.total_fwd_packets * 240)
    flow_dict['Total Length of Bwd Packets'] = req.total_len_bwd_packets or (req.total_bwd_packets * 500)
    flow_dict['Flow Bytes/s'] = req.flow_bytes_s or 50000.0
    flow_dict['Flow Packets/s'] = req.flow_packets_s or 100.0
    flow_dict['FIN Flag Count'] = req.fin_flag_count
    flow_dict['SYN Flag Count'] = req.syn_flag_count
    flow_dict['RST Flag Count'] = req.rst_flag_count
    flow_dict['PSH Flag Count'] = req.psh_flag_count
    flow_dict['ACK Flag Count'] = req.ack_flag_count
    flow_dict['URG Flag Count'] = req.urg_flag_count
    flow_dict['Down/Up Ratio'] = req.down_up_ratio
    flow_dict['Average Packet Size'] = req.avg_packet_size

    # Fill defaults for remaining features
    flow_dict.setdefault('Fwd Packet Length Mean', 240.0)
    flow_dict.setdefault('Bwd Packet Length Mean', 500.0)
    flow_dict.setdefault('Flow IAT Mean', req.flow_duration / (req.total_fwd_packets + req.total_bwd_packets + 1))
    flow_dict.setdefault('Flow IAT Std', 1000.0)
    flow_dict.setdefault('Fwd Header Length', req.total_fwd_packets * 32)
    flow_dict.setdefault('Bwd Header Length', req.total_bwd_packets * 32)
    flow_dict.setdefault('min_seg_size_forward', 32)

    # Execute genuine model prediction
    prediction = engine.predict_flow(flow_dict)

    flow_summary = {
        "src_ip": req.src_ip,
        "dst_ip": req.dst_ip,
        "src_port": req.src_port,
        "dst_port": req.dst_port,
        "protocol": req.protocol,
        "flow_duration": req.flow_duration,
        "total_packets": req.total_fwd_packets + req.total_bwd_packets
    }

    return {
        "predicted_attack": prediction["predicted_attack"],
        "confidence": prediction["confidence"],
        "confidence_percentage": prediction["confidence_percentage"],
        "is_threat": prediction["is_threat"],
        "severity": prediction["severity"],
        "probabilities": prediction["probabilities"],
        "flow_summary": flow_summary
    }

@router.get("/presets")
def get_attack_test_presets(current_user: User = Depends(get_current_user)):
    """Pre-configured attack profiles for interactive SOC testing and demonstrations."""
    return [
        {
            "id": "benign-web",
            "name": "Legitimate HTTPS Browsing",
            "category": "BENIGN",
            "description": "Standard encrypted web session to port 443 with normal packet balance and timing.",
            "data": {
                "src_ip": "192.168.1.105",
                "dst_ip": "142.250.190.46",
                "src_port": 52140,
                "dst_port": 443,
                "protocol": "TCP",
                "flow_duration": 180000.0,
                "total_fwd_packets": 12,
                "total_bwd_packets": 14,
                "total_len_fwd_packets": 2880.0,
                "total_len_bwd_packets": 8500.0,
                "flow_bytes_s": 63200.0,
                "flow_packets_s": 144.0,
                "syn_flag_count": 1,
                "ack_flag_count": 1,
                "psh_flag_count": 1,
                "fin_flag_count": 0,
                "rst_flag_count": 0,
                "urg_flag_count": 0,
                "down_up_ratio": 1.16,
                "avg_packet_size": 437.0
            }
        },
        {
            "id": "dos-hulk",
            "name": "DoS Attack (Hulk / Slow HTTP)",
            "category": "DoS",
            "description": "Slow request flood to port 80 designed to exhaust web server connection pools.",
            "data": {
                "src_ip": "185.220.101.5",
                "dst_ip": "192.168.1.10",
                "src_port": 41234,
                "dst_port": 80,
                "protocol": "TCP",
                "flow_duration": 6500000.0,
                "total_fwd_packets": 22,
                "total_bwd_packets": 1,
                "total_len_fwd_packets": 3960.0,
                "total_len_bwd_packets": 40.0,
                "flow_bytes_s": 615.0,
                "flow_packets_s": 3.5,
                "syn_flag_count": 1,
                "ack_flag_count": 0,
                "psh_flag_count": 1,
                "fin_flag_count": 0,
                "rst_flag_count": 1,
                "urg_flag_count": 0,
                "down_up_ratio": 0.04,
                "avg_packet_size": 173.0
            }
        },
        {
            "id": "ddos-volumetric",
            "name": "DDoS Volumetric Flood",
            "category": "DDoS",
            "description": "High-intensity multi-source UDP/TCP burst targeting port 80 with high packets/second.",
            "data": {
                "src_ip": "103.203.57.18",
                "dst_ip": "192.168.1.1",
                "src_port": 61001,
                "dst_port": 80,
                "protocol": "TCP",
                "flow_duration": 1200000.0,
                "total_fwd_packets": 110,
                "total_bwd_packets": 2,
                "total_len_fwd_packets": 49500.0,
                "total_len_bwd_packets": 60.0,
                "flow_bytes_s": 413000.0,
                "flow_packets_s": 933.0,
                "syn_flag_count": 1,
                "ack_flag_count": 0,
                "psh_flag_count": 0,
                "fin_flag_count": 0,
                "rst_flag_count": 1,
                "urg_flag_count": 0,
                "down_up_ratio": 0.01,
                "avg_packet_size": 442.0
            }
        },
        {
            "id": "portscan-nmap",
            "name": "Stealth PortScan Probe",
            "category": "PortScan",
            "description": "Rapid SYN sweep reconnaissance packet targeting a non-standard port with 0 return traffic.",
            "data": {
                "src_ip": "45.33.32.156",
                "dst_ip": "192.168.1.10",
                "src_port": 58912,
                "dst_port": 3389,
                "protocol": "TCP",
                "flow_duration": 450.0,
                "total_fwd_packets": 1,
                "total_bwd_packets": 0,
                "total_len_fwd_packets": 44.0,
                "total_len_bwd_packets": 0.0,
                "flow_bytes_s": 97700.0,
                "flow_packets_s": 2222.0,
                "syn_flag_count": 1,
                "ack_flag_count": 0,
                "psh_flag_count": 0,
                "fin_flag_count": 0,
                "rst_flag_count": 0,
                "urg_flag_count": 0,
                "down_up_ratio": 0.0,
                "avg_packet_size": 44.0
            }
        },
        {
            "id": "bruteforce-ssh",
            "name": "SSH Credential Brute Force",
            "category": "Brute Force",
            "description": "Automated authentication trial loop hitting SSH port 22 with characteristic handshake lengths.",
            "data": {
                "src_ip": "198.51.100.4",
                "dst_ip": "192.168.1.1",
                "src_port": 49821,
                "dst_port": 22,
                "protocol": "TCP",
                "flow_duration": 135000.0,
                "total_fwd_packets": 14,
                "total_bwd_packets": 12,
                "total_len_fwd_packets": 980.0,
                "total_len_bwd_packets": 1150.0,
                "flow_bytes_s": 15700.0,
                "flow_packets_s": 192.0,
                "syn_flag_count": 1,
                "ack_flag_count": 1,
                "psh_flag_count": 1,
                "fin_flag_count": 0,
                "rst_flag_count": 1,
                "urg_flag_count": 0,
                "down_up_ratio": 0.85,
                "avg_packet_size": 81.0
            }
        },
        {
            "id": "botnet-c2",
            "name": "Botnet C2 Beaconing",
            "category": "Botnet",
            "description": "Periodic heartbeat signaling to Command & Control server on IRC/custom port 6667.",
            "data": {
                "src_ip": "192.168.1.140",
                "dst_ip": "194.26.29.112",
                "src_port": 50122,
                "dst_port": 6667,
                "protocol": "TCP",
                "flow_duration": 850000.0,
                "total_fwd_packets": 8,
                "total_bwd_packets": 7,
                "total_len_fwd_packets": 760.0,
                "total_len_bwd_packets": 540.0,
                "flow_bytes_s": 1520.0,
                "flow_packets_s": 17.6,
                "syn_flag_count": 1,
                "ack_flag_count": 1,
                "psh_flag_count": 1,
                "fin_flag_count": 0,
                "rst_flag_count": 0,
                "urg_flag_count": 0,
                "down_up_ratio": 0.87,
                "avg_packet_size": 86.0
            }
        },
        {
            "id": "web-sqli",
            "name": "Web Attack (SQL Injection / XSS)",
            "category": "Web Attack",
            "description": "Exploit payload directed at port 8080 with oversized forward request packet payloads.",
            "data": {
                "src_ip": "91.189.91.43",
                "dst_ip": "192.168.1.10",
                "src_port": 44102,
                "dst_port": 8080,
                "protocol": "TCP",
                "flow_duration": 220000.0,
                "total_fwd_packets": 16,
                "total_bwd_packets": 14,
                "total_len_fwd_packets": 11520.0,
                "total_len_bwd_packets": 14200.0,
                "flow_bytes_s": 116900.0,
                "flow_packets_s": 136.0,
                "syn_flag_count": 1,
                "ack_flag_count": 1,
                "psh_flag_count": 1,
                "fin_flag_count": 0,
                "rst_flag_count": 0,
                "urg_flag_count": 0,
                "down_up_ratio": 0.87,
                "avg_packet_size": 857.0
            }
        }
    ]
