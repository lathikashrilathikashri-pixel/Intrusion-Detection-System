"""
AI-Based Intrusion Detection System (AI-IDS)
Traffic & Flow Analysis Pydantic Schemas
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, Dict, List, Any
from datetime import datetime

class TrafficRecordResponse(BaseModel):
    id: int
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    flow_duration: float
    total_fwd_packets: int
    total_bwd_packets: int
    flow_bytes_s: float
    flow_packets_s: float
    predicted_attack: str
    confidence: float
    is_threat: bool
    severity: str
    probabilities: Optional[Dict[str, float]] = None

    model_config = ConfigDict(from_attributes=True)

class ManualFlowPredictRequest(BaseModel):
    src_ip: Optional[str] = "192.168.1.150"
    dst_ip: Optional[str] = "192.168.1.10"
    src_port: Optional[int] = 49152
    dst_port: int = Field(default=80, description="Destination Port")
    protocol: Optional[str] = "TCP"
    flow_duration: float = Field(default=120000.0, description="Flow Duration in microseconds")
    total_fwd_packets: int = Field(default=10, description="Total Forward Packets")
    total_bwd_packets: int = Field(default=8, description="Total Backward Packets")
    total_len_fwd_packets: Optional[float] = 1200.0
    total_len_bwd_packets: Optional[float] = 4500.0
    flow_bytes_s: Optional[float] = 47500.0
    flow_packets_s: Optional[float] = 150.0
    fin_flag_count: Optional[int] = 0
    syn_flag_count: Optional[int] = 1
    rst_flag_count: Optional[int] = 0
    psh_flag_count: Optional[int] = 1
    ack_flag_count: Optional[int] = 1
    urg_flag_count: Optional[int] = 0
    down_up_ratio: Optional[float] = 1.0
    avg_packet_size: Optional[float] = 316.0
    # Additional raw CICIDS feature dictionary if passed
    raw_features: Optional[Dict[str, Any]] = None

class FlowPredictResponse(BaseModel):
    predicted_attack: str
    confidence: float
    confidence_percentage: float
    is_threat: bool
    severity: str
    probabilities: Dict[str, float]
    flow_summary: Dict[str, Any]

class BatchAnalysisSummary(BaseModel):
    job_uuid: str
    filename: str
    total_records: int
    benign_count: int
    threat_count: int
    threat_percentage: float
    attack_breakdown: Dict[str, int]
    alerts_generated: int
    processed_at: datetime
