"""
AI-Based Intrusion Detection System (AI-IDS)
Dashboard & Analytics Schemas
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime

class ThreatKPI(BaseModel):
    total_connections: int
    total_threats: int
    benign_count: int
    normal_percentage: float
    suspicious_percentage: float
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    open_alerts: int

class AttackDistributionItem(BaseModel):
    category: str
    count: int
    percentage: float
    severity: str

class TimelinePoint(BaseModel):
    time: str
    benign: int
    threats: int
    total: int

class RecentActivityItem(BaseModel):
    id: int
    type: str # ALERT, TRAFFIC, JOB, SYSTEM
    timestamp: datetime
    title: str
    description: str
    severity: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None

class DashboardStats(BaseModel):
    kpis: ThreatKPI
    attack_distribution: List[AttackDistributionItem]
    traffic_timeline: List[TimelinePoint]
    recent_activities: List[RecentActivityItem]
    soc_system_status: Dict[str, Any]
