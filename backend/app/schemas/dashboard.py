"""backend/app/schemas/dashboard.py"""
from datetime import date
from typing import List, Optional
from pydantic import BaseModel


class RiskDistribution(BaseModel):
    low_risk: int = 0
    medium_risk: int = 0
    high_risk: int = 0
    critical_risk: int = 0
    inconclusive: int = 0


class DashboardSummary(BaseModel):
    total_scans: int
    likely_phishing: int
    suspicious: int
    likely_legitimate: int
    insufficient_evidence: int
    high_risk_findings: int
    model_version: Optional[str]
    model_status: str
    recent_scans: list

    model_config = {"protected_namespaces": ()}


class TrendPoint(BaseModel):
    date: str
    total: int
    phishing: int
    legitimate: int
    suspicious: int


class DashboardTrends(BaseModel):
    period_days: int
    data: List[TrendPoint]


