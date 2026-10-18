"""
backend/app/schemas/scan.py
"""
from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel


class AnalyzeSourceRequest(BaseModel):
    raw_email: str
    label: Optional[str] = None  # optional user label


class ScanFindingResponse(BaseModel):
    id: int
    finding_type: str
    severity: str
    explanation: str
    evidence: Optional[str]
    source: Optional[str]
    confidence: Optional[float]
    points: Optional[float]
    recommended_action: Optional[str]

    model_config = {"from_attributes": True}


class ExtractedURLResponse(BaseModel):
    id: int
    original_url: str
    hostname: Optional[str]
    protocol: Optional[str]
    anchor_text: Optional[str]
    source: Optional[str]
    uses_https: Optional[bool]
    is_ip_address: Optional[bool]
    is_punycode: Optional[bool]
    uses_shortener: Optional[bool]
    has_anchor_mismatch: Optional[bool]
    url_score: Optional[int]
    analysis_status: str
    reputation_result: Optional[Dict[str, Any]]
    flags: Optional[List[Dict[str, Any]]]
    checked_at: Optional[datetime]

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: int
    scan_status: str
    original_filename: Optional[str]
    subject: Optional[str]
    sender: Optional[str]
    classification: Optional[str]
    model_score: Optional[float]
    overall_risk: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True, "protected_namespaces": ()}


class ScanDetailResponse(BaseModel):
    id: int
    scan_status: str
    original_filename: Optional[str]
    file_hash: Optional[str]
    subject: Optional[str]
    sender: Optional[str]
    reply_to: Optional[str]
    received_at: Optional[datetime]
    classification: Optional[str]
    model_score: Optional[float]
    overall_risk: Optional[str]
    scoring_rule_version: Optional[str]
    error_message: Optional[str]
    created_at: datetime
    completed_at: Optional[datetime]
    findings: List[ScanFindingResponse] = []
    extracted_urls: List[ExtractedURLResponse] = []
    full_result: Optional[Dict[str, Any]] = None

    model_config = {"from_attributes": True, "protected_namespaces": ()}


class ScanListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[ScanSummary]
