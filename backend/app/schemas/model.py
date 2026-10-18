"""backend/app/schemas/model.py"""
from typing import Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime


class ModelStatusResponse(BaseModel):
    version: str
    status: str
    algorithm: Optional[str] = None
    training_date: Optional[datetime] = None
    artifact_path: Optional[str] = None
    message: Optional[str] = None


class ModelMetricsResponse(BaseModel):
    version: str
    metrics: Optional[Dict[str, Any]] = None
    evaluation_summary: Optional[Dict[str, Any]] = None
