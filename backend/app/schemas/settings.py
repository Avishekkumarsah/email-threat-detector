"""backend/app/schemas/settings.py"""
from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel


class SettingResponse(BaseModel):
    id: int
    setting_key: str
    setting_value: Optional[str]
    description: Optional[str]
    updated_at: datetime

    model_config = {"from_attributes": True}


class SettingPatchRequest(BaseModel):
    setting_key: str
    setting_value: Optional[str]


class SettingsBulkPatchRequest(BaseModel):
    settings: List[SettingPatchRequest]
