"""backend/app/api/settings_api.py"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from backend.app.database.session import get_db
from backend.app.models.settings import ApplicationSetting
from backend.app.schemas.settings import SettingResponse, SettingsBulkPatchRequest
from backend.app.security.dependencies import get_current_user, require_admin
from backend.app.services.audit_service import log_event

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("", response_model=List[SettingResponse])
def get_settings_list(current_user=Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ApplicationSetting).order_by(ApplicationSetting.setting_key).all()


@router.patch("", response_model=List[SettingResponse])
def patch_settings(
    body: SettingsBulkPatchRequest,
    current_user=Depends(require_admin),
    db: Session = Depends(get_db),
):
    updated = []
    for item in body.settings:
        setting = db.query(ApplicationSetting).filter(
            ApplicationSetting.setting_key == item.setting_key
        ).first()
        if setting:
            setting.setting_value = item.setting_value
            setting.updated_by = current_user.id
        else:
            setting = ApplicationSetting(
                setting_key=item.setting_key,
                setting_value=item.setting_value,
                updated_by=current_user.id,
            )
            db.add(setting)
        updated.append(setting)
    db.commit()
    log_event(db, "settings.update", actor_user_id=current_user.id,
              metadata={"keys": [i.setting_key for i in body.settings]})
    return updated
