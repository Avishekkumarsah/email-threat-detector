"""backend/app/api/model_api.py"""
from fastapi import APIRouter, Depends
from backend.app.schemas.model import ModelStatusResponse, ModelMetricsResponse
from backend.app.security.dependencies import get_current_user
from backend.app.ml.inference import get_model_status, get_model_metrics
from backend.app.core.config import get_settings

settings = get_settings()
router = APIRouter(prefix="/api/model", tags=["Model"])


@router.get("/status", response_model=ModelStatusResponse)
def model_status(current_user=Depends(get_current_user)):
    info = get_model_status()
    return ModelStatusResponse(
        version=info.get("version", settings.MODEL_VERSION),
        status=info.get("status", "unknown"),
        algorithm=info.get("algorithm"),
        training_date=None,
        artifact_path=info.get("artifact_path"),
        message=info.get("message"),
    )


@router.get("/metrics", response_model=ModelMetricsResponse)
def model_metrics(current_user=Depends(get_current_user)):
    metrics = get_model_metrics()
    return ModelMetricsResponse(
        version=settings.MODEL_VERSION,
        metrics=metrics,
        evaluation_summary=metrics,
    )
