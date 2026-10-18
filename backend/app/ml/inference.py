"""
backend/app/ml/inference.py
-----------------------------
ML inference service — loads model once, never retrains per scan.
Falls back to keyword rules if model not found (honest error message).
"""
import os
import re
import json
import joblib
from functools import lru_cache
from typing import Optional
from backend.app.core.config import get_settings

settings = get_settings()

_MODEL = None
_VECTORIZER = None
_LOAD_ERROR: Optional[str] = None
_METRICS: Optional[dict] = None


def _clean_text(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+", " URL ", text)
    text = text.lower()
    return re.sub(r"\s+", " ", text).strip()


def load_model():
    """Load model + vectorizer once and cache. Thread-safe via GIL on initial load."""
    global _MODEL, _VECTORIZER, _LOAD_ERROR, _METRICS
    if _MODEL is not None or _LOAD_ERROR is not None:
        return

    import pathlib
    project_root = pathlib.Path(__file__).resolve().parents[3]

    def _resolve(p):
        if os.path.isabs(p) and os.path.exists(p):
            return p
        candidate = project_root / p
        if candidate.exists():
            return str(candidate)
        return p

    model_path = _resolve(settings.MODEL_PATH)
    vec_path = _resolve(settings.VECTORIZER_PATH)
    metrics_path = _resolve(settings.METRICS_PATH)

    try:
        _MODEL = joblib.load(model_path)
        _VECTORIZER = joblib.load(vec_path)
    except FileNotFoundError as e:
        _LOAD_ERROR = (
            f"Model not found at {model_path}. "
            "Operating in keyword-rule-only mode."
        )
    except Exception as e:
        _LOAD_ERROR = f"Model failed to load: {e}. Operating in keyword-rule-only fallback."

    if os.path.exists(metrics_path):
        try:
            with open(metrics_path) as f:
                _METRICS = json.load(f)
        except Exception:
            _METRICS = None


def get_model_status() -> dict:
    load_model()
    if _MODEL is not None:
        return {
            "status": "loaded",
            "version": settings.MODEL_VERSION,
            "algorithm": type(_MODEL).__name__,
            "artifact_path": settings.MODEL_PATH,
            "message": None,
        }
    return {
        "status": "not_loaded" if _LOAD_ERROR else "error",
        "version": settings.MODEL_VERSION,
        "algorithm": None,
        "artifact_path": settings.MODEL_PATH,
        "message": _LOAD_ERROR,
    }


def get_model_metrics() -> Optional[dict]:
    load_model()
    return _METRICS


def _keyword_flags(subject: str, body_text: str) -> list:
    text = f"{subject} {body_text}".lower()
    return [p for p in settings.SUSPICIOUS_PHRASES if p in text]


def analyze_content(subject: str, body_text: str) -> dict:
    """
    Returns:
        phishing_probability: float 0-100
        classification: str (Likely Phishing | Suspicious | Likely Legitimate | Insufficient Evidence)
        top_indicators: list[str]
        keyword_flags: list[str]
        error: str | None
    """
    load_model()
    keyword_flags = _keyword_flags(subject or "", body_text or "")

    if _MODEL is None:
        prob = min(100.0, len(keyword_flags) * 20.0)
        classification = _classify(prob)
        return {
            "phishing_probability": round(prob, 1),
            "classification": classification,
            "top_indicators": keyword_flags[:5],
            "keyword_flags": keyword_flags,
            "error": _LOAD_ERROR,
        }

    combined = _clean_text(f"{subject} {body_text}")
    try:
        vec = _VECTORIZER.transform([combined])
        if hasattr(_MODEL, "predict_proba"):
            prob = float(_MODEL.predict_proba(vec)[0][1]) * 100
        else:
            prob = float(_MODEL.predict(vec)[0]) * 100

        top_indicators = []
        if hasattr(_MODEL, "coef_"):
            feature_names = _VECTORIZER.get_feature_names_out()
            row = vec.tocoo()
            contributions = [
                (feature_names[col], _MODEL.coef_[0][col] * val)
                for col, val in zip(row.col, row.data)
            ]
            contributions.sort(key=lambda x: x[1], reverse=True)
            top_indicators = [w for w, c in contributions[:5] if c > 0]

        return {
            "phishing_probability": round(prob, 1),
            "classification": _classify(prob),
            "top_indicators": top_indicators or keyword_flags[:5],
            "keyword_flags": keyword_flags,
            "error": None,
        }
    except Exception as e:
        prob = min(100.0, len(keyword_flags) * 20.0)
        return {
            "phishing_probability": round(prob, 1),
            "classification": _classify(prob),
            "top_indicators": keyword_flags[:5],
            "keyword_flags": keyword_flags,
            "error": f"Model prediction failed, used keyword fallback: {e}",
        }


def _classify(prob: float) -> str:
    if prob >= 70:
        return "Likely Phishing"
    elif prob >= 45:
        return "Suspicious"
    elif prob >= 10:
        return "Likely Legitimate"
    else:
        return "Likely Legitimate"
