"""
content_analysis.py
--------------------
Loads the trained model ONCE and exposes analyze_content() for the rest
of the app. Falls back to a simple keyword rule-check if the model files
are missing, instead of crashing.
"""

import os
import re
import joblib
import config

_MODEL = None
_VECTORIZER = None
_LOAD_ERROR = None


def _clean_text(text):
    if not isinstance(text, str):
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"https?://\S+", " URL ", text)
    text = text.lower()
    return re.sub(r"\s+", " ", text).strip()


def _load_model():
    """Load model + vectorizer once and cache them in module-level globals."""
    global _MODEL, _VECTORIZER, _LOAD_ERROR
    if _MODEL is not None or _LOAD_ERROR is not None:
        return
    model_path = os.path.join(config.MODEL_DIR, "phishing_model.pkl")
    vec_path = os.path.join(config.MODEL_DIR, "vectorizer.pkl")
    try:
        _MODEL = joblib.load(model_path)
        _VECTORIZER = joblib.load(vec_path)
    except Exception as e:
        _LOAD_ERROR = (
            f"Model not found or failed to load ({e}). "
            f"Run 'python model/train_model.py' first. Falling back to keyword rules only."
        )


def _keyword_flags(subject, body_text):
    text = f"{subject} {body_text}".lower()
    return [p for p in config.SUSPICIOUS_PHRASES if p in text]


def analyze_content(subject, body_text):
    """
    Returns:
    {
      "phishing_probability": float 0-100,
      "label": "Phishing" / "Legitimate",
      "top_indicators": [...],
      "keyword_flags": [...],
      "error": None or str
    }
    """
    _load_model()
    keyword_flags = _keyword_flags(subject, body_text)

    if _MODEL is None:
        # Rule-based backup: score purely from keyword hits
        prob = min(100.0, len(keyword_flags) * 20.0)
        return {
            "phishing_probability": round(prob, 1),
            "label": "Phishing" if prob >= 50 else "Legitimate",
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
            "label": "Phishing" if prob >= 50 else "Legitimate",
            "top_indicators": top_indicators or keyword_flags[:5],
            "keyword_flags": keyword_flags,
            "error": None,
        }
    except Exception as e:
        prob = min(100.0, len(keyword_flags) * 20.0)
        return {
            "phishing_probability": round(prob, 1),
            "label": "Phishing" if prob >= 50 else "Legitimate",
            "top_indicators": keyword_flags[:5],
            "keyword_flags": keyword_flags,
            "error": f"Model prediction failed, used keyword fallback: {e}",
        }
