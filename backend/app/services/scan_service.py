"""
backend/app/services/scan_service.py
--------------------------------------
Core scan pipeline: parse → analyze → score → persist to PostgreSQL.
All analysis modules ported from the original modules/ directory.
"""
import os
import uuid
import json
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session

from backend.app.core.config import get_settings
from backend.app.models.scan import EmailScan
from backend.app.models.finding import ScanFinding
from backend.app.models.url import ExtractedURL
from backend.app.models.model_version import ModelVersion

settings = get_settings()

# ── Import ported analysis modules ────────────────────────────────────────────
import sys, pathlib
# Add project root to sys.path so we can import original modules
_root = pathlib.Path(__file__).resolve().parents[3]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from modules import parser, content_analysis, header_analysis, url_analysis, attachment_analysis, geolocation, scoring
# Use new ML inference instead of content_analysis directly
from backend.app.ml.inference import analyze_content as ml_analyze_content


def _risk_level(score: int) -> str:
    """Map numeric score to 5-level risk category."""
    if score <= settings.SCORE_LOW_RISK_MAX:
        return "Low Risk"
    elif score <= settings.SCORE_MEDIUM_RISK_MAX:
        return "Medium Risk"
    elif score <= settings.SCORE_HIGH_RISK_MAX:
        return "High Risk"
    elif score <= settings.SCORE_CRITICAL_RISK_MAX:
        return "Critical Risk"
    return "Inconclusive"


def _get_or_create_model_version(db: Session) -> Optional[int]:
    """Get active model version ID or create one."""
    mv = db.query(ModelVersion).filter(ModelVersion.deployment_status == "active").first()
    if mv:
        return mv.id
    # Create a placeholder entry
    from backend.app.ml.inference import get_model_status, get_model_metrics
    status = get_model_status()
    metrics = get_model_metrics()
    mv = ModelVersion(
        version=settings.MODEL_VERSION,
        artifact_reference=settings.MODEL_PATH,
        vectorizer_reference=settings.VECTORIZER_PATH,
        algorithm=status.get("algorithm"),
        training_date=datetime.now(timezone.utc),
        evaluation_summary=metrics,
        deployment_status="active",
    )
    db.add(mv)
    db.flush()
    return mv.id


def _run_pipeline(file_path: Optional[str] = None, raw_text: Optional[str] = None) -> dict:
    """Run the full analysis pipeline. Returns combined result dict."""
    if file_path:
        parsed = parser.parse_email(file_path=file_path)
    else:
        parsed = parser.parse_email(raw_text=raw_text)

    subject = parsed["headers"].get("subject", "")
    body_plain = parsed["body"].get("plain") or parsed["body"].get("html", "")

    # Content analysis (ML + keyword)
    try:
        content_result = ml_analyze_content(subject, body_plain)
        content_result["phishing_probability"] = content_result.get("phishing_probability", 0)
        content_result["score"] = content_result["phishing_probability"]
    except Exception as e:
        content_result = {"error": str(e), "phishing_probability": 0, "score": 0, "flags": []}

    try:
        header_result = header_analysis.analyze_headers(parsed["headers"])
    except Exception as e:
        header_result = {"error": str(e), "score": 0, "flags": []}

    try:
        url_result = url_analysis.analyze_urls(parsed["urls"])
    except Exception as e:
        url_result = {"error": str(e), "score": 0, "flags": [], "url_results": []}

    try:
        attachment_result = attachment_analysis.analyze_attachments(parsed["attachments"])
    except Exception as e:
        attachment_result = {"error": str(e), "score": 0, "flags": []}

    try:
        geo_result = geolocation.build_route(parsed["received_chain"], parsed["headers"])
    except Exception as e:
        geo_result = {"error": str(e), "hops": [], "flags": [], "score": 0}

    score_result = scoring.compute_threat_score(
        content_result, header_result, url_result, attachment_result, geo_result
    )

    return {
        "parsed": parsed,
        "content": content_result,
        "header": header_result,
        "url": url_result,
        "attachment": attachment_result,
        "geo": geo_result,
        "score": score_result,
    }


def _extract_findings(result: dict, scan_id: int) -> list[ScanFinding]:
    """Convert raw flags from all modules into normalized ScanFinding rows."""
    findings = []
    source_map = {
        "content": "content",
        "header": "header",
        "url": "url",
        "attachment": "attachment",
        "geo": "geolocation",
    }

    recommended_actions = {
        "spf_fail": "Do not click any links. Verify the sender through an independent channel.",
        "dkim_fail": "Message integrity cannot be verified. Treat as suspicious.",
        "dmarc_fail": "Email failed DMARC policy. High risk of spoofing.",
        "reply_to_mismatch": "Do not reply — the reply will go to a different address than the sender.",
        "freemail_brand_impersonation": "Sender is impersonating a known brand. Do not provide credentials.",
        "lookalike_domain": "Domain is designed to look like a trusted site. Do not click links.",
        "ip_based_url": "URLs going to raw IP addresses are a strong phishing indicator.",
        "anchor_mismatch": "Visible link text does not match real destination. Do not click.",
        "punycode": "Domain uses international characters to look like a trusted domain.",
        "high_risk_extension": "Attachment has a dangerous file extension. Do not open.",
        "macro_enabled": "Document contains macros that can execute malicious code. Do not open.",
    }

    for source_key, source_label in source_map.items():
        module_result = result.get(source_key, {})
        if not module_result or module_result.get("error"):
            continue
        for flag in module_result.get("flags", []):
            findings.append(ScanFinding(
                scan_id=scan_id,
                finding_type=flag.get("check", "unknown"),
                severity=flag.get("severity", "low"),
                explanation=flag.get("detail", ""),
                evidence=flag.get("detail", ""),
                source=source_label,
                confidence=None,
                points=float(flag.get("points", 0)),
                recommended_action=recommended_actions.get(flag.get("check", ""), None),
            ))

    return findings


def _extract_urls(url_result: dict, scan_id: int) -> list[ExtractedURL]:
    """Convert url_result per-URL breakdown into normalized ExtractedURL rows."""
    rows = []
    from urllib.parse import urlparse
    for u in url_result.get("url_results", []):
        url_str = u.get("url", "")
        try:
            parsed = urlparse(url_str)
            hostname = parsed.hostname or ""
            protocol = parsed.scheme or ""
        except Exception:
            hostname = ""
            protocol = ""

        flags = u.get("flags", [])
        flag_types = {f.get("check") for f in flags}

        rows.append(ExtractedURL(
            scan_id=scan_id,
            original_url=url_str,
            hostname=hostname,
            protocol=protocol,
            anchor_text=None,  # set from parsed data if available
            source=None,
            uses_https=protocol == "https",
            is_ip_address="ip_based_url" in flag_types,
            is_punycode="punycode" in flag_types,
            uses_shortener="shortener" in flag_types,
            has_anchor_mismatch="anchor_mismatch" in flag_types,
            url_score=int(u.get("score", 0)),
            analysis_status="checked",
            flags=flags,
            checked_at=datetime.now(timezone.utc),
        ))
    return rows


def run_scan_from_file(
    db: Session,
    file_path: str,
    original_filename: str,
    user_id: int,
) -> EmailScan:
    """Run full scan pipeline from an uploaded .eml file and persist to DB."""
    mv_id = _get_or_create_model_version(db)
    result = _run_pipeline(file_path=file_path)
    return _persist_scan(db, result, original_filename, user_id, mv_id)


def run_scan_from_source(
    db: Session,
    raw_text: str,
    user_id: int,
) -> EmailScan:
    """Run full scan pipeline from pasted email source and persist to DB."""
    mv_id = _get_or_create_model_version(db)
    result = _run_pipeline(raw_text=raw_text)
    return _persist_scan(db, result, "pasted_source.eml", user_id, mv_id)


def _persist_scan(
    db: Session,
    result: dict,
    original_filename: str,
    user_id: int,
    mv_id: Optional[int],
) -> EmailScan:
    """Persist scan + normalized findings + URLs to PostgreSQL."""
    headers = result["parsed"]["headers"]
    score_result = result["score"]
    content_result = result.get("content", {})

    final_score = score_result.get("final_score", 0)
    overall_risk = _risk_level(final_score)

    # Map old 3-level verdict to new 5-level classification
    classification_map = {
        "Dangerous": "Likely Phishing",
        "Suspicious": "Suspicious",
        "Safe": "Likely Legitimate",
    }
    classification = content_result.get("classification") or classification_map.get(
        score_result.get("verdict", ""), "Insufficient Evidence"
    )

    now = datetime.now(timezone.utc)
    scan = EmailScan(
        user_id=user_id,
        model_version_id=mv_id,
        scan_status="completed",
        original_filename=original_filename,
        file_hash=result["parsed"].get("file_hash"),
        subject=headers.get("subject", ""),
        sender=headers.get("from", ""),
        reply_to=headers.get("reply_to", ""),
        classification=classification,
        model_score=content_result.get("phishing_probability"),
        overall_risk=overall_risk,
        scoring_rule_version=settings.SCORING_RULE_VERSION,
        full_result_json=json.dumps(result),
        completed_at=now,
        created_at=now,
    )
    db.add(scan)
    db.flush()  # get scan.id

    # Persist normalized findings
    findings = _extract_findings(result, scan.id)
    db.add_all(findings)

    # Persist normalized URLs
    urls = _extract_urls(result.get("url", {}), scan.id)
    db.add_all(urls)

    db.commit()
    db.refresh(scan)
    return scan
