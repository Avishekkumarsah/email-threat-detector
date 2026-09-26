"""
header_analysis.py
-------------------
Looks for sender-spoofing signals: SPF/DKIM/DMARC results, From vs
Reply-To/Return-Path mismatches, brand impersonation from free-mail
accounts, and lookalike domains.
"""

import re
import difflib
import config


def _add_flag(flags, check, severity, detail, points):
    flags.append({"check": check, "severity": severity, "detail": detail, "points": points})
    return points


def _auth_result(auth_results, key):
    """Pull 'pass'/'fail'/'none'/etc out of an Authentication-Results header for spf/dkim/dmarc."""
    if not auth_results:
        return "none"
    match = re.search(rf"{key}=(\w+)", auth_results, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def _is_lookalike(domain, brands, threshold=0.82):
    """Catch things like paypa1.com, arnazon.com using simple string similarity."""
    if not domain:
        return None
    core = domain.split(".")[0]
    for brand in brands:
        if core == brand:
            continue  # exact match to the real brand name isn't a lookalike
        ratio = difflib.SequenceMatcher(None, core, brand).ratio()
        if ratio >= threshold:
            return brand
    return None


def analyze_headers(headers):
    flags = []
    score = 0

    try:
        if not headers:
            return {"score": 0, "flags": [], "error": "No headers to analyze"}

        auth = headers.get("authentication_results", "")
        spf = _auth_result(auth, "spf") or ("pass" if "pass" in headers.get("received_spf", "").lower() else "none")
        dkim = _auth_result(auth, "dkim")
        dmarc = _auth_result(auth, "dmarc")

        if spf == "fail":
            score += _add_flag(flags, "spf_fail", "high", "SPF check failed - sending server is not authorized for this domain.", config.HEADER_POINTS["spf_fail"])
        elif spf == "none":
            score += _add_flag(flags, "spf_none", "low", "No SPF result found.", config.HEADER_POINTS["spf_none"])

        if dkim == "fail":
            score += _add_flag(flags, "dkim_fail", "high", "DKIM signature failed verification.", config.HEADER_POINTS["dkim_fail"])
        elif dkim == "none" and not headers.get("dkim_signature_present"):
            score += _add_flag(flags, "dkim_none", "low", "Email is not DKIM signed.", config.HEADER_POINTS["dkim_none"])

        if dmarc == "fail":
            score += _add_flag(flags, "dmarc_fail", "medium", "DMARC policy check failed.", config.HEADER_POINTS["dmarc_fail"])

        from_domain = headers.get("from_domain", "")
        reply_domain = headers.get("reply_to_domain", "")
        return_domain = headers.get("return_path_domain", "")

        if reply_domain and from_domain and reply_domain != from_domain:
            score += _add_flag(flags, "reply_to_mismatch", "high",
                                f"From domain '{from_domain}' does not match Reply-To domain '{reply_domain}'.",
                                config.HEADER_POINTS["reply_to_mismatch"])

        if return_domain and from_domain and return_domain != from_domain:
            score += _add_flag(flags, "return_path_mismatch", "medium",
                                f"From domain '{from_domain}' does not match Return-Path domain '{return_domain}'.",
                                config.HEADER_POINTS["return_path_mismatch"])

        from_name = (headers.get("from_name") or "").lower()
        if from_domain in config.FREEMAIL_DOMAINS:
            for brand in config.KNOWN_BRANDS:
                if brand in from_name:
                    score += _add_flag(flags, "freemail_brand_impersonation", "high",
                                        f"Display name mentions '{brand}' but sends from a free-mail address ({from_domain}).",
                                        config.HEADER_POINTS["freemail_brand_impersonation"])
                    break

        lookalike = _is_lookalike(from_domain, config.KNOWN_BRANDS)
        if lookalike:
            score += _add_flag(flags, "lookalike_domain", "high",
                                f"Sender domain '{from_domain}' closely resembles '{lookalike}'.",
                                config.HEADER_POINTS["lookalike_domain"])

        if not headers.get("message_id"):
            score += _add_flag(flags, "missing_message_id", "low", "Missing Message-ID header.", config.HEADER_POINTS["missing_message_id"])
        if not headers.get("date"):
            score += _add_flag(flags, "missing_date", "low", "Missing Date header.", config.HEADER_POINTS["missing_date"])

        subject = headers.get("subject", "") or ""
        caps_ratio = sum(1 for c in subject if c.isupper()) / max(len(subject), 1)
        if (caps_ratio > 0.6 and len(subject) > 5) or subject.count("!") >= 2 or \
           any(w in subject.upper() for w in ["URGENT", "ACTION REQUIRED", "IMMEDIATELY"]):
            score += _add_flag(flags, "suspicious_subject", "medium",
                                f"Subject line uses urgency/alarm tactics: \"{subject}\"",
                                config.HEADER_POINTS["suspicious_subject"])

        return {"score": min(score, 100), "flags": flags, "error": None}

    except Exception as e:
        return {"score": 0, "flags": [], "error": f"Header analysis failed: {e}"}
