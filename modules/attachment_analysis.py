"""
attachment_analysis.py
-----------------------
Checks attachment metadata ONLY (filename, extension, declared type,
size, hash). Attachments are never opened, saved to disk, or executed
anywhere in this project.
"""

import os
import requests
import config


def _add_flag(flags, check, severity, detail, points):
    flags.append({"check": check, "severity": severity, "detail": detail, "points": points})
    return points


def _vt_lookup_hash(sha256):
    if not config.VT_API_KEY or not sha256:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": config.VT_API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json()["data"]["attributes"]["last_analysis_stats"]
    except Exception:
        return None
    return None


# Very small map of content-type -> expected extensions, just enough to
# catch obvious mismatches without maintaining a huge MIME table.
CONTENT_TYPE_EXPECTATIONS = {
    "application/pdf": [".pdf"],
    "image/jpeg": [".jpg", ".jpeg"],
    "image/png": [".png"],
    "text/plain": [".txt"],
}


def analyze_attachments(attachments):
    flags = []
    score = 0
    vt_lookups_used = 0

    try:
        if not attachments:
            return {"score": 0, "flags": [], "attachment_results": [], "error": None}

        results = []
        for att in attachments:
            att_flags = []
            att_score = 0
            filename = att.get("filename") or "unnamed"
            lower = filename.lower()
            ext = os.path.splitext(lower)[1]

            if ext in config.HIGH_RISK_EXTENSIONS:
                att_score += _add_flag(att_flags, "high_risk_extension", "high",
                                        f"'{filename}' has a high-risk extension ({ext}).",
                                        config.ATTACHMENT_POINTS["high_risk_extension"])

            if ext in config.MACRO_EXTENSIONS:
                att_score += _add_flag(att_flags, "macro_enabled", "high",
                                        f"'{filename}' is a macro-enabled Office file ({ext}).",
                                        config.ATTACHMENT_POINTS["macro_enabled"])

            name_no_ext = lower.rsplit(ext, 1)[0] if ext else lower
            if "." in name_no_ext:
                inner_ext = "." + name_no_ext.rsplit(".", 1)[1]
                if inner_ext in [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png", ".txt"]:
                    att_score += _add_flag(att_flags, "double_extension", "high",
                                            f"'{filename}' uses a double extension - looks like a document but is really '{ext}'.",
                                            config.ATTACHMENT_POINTS["double_extension"])

            if ext in config.ARCHIVE_EXTENSIONS:
                att_score += _add_flag(att_flags, "archive_unknown_contents", "medium",
                                        f"'{filename}' is an archive - contents cannot be inspected here.",
                                        config.ATTACHMENT_POINTS["archive_unknown_contents"])

            ctype = att.get("content_type", "")
            expected = CONTENT_TYPE_EXPECTATIONS.get(ctype)
            if expected and ext and ext not in expected:
                att_score += _add_flag(att_flags, "extension_mismatch", "medium",
                                        f"'{filename}' declares type '{ctype}' but has extension '{ext}'.",
                                        config.ATTACHMENT_POINTS["extension_mismatch"])

            vt_stats = None
            if vt_lookups_used < config.MAX_VT_HASH_LOOKUPS:
                vt_stats = _vt_lookup_hash(att.get("sha256"))
                if vt_stats is not None:
                    vt_lookups_used += 1
                    if vt_stats.get("malicious", 0) > 0:
                        att_score += _add_flag(att_flags, "virustotal_flagged", "high",
                                                f"VirusTotal: {vt_stats.get('malicious')} engines flagged '{filename}' as malicious.", 60)

            results.append({
                "filename": filename,
                "content_type": ctype,
                "size_bytes": att.get("size_bytes"),
                "sha256": att.get("sha256"),
                "score": min(att_score, 100),
                "flags": att_flags,
            })
            flags.extend(att_flags)
            score = max(score, att_score)

        return {"score": min(score, 100), "flags": flags, "attachment_results": results, "error": None}

    except Exception as e:
        return {"score": 0, "flags": [], "attachment_results": [], "error": f"Attachment analysis failed: {e}"}
