"""
scoring.py
----------
Combines the four core checks (content, header, url, attachment) into
one final threat score using weights from config.py, plus a small bonus
from the geolocation check. If a module failed, its weight is
redistributed across the remaining working modules instead of being
silently treated as zero.

PLAIN-ENGLISH EXPLANATION (for the viva):
We don't trust any single check alone - a normal email can occasionally
trigger one weak signal. So instead we grade the email on four areas
(what it says, who it claims to be from, where its links go, and what
it's attached), weight the areas by how reliable they are (content and
header carry the most weight, attachments the least since most emails
have none), add a small bonus if its delivery route looks suspicious,
and only then decide Safe / Suspicious / Dangerous. If a check couldn't
run - the file skipped, or there was no attachment.
"""

import config


def _verdict_for(score):
    for name, (low, high) in config.VERDICT_THRESHOLDS.items():
        if low <= score <= high:
            return name
    return "Suspicious"


def compute_threat_score(content_result, header_result, url_result, attachment_result, geo_result):
    try:
        modules = {
            "content": content_result,
            "header": header_result,
            "url": url_result,
            "attachment": attachment_result,
        }

        working = {}
        skipped = []
        for name, result in modules.items():
            if result is None or result.get("error"):
                skipped.append(f"{name} ({result.get('error') if result else 'no result'})")
            else:
                working[name] = result

        if not working:
            return {
                "final_score": 0, "verdict": "Suspicious", "breakdown": [],
                "reasons": [], "skipped_checks": skipped,
                "error": "All checks failed - unable to score this email.",
            }

        # Redistribute weight of skipped modules proportionally across the rest
        total_weight = sum(config.WEIGHTS[name] for name in working)
        breakdown = []
        weighted_sum = 0.0

        for name, result in working.items():
            raw_score = result.get("phishing_probability", result.get("score", 0))
            effective_weight = config.WEIGHTS[name] / total_weight
            contribution = raw_score * effective_weight
            weighted_sum += contribution
            breakdown.append({
                "category": name.capitalize(),
                "raw_score": round(raw_score, 1),
                "weight": round(effective_weight, 2),
                "contribution": round(contribution, 1),
            })

        geo_score = geo_result.get("score", 0) if geo_result and not geo_result.get("error") else 0
        geo_bonus = min(geo_score, config.GEO_BONUS_CAP)
        breakdown.append({
            "category": "Geo bonus",
            "raw_score": geo_score,
            "weight": "capped",
            "contribution": geo_bonus,
        })

        final_score = min(round(weighted_sum + geo_bonus), 100)
        verdict = _verdict_for(final_score)

        all_flags = []
        for result in list(working.values()) + ([geo_result] if geo_result and not geo_result.get("error") else []):
            all_flags.extend(result.get("flags", []))
        all_flags.sort(key=lambda f: f.get("points", 0), reverse=True)
        reasons = [f["detail"] for f in all_flags[:8]]

        return {
            "final_score": final_score,
            "verdict": verdict,
            "breakdown": breakdown,
            "reasons": reasons,
            "skipped_checks": skipped,
            "error": None,
        }

    except Exception as e:
        return {
            "final_score": 0, "verdict": "Suspicious", "breakdown": [],
            "reasons": [], "skipped_checks": [], "error": f"Scoring failed: {e}",
        }
