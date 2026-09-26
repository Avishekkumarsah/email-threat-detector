"""
url_analysis.py
----------------
Inspects every link found by parser.py for classic phishing-URL tricks:
IP-based links, shorteners, "@" tricks, anchor-text mismatches, risky
TLDs, punycode domains, and lookalike brand domains. Optional VirusTotal
lookup is used only if a key is configured, and failures never crash
the app.
"""

import re
import difflib
from urllib.parse import urlparse
import requests
import config


def _add_flag(flags, check, severity, detail, points):
    flags.append({"check": check, "severity": severity, "detail": detail, "points": points})
    return points


def _is_ip(host):
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host or ""))


def _is_lookalike(domain, brands, threshold=0.82):
    if not domain:
        return None
    core = domain.split(".")[0]
    for brand in brands:
        if core == brand:
            continue
        if difflib.SequenceMatcher(None, core, brand).ratio() >= threshold:
            return brand
    return None


def _vt_lookup_url(url):
    """Optional VirusTotal check. Returns None silently if no key / any failure."""
    if not config.VT_API_KEY:
        return None
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": config.VT_API_KEY},
            timeout=5,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return stats
    except Exception:
        return None
    return None


def _analyze_one_url(entry, vt_lookups_used):
    url = entry["url"]
    flags = []
    score = 0
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""

        if _is_ip(host):
            score += _add_flag(flags, "ip_based_url", "high", f"Link uses a raw IP address: {url}", config.URL_POINTS["ip_based_url"])

        if len(url) > config.LONG_URL_THRESHOLD:
            score += _add_flag(flags, "long_url", "low", f"Unusually long URL ({len(url)} chars).", config.URL_POINTS["long_url"])

        if any(short in host for short in config.URL_SHORTENERS):
            score += _add_flag(flags, "shortener", "medium", f"Uses a URL shortener ({host}) which hides the real destination.", config.URL_POINTS["shortener"])

        if "@" in url:
            score += _add_flag(flags, "at_symbol", "high", "URL contains '@' which can hide the real destination host.", config.URL_POINTS["at_symbol"])

        if host.count(".") > config.MAX_SUBDOMAINS:
            score += _add_flag(flags, "many_subdomains", "low", f"Domain has many subdomains ({host}).", config.URL_POINTS["many_subdomains"])

        if parsed.scheme != "https":
            score += _add_flag(flags, "not_https", "low", "Link does not use HTTPS.", config.URL_POINTS["not_https"])

        anchor = entry.get("anchor_text")
        if anchor:
            anchor_host_match = re.search(r"([\w-]+\.)+[a-z]{2,}", anchor.lower())
            if anchor_host_match and anchor_host_match.group(0) not in host:
                score += _add_flag(flags, "anchor_mismatch", "high",
                                    f"Visible text says '{anchor}' but the link goes to '{host}'.",
                                    config.URL_POINTS["anchor_mismatch"])

        if any(host.endswith(tld) for tld in config.SUSPICIOUS_TLDS):
            score += _add_flag(flags, "suspicious_tld", "medium", f"Uses an uncommon/high-risk TLD ({host}).", config.URL_POINTS["suspicious_tld"])

        if host.startswith("xn--") or ".xn--" in host:
            score += _add_flag(flags, "punycode", "high", f"Domain uses punycode encoding ({host}), often used to fake a trusted domain.", config.URL_POINTS["punycode"])

        lookalike = _is_lookalike(host, config.KNOWN_BRANDS)
        if lookalike:
            score += _add_flag(flags, "lookalike_domain", "high", f"Domain '{host}' closely resembles '{lookalike}'.", config.URL_POINTS["lookalike_domain"])

        vt_stats = None
        if vt_lookups_used[0] < config.MAX_VT_URL_LOOKUPS:
            vt_stats = _vt_lookup_url(url)
            if vt_stats is not None:
                vt_lookups_used[0] += 1
                if vt_stats.get("malicious", 0) > 0:
                    score += _add_flag(flags, "virustotal_flagged", "high",
                                        f"VirusTotal: {vt_stats.get('malicious')} engines flagged this URL as malicious.", 40)

        return {"url": url, "score": min(score, 100), "flags": flags}

    except Exception as e:
        return {"url": url, "score": 0, "flags": [{"check": "error", "severity": "low", "detail": str(e), "points": 0}]}


def analyze_urls(urls):
    """
    Returns overall {"score", "flags", "url_results", "error"}.
    "flags" is a flattened list (used by the scoring engine's top-reasons list),
    "url_results" keeps the per-URL breakdown for the dashboard.
    """
    try:
        if not urls:
            return {"score": 0, "flags": [], "url_results": [], "error": None}

        vt_lookups_used = [0]
        url_results = [_analyze_one_url(u, vt_lookups_used) for u in urls]

        all_flags = []
        for r in url_results:
            all_flags.extend(r["flags"])

        overall_score = min(max((r["score"] for r in url_results), default=0), 100)
        return {"score": overall_score, "flags": all_flags, "url_results": url_results, "error": None}

    except Exception as e:
        return {"score": 0, "flags": [], "url_results": [], "error": f"URL analysis failed: {e}"}
