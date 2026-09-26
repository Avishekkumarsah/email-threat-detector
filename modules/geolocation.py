"""
geolocation.py
---------------
Extracts IP addresses from the Received-header chain and looks up their
approximate location using the free ip-api.com service. Results are
cached in memory per-request so the same IP is never looked up twice.
"""

import re
import ipaddress
import requests
import config

_CACHE = {}

IP_REGEX = re.compile(
    r'(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[a-fA-F0-9:]{2,}:[a-fA-F0-9:]+)'
)


def is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_reserved or addr.is_multicast
            or (isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network("100.64.0.0/10"))
        )
    except ValueError:
        return False


def extract_ips(received_chain, headers):
    """Pull every plausible public IP out of Received headers + X-Originating-IP style headers."""
    found = []
    seen = set()

    for header in received_chain or []:
        # Prefer IPs inside [brackets] since those are usually the true connecting IP
        bracketed = re.findall(r"\[([\da-fA-F:\.]+)\]", header)
        candidates = bracketed if bracketed else IP_REGEX.findall(header)
        for ip in candidates:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                found.append(ip)

    for key in ("x-originating-ip", "x-sender-ip"):
        val = (headers or {}).get(key, "")
        for ip in IP_REGEX.findall(val or ""):
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            if ip not in seen:
                seen.add(ip)
                found.append(ip)

    return found


def lookup_ip(ip):
    """
    Look up IP location via https://ip-api.com with fallbacks to ipwho.is and freeipapi.com.
    Cached per IP in memory. Never raises.
    """
    if ip in _CACHE:
        return _CACHE[ip]

    headers_req = {"User-Agent": "EmailThreatDetector/2.0"}

    # Provider 1: ip-api.com (HTTPS)
    try:
        resp = requests.get(
            f"https://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,proxy,hosting,query"},
            timeout=4,
            headers=headers_req,
        )
        data = resp.json()
        if data.get("status") == "success":
            _CACHE[ip] = data
            return data
    except Exception:
        pass

    # Provider 2: ipwho.is (HTTPS fallback)
    try:
        resp = requests.get(
            f"https://ipwho.is/{ip}",
            timeout=4,
            headers=headers_req,
        )
        data = resp.json()
        if data.get("success"):
            res = {
                "status": "success",
                "query": ip,
                "country": data.get("country", ""),
                "countryCode": data.get("country_code", ""),
                "regionName": data.get("region", ""),
                "city": data.get("city", ""),
                "lat": data.get("latitude"),
                "lon": data.get("longitude"),
                "isp": data.get("connection", {}).get("isp", ""),
                "org": data.get("connection", {}).get("org", ""),
                "as": data.get("connection", {}).get("asn", ""),
                "proxy": data.get("security", {}).get("proxy", False),
                "hosting": data.get("security", {}).get("hosting", False),
            }
            _CACHE[ip] = res
            return res
    except Exception:
        pass

    # Provider 3: freeipapi.com (HTTPS fallback)
    try:
        resp = requests.get(
            f"https://freeipapi.com/api/json/{ip}",
            timeout=4,
            headers=headers_req,
        )
        data = resp.json()
        if data.get("ipAddress"):
            res = {
                "status": "success",
                "query": ip,
                "country": data.get("countryName", ""),
                "countryCode": data.get("countryCode", ""),
                "regionName": data.get("regionName", ""),
                "city": data.get("cityName", ""),
                "lat": data.get("latitude"),
                "lon": data.get("longitude"),
                "isp": data.get("asnName", ""),
                "org": "",
                "as": data.get("asn", ""),
                "proxy": False,
                "hosting": False,
            }
            _CACHE[ip] = res
            return res
    except Exception:
        pass

    fallback_data = {"status": "failed", "query": ip}
    _CACHE[ip] = fallback_data
    return fallback_data


def build_route(received_chain, headers):
    flags = []
    score = 0
    note = "Geolocation is approximate. VPNs, proxies, and hosting providers can hide the true sender location."

    try:
        all_ips = extract_ips(received_chain, headers)
        public_ips = [ip for ip in all_ips if is_public_ip(ip)]
        skipped_private = len(all_ips) - len(public_ips)

        if not public_ips:
            score += config.GEO_POINTS["no_public_ip"]
            flags.append({"check": "no_public_ip", "severity": "medium",
                           "detail": "No public sender IP could be found in the headers.",
                           "points": config.GEO_POINTS["no_public_ip"]})
            return {
                "hops": [], "origin": None, "countries": [], "flags": flags,
                "score": min(score, 100), "note": note, "error": None,
                "skipped_private_ips": skipped_private,
            }

        # Reverse so hop 1 = origin (Received headers are added newest-first)
        ordered_ips = list(reversed(public_ips))[: config.MAX_GEO_LOOKUPS]

        hops = []
        countries = []
        for i, ip in enumerate(ordered_ips, start=1):
            info = lookup_ip(ip)
            if info.get("status") != "success":
                continue
            label = "Origin" if i == 1 else ("Final server" if i == len(ordered_ips) else "Relay")
            location_parts = [p for p in [info.get("city"), info.get("regionName"), info.get("country")] if p]
            location_str = ", ".join(location_parts) if location_parts else (info.get("country") or "Unknown Location")

            hop = {
                "hop_number": i,
                "ip": ip,
                "country": info.get("country", ""),
                "country_code": info.get("countryCode", ""),
                "region": info.get("regionName", ""),
                "city": info.get("city", ""),
                "location_str": location_str,
                "lat": info.get("lat"),
                "lon": info.get("lon"),
                "isp": info.get("isp") or info.get("org") or "Unknown ISP",
                "org": info.get("org", ""),
                "asn": info.get("as", ""),
                "is_proxy": bool(info.get("proxy")),
                "is_hosting": bool(info.get("hosting")),
                "label": label,
            }
            hops.append(hop)
            if hop["country_code"]:
                countries.append(hop["country_code"])

        origin = hops[0] if hops else None

        if origin and (origin["is_proxy"] or origin["is_hosting"]):
            score += config.GEO_POINTS["proxy_or_hosting_origin"]
            flags.append({"check": "proxy_or_hosting_origin", "severity": "medium",
                           "detail": f"Origin IP {origin['ip']} belongs to a known proxy/hosting provider ({origin['org']}).",
                           "points": config.GEO_POINTS["proxy_or_hosting_origin"]})

        unique_countries = set(countries)
        if len(unique_countries) > config.MAX_COUNTRIES_BEFORE_FLAG:
            score += config.GEO_POINTS["many_countries"]
            flags.append({"check": "many_countries", "severity": "low",
                           "detail": f"Email route crosses {len(unique_countries)} different countries.",
                           "points": config.GEO_POINTS["many_countries"]})

        if origin and origin["country_code"] in config.HIGH_RISK_COUNTRIES:
            score += config.GEO_POINTS["high_risk_country"]
            flags.append({"check": "high_risk_country", "severity": "low",
                           "detail": f"Origin country ({origin['country']}) is on the configured watch list.",
                           "points": config.GEO_POINTS["high_risk_country"]})

        return {
            "hops": hops,
            "origin": origin,
            "countries": sorted(unique_countries),
            "flags": flags,
            "score": min(score, 100),
            "note": note,
            "error": None,
            "skipped_private_ips": skipped_private,
        }

    except Exception as e:
        return {"hops": [], "origin": None, "countries": [], "flags": [],
                "score": 0, "note": note, "error": f"Geolocation failed: {e}"}
