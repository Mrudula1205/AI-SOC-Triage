import ipaddress
import json
import re
from typing import Any
from urllib import error, parse, request

IPV4_CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_ip_candidates(raw_log: str) -> list[str]:
    seen = set()
    candidates = []
    for ip in IPV4_CANDIDATE_PATTERN.findall(raw_log):
        if ip not in seen:
            seen.add(ip)
            candidates.append(ip)
    return candidates


def lookup_abuseipdb(
    ip: str,
    api_key: str,
    timeout_sec: float,
    malicious_score_threshold: int,
) -> dict[str, Any]:
    query = parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    req = request.Request(
        url,
        headers={"Key": api_key, "Accept": "application/json"},
        method="GET",
    )

    with request.urlopen(req, timeout=timeout_sec) as response:
        payload = json.loads(response.read().decode("utf-8"))

    data = payload.get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))

    return {
        "ip": ip,
        "reputation_score": score,
        "known_malicious": score >= malicious_score_threshold,
        "country_code": data.get("countryCode") or "",
        "usage_type": data.get("usageType") or "",
        "isp": data.get("isp") or "",
        "total_reports": int(data.get("totalReports", 0) or 0),
        "last_reported_at": data.get("lastReportedAt") or "",
        "source": "abuseipdb",
    }


def build_threat_intel_context(
    alert: dict[str, Any],
    api_key: str,
    lookup_fn,
) -> dict[str, Any]:
    raw_log = str(alert.get("raw_log", ""))
    ip_candidates = extract_ip_candidates(raw_log)

    if not ip_candidates:
        return {
            "provider": "abuseipdb",
            "enabled": bool(api_key),
            "ips_found": [],
            "ioc_enrichment": [],
            "skipped_iocs": [],
        }

    enrichment = []
    skipped = []
    valid_public_ips = []

    for ip in ip_candidates:
        try:
            parsed_ip = ipaddress.ip_address(ip)
        except ValueError:
            skipped.append({"ip": ip, "reason": "invalid_ip_format"})
            continue

        if not parsed_ip.is_global:
            skipped.append({"ip": ip, "reason": "not_public_ip"})
            continue

        valid_public_ips.append(ip)

        if not api_key:
            skipped.append({"ip": ip, "reason": "api_key_not_configured"})
            continue

        try:
            enrichment.append(lookup_fn(ip))
        except error.HTTPError as exc:
            skipped.append({"ip": ip, "reason": f"api_error_{exc.code}"})
        except Exception:
            skipped.append({"ip": ip, "reason": "lookup_failed"})

    return {
        "provider": "abuseipdb",
        "enabled": bool(api_key),
        "ips_found": valid_public_ips,
        "ioc_enrichment": enrichment,
        "skipped_iocs": skipped,
    }
