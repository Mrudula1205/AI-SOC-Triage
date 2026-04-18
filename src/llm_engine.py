import json
import os
import ipaddress
import re
from urllib import error, parse, request
from dotenv import load_dotenv
load_dotenv()  
from groq import Groq
from .guardrails import load_mitre_mapping, validate_llm_output, build_fallback_output
from .rule_engine import evaluate_rule_signals, apply_rule_overrides
from .prompt import SYSTEM_PROMPT
from .config import (
    CONTROL_CHARS_PATTERN,
    MAX_LLM_FIELD_LENGTH,
    PROMPT_INJECTION_PHRASES,
    SANITIZE_REPLACEMENT_TOKEN,
)

GROQ_API_KEY = os.getenv("GROQ_API")
MODEL=os.getenv("MODEL")

if not GROQ_API_KEY:
    raise ValueError("GROQ_API key not found in environment variables")
if not MODEL:
    raise ValueError("MODEL not found in environment variables")

client = Groq(api_key=GROQ_API_KEY)

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
THREAT_INTEL_TIMEOUT_SEC = float(os.getenv("THREAT_INTEL_TIMEOUT_SEC", "3"))
MALICIOUS_SCORE_THRESHOLD = int(os.getenv("MALICIOUS_SCORE_THRESHOLD", "25"))
IPV4_CANDIDATE_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def _sanitize_text(value: str) -> str:
    cleaned = CONTROL_CHARS_PATTERN.sub(" ", value)

    for pattern in PROMPT_INJECTION_PHRASES:
        cleaned = pattern.sub(SANITIZE_REPLACEMENT_TOKEN, cleaned)

    cleaned = " ".join(cleaned.split())
    if len(cleaned) > MAX_LLM_FIELD_LENGTH:
        cleaned = cleaned[:MAX_LLM_FIELD_LENGTH] + "..."

    return cleaned


def sanitize_input(alert: dict) -> dict:
    def _walk(value):
        if isinstance(value, str):
            return _sanitize_text(value)
        if isinstance(value, dict):
            return {k: _walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_walk(v) for v in value]
        return value

    return _walk(alert)


def _extract_ip_candidates(raw_log: str) -> list[str]:
    seen = set()
    candidates = []
    for ip in IPV4_CANDIDATE_PATTERN.findall(raw_log):
        if ip not in seen:
            seen.add(ip)
            candidates.append(ip)
    return candidates


def _lookup_abuseipdb(ip: str) -> dict:
    query = parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    req = request.Request(
        url,
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        method="GET",
    )

    with request.urlopen(req, timeout=THREAT_INTEL_TIMEOUT_SEC) as response:
        payload = json.loads(response.read().decode("utf-8"))

    data = payload.get("data", {})
    score = int(data.get("abuseConfidenceScore", 0))

    return {
        "ip": ip,
        "reputation_score": score,
        "known_malicious": score >= MALICIOUS_SCORE_THRESHOLD,
        "country_code": data.get("countryCode") or "",
        "usage_type": data.get("usageType") or "",
        "isp": data.get("isp") or "",
        "total_reports": int(data.get("totalReports", 0) or 0),
        "last_reported_at": data.get("lastReportedAt") or "",
        "source": "abuseipdb",
    }


def _build_threat_intel_context(alert: dict) -> dict:
    raw_log = str(alert.get("raw_log", ""))
    ip_candidates = _extract_ip_candidates(raw_log)

    if not ip_candidates:
        return {
            "provider": "abuseipdb",
            "enabled": bool(ABUSEIPDB_API_KEY),
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

        if not ABUSEIPDB_API_KEY:
            skipped.append({"ip": ip, "reason": "api_key_not_configured"})
            continue

        try:
            enrichment.append(_lookup_abuseipdb(ip))
        except error.HTTPError as exc:
            skipped.append({"ip": ip, "reason": f"api_error_{exc.code}"})
        except Exception:
            skipped.append({"ip": ip, "reason": "lookup_failed"})

    return {
        "provider": "abuseipdb",
        "enabled": bool(ABUSEIPDB_API_KEY),
        "ips_found": valid_public_ips,
        "ioc_enrichment": enrichment,
        "skipped_iocs": skipped,
    }

def analyze_with_llm(alert: dict):
    original_alert = alert
    sanitized_alert = sanitize_input(alert)
    threat_intel = _build_threat_intel_context(original_alert)
    rule_signals = evaluate_rule_signals(original_alert, threat_intel)

    prompt_payload = dict(sanitized_alert)
    prompt_payload["_threat_intel"] = threat_intel
    prompt_payload["_rule_signals"] = rule_signals

    user_prompt = f"""
Analyze this security alert:

{json.dumps(prompt_payload, indent=2)}

Return structured JSON output.
"""
    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.2
        )

        output_text = response.choices[0].message.content
    except Exception as e:
        print(f"Error calling LLM: {e}")
        return build_fallback_output(original_alert)


    try:
        parsed = json.loads(output_text)
    except Exception as e:
        print(f"Error parsing LLM output: {e}")
        return build_fallback_output(original_alert)

    if isinstance(parsed, dict):
        parsed = apply_rule_overrides(parsed, rule_signals)

    mitre_mapping = load_mitre_mapping()
    validation = validate_llm_output(parsed, original_alert, mitre_mapping)

    if validation["is_valid"]:
        return validation["normalized_output"]
    else: 
        print(validation["errors"])

    return build_fallback_output(original_alert)