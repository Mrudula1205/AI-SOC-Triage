import json
import os
from dotenv import load_dotenv
load_dotenv()  
from groq import Groq
from .guardrails import load_mitre_mapping, validate_llm_output, build_fallback_output
from .rule_engine import evaluate_rule_signals, apply_rule_overrides
from .prompt import SYSTEM_PROMPT
from .enrichment import build_threat_intel_context, lookup_abuseipdb
from .postprocess import parse_model_output, finalize_output
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


def _lookup_abuseipdb(ip: str) -> dict:
    return lookup_abuseipdb(
        ip=ip,
        api_key=ABUSEIPDB_API_KEY,
        timeout_sec=THREAT_INTEL_TIMEOUT_SEC,
        malicious_score_threshold=MALICIOUS_SCORE_THRESHOLD,
    )


def _build_threat_intel_context(alert: dict) -> dict:
    return build_threat_intel_context(
        alert=alert,
        api_key=ABUSEIPDB_API_KEY,
        lookup_fn=_lookup_abuseipdb,
    )


def _finalize_output(parsed: dict, original_alert: dict, rule_signals: dict) -> dict:
    return finalize_output(
        parsed=parsed,
        original_alert=original_alert,
        rule_signals=rule_signals,
        apply_rule_overrides_fn=apply_rule_overrides,
        load_mitre_mapping_fn=load_mitre_mapping,
        validate_llm_output_fn=validate_llm_output,
        build_fallback_output_fn=build_fallback_output,
    )

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
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
        )
        output_text = response.choices[0].message.content
    except Exception as exc:
        print(f"Error calling LLM: {exc}")
        return build_fallback_output(original_alert)

    try:
        parsed = parse_model_output(output_text)
    except Exception as exc:
        print(f"Error parsing LLM output: {exc}")
        return build_fallback_output(original_alert)

    return _finalize_output(parsed, original_alert, rule_signals)