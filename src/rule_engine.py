import re
from typing import Any

SEVERITY_RANK = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

MIMIKATZ_PATTERN = re.compile(r"mimikatz|lsass|credential dump", re.IGNORECASE)
ENCODED_PS_PATTERN = re.compile(r"encoded\s*powershell|obfuscated\s*powershell", re.IGNORECASE)
IMPOSSIBLE_TRAVEL_PATTERN = re.compile(r"impossible\s*travel", re.IGNORECASE)
DATA_EXFIL_PATTERN = re.compile(r"data\s*exfiltration|large\s*data\s*transfer", re.IGNORECASE)
PORT_SCAN_PATTERN = re.compile(r"port\s*scan|scanning\s*ports", re.IGNORECASE)


def _normalize_severity(value: Any) -> str:
    raw = str(value or "INFO").strip().upper()
    aliases = {
        "CRIT": "CRITICAL",
        "INFORMATIONAL": "INFO",
    }
    return aliases.get(raw, raw) if aliases.get(raw, raw) in SEVERITY_RANK else "INFO"


def _max_severity(left: str, right: str) -> str:
    lsev = _normalize_severity(left)
    rsev = _normalize_severity(right)
    return lsev if SEVERITY_RANK[lsev] >= SEVERITY_RANK[rsev] else rsev


def _merge_actions(base_actions: list[str], rule_actions: list[str]) -> list[str]:
    merged = []
    seen = set()
    for action in base_actions + rule_actions:
        text = str(action).strip()
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        merged.append(text)
    return merged[:5]


def evaluate_rule_signals(alert: dict[str, Any], threat_intel: dict[str, Any]) -> dict[str, Any]:
    raw_log = str(alert.get("raw_log", ""))
    alert_type = str(alert.get("alert_type", ""))
    full_text = f"{alert_type} {raw_log}"

    severity_floor = "INFO"
    confidence_floor = 0.0
    escalation_required = False
    mitre_hint = {"tactic": "", "technique": ""}
    reason_codes: list[str] = []
    recommended_actions: list[str] = []

    if MIMIKATZ_PATTERN.search(full_text):
        severity_floor = _max_severity(severity_floor, "CRITICAL")
        confidence_floor = max(confidence_floor, 0.9)
        escalation_required = True
        mitre_hint = {
            "tactic": "Credential Access",
            "technique": "OS Credential Dumping (T1003)",
        }
        reason_codes.append("rule_credential_dumping")
        recommended_actions.extend([
            "Isolate affected endpoint via EDR",
            "Reset privileged credentials immediately",
            "Collect volatile memory for forensic review",
        ])

    if ENCODED_PS_PATTERN.search(full_text) and re.search(r"outbound|connection|external\s*ip", full_text, re.IGNORECASE):
        severity_floor = _max_severity(severity_floor, "HIGH")
        confidence_floor = max(confidence_floor, 0.8)
        escalation_required = True
        mitre_hint = {
            "tactic": "Execution",
            "technique": "PowerShell (T1059.001)",
        }
        reason_codes.append("rule_encoded_powershell_outbound")
        recommended_actions.extend([
            "Isolate host with suspicious PowerShell execution",
            "Block outbound destination indicators",
            "Retrieve and decode PowerShell command for analysis",
        ])

    if IMPOSSIBLE_TRAVEL_PATTERN.search(full_text) and re.search(r"mfa\s*failure|mfa\s*failed", full_text, re.IGNORECASE):
        severity_floor = _max_severity(severity_floor, "HIGH")
        confidence_floor = max(confidence_floor, 0.8)
        escalation_required = True
        mitre_hint = {
            "tactic": "Credential Access",
            "technique": "Valid Accounts (T1078)",
        }
        reason_codes.append("rule_impossible_travel_mfa_failure")
        recommended_actions.extend([
            "Force password reset for impacted account",
            "Revoke active user sessions and refresh tokens",
            "Apply conditional access and strict MFA verification",
        ])

    if DATA_EXFIL_PATTERN.search(full_text) and re.search(r"ftp|external\s*ip|sensitive\s*documents", full_text, re.IGNORECASE):
        severity_floor = _max_severity(severity_floor, "CRITICAL")
        confidence_floor = max(confidence_floor, 0.9)
        escalation_required = True
        mitre_hint = {
            "tactic": "Exfiltration",
            "technique": "Exfiltration Over Alternative Protocol (T1048)",
        }
        reason_codes.append("rule_data_exfiltration")
        recommended_actions.extend([
            "Block exfiltration channel at network controls",
            "Isolate source asset from outbound connectivity",
            "Preserve transfer and DLP telemetry for investigation",
        ])

    if PORT_SCAN_PATTERN.search(full_text) and re.search(r"external\s*ip|from\s*ip", full_text, re.IGNORECASE):
        severity_floor = _max_severity(severity_floor, "MEDIUM")
        confidence_floor = max(confidence_floor, 0.6)
        mitre_hint = {
            "tactic": "Reconnaissance",
            "technique": "Active Scanning (T1595)",
        }
        reason_codes.append("rule_port_scan_external")
        recommended_actions.extend([
            "Block scanning source IP at perimeter firewall",
            "Increase monitoring on targeted hosts",
            "Review IDS and firewall logs for follow-on activity",
        ])

    ioc_enrichment = threat_intel.get("ioc_enrichment", [])
    known_malicious_hits = [
        ioc for ioc in ioc_enrichment
        if isinstance(ioc, dict) and bool(ioc.get("known_malicious"))
    ]
    if known_malicious_hits:
        severity_floor = _max_severity(severity_floor, "HIGH")
        confidence_floor = max(confidence_floor, 0.75)
        escalation_required = True
        reason_codes.append("rule_known_malicious_ioc")
        recommended_actions.extend([
            "Block malicious IOC indicators across controls",
            "Search environment for additional activity from malicious IOC",
        ])

    return {
        "severity_floor": severity_floor,
        "confidence_floor": round(confidence_floor, 2),
        "escalation_required": escalation_required,
        "mitre_hint": mitre_hint,
        "reason_codes": reason_codes,
        "recommended_actions": _merge_actions([], recommended_actions),
    }


def apply_rule_overrides(prediction: dict[str, Any], rule_signals: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(prediction, dict):
        return prediction

    adjusted = dict(prediction)

    rule_severity = _normalize_severity(rule_signals.get("severity_floor", "INFO"))
    model_severity = _normalize_severity(adjusted.get("severity", "INFO"))
    adjusted["severity"] = _max_severity(model_severity, rule_severity).title()

    confidence = adjusted.get("confidence")
    model_conf = float(confidence) if isinstance(confidence, (int, float)) else 0.0
    adjusted["confidence"] = min(1.0, max(model_conf, float(rule_signals.get("confidence_floor", 0.0))))

    if bool(rule_signals.get("escalation_required")):
        adjusted["escalation_required"] = True

    mitre_hint = rule_signals.get("mitre_hint", {})
    tactic_hint = str(mitre_hint.get("tactic", "")).strip()
    technique_hint = str(mitre_hint.get("technique", "")).strip()

    current_tactic = str(adjusted.get("mitre_tactic", "")).strip()
    current_technique = str(adjusted.get("mitre_technique", "")).strip()

    if tactic_hint and (not current_tactic or current_tactic.lower() == "unknown"):
        adjusted["mitre_tactic"] = tactic_hint
    if technique_hint and (not current_technique or current_technique.lower() == "unknown"):
        adjusted["mitre_technique"] = technique_hint

    base_actions = adjusted.get("recommended_actions", [])
    if not isinstance(base_actions, list):
        base_actions = []
    adjusted["recommended_actions"] = _merge_actions(base_actions, rule_signals.get("recommended_actions", []))

    reason_codes = rule_signals.get("reason_codes", [])
    if reason_codes:
        reasoning = str(adjusted.get("reasoning", "")).strip()
        codes_text = ", ".join(reason_codes)
        suffix = f" Rule engine baseline signals: {codes_text}."
        adjusted["reasoning"] = (reasoning + suffix).strip() if reasoning else suffix.strip()

    return adjusted
