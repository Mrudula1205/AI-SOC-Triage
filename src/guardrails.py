import json
import re
#from normalize import normalize_llm_output

ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
REQUIRED_FIELDS = {
    "alert_id",
    "incident_summary",
    "severity",
    "confidence",
    "mitre_tactic",
    "mitre_technique",
    "reasoning",
    "recommended_actions",
    "escalation_required"
}


def load_mitre_mapping(path="mitre_mapping.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_required_fields(output: dict) -> list[str]:
    missing = [field for field in REQUIRED_FIELDS if field not in output]
    return missing


def validate_severity(output: dict) -> list[str]:
    errors = []
    severity = output.get("severity")
    if severity not in ALLOWED_SEVERITIES:
        errors.append(f"Invalid severity: {severity}")
    return errors


def validate_confidence(output: dict) -> list[str]:
    errors = []
    confidence = output.get("confidence")

    if not isinstance(confidence, (int, float)):
        errors.append("Confidence must be a number")
        return errors

    if not (0 <= confidence <= 1):
        errors.append(f"Confidence out of range: {confidence}")

    return errors


def validate_actions(output: dict) -> list[str]:
    errors = []
    actions = output.get("recommended_actions")

    if not isinstance(actions, list):
        errors.append("recommended_actions must be a list")
        return errors

    if len(actions) == 0:
        errors.append("recommended_actions cannot be empty")

    if len(actions) > 5:
        errors.append("recommended_actions should not exceed 5 items")

    return errors

def validate_mitre_mapping(output: dict, alert: dict, mitre_mapping: dict) -> list[str]:
    errors = []

    alert_type = alert.get("alert_type")
    expected = mitre_mapping.get(alert_type)

    if not expected:
        errors.append(f"No MITRE mapping configured for alert type: {alert_type}")
        return errors

    tactic = str(output.get("mitre_tactic", "")).strip().lower()
    technique_text = str(output.get("mitre_technique", "")).strip()

    expected_tactic = expected["tactic"].strip().lower()
    expected_technique = expected["technique"].strip()
    expected_id = expected["technique_id"].strip().upper()
    allowed_subtechniques = expected.get("allowed_subtechniques", [])

    # Loose tactic validation
    if expected_tactic not in tactic:
        errors.append(
            f"Invalid tactic '{output.get('mitre_tactic')}' for alert type '{alert_type}'. Expected '{expected['tactic']}'"
        )

    # Extract ATT&CK IDs from LLM output
    found_ids = extract_attack_ids(technique_text)

    # First preference: validate by ATT&CK ID family
    if found_ids:
        matched = any(
            attack_id_matches(found_id, expected_id, allowed_subtechniques)
            for found_id in found_ids
        )
        if not matched:
            errors.append(
                f"Invalid technique '{technique_text}' for alert type '{alert_type}'. "
                f"Expected '{expected_technique} ({expected_id})' or a valid sub-technique."
            )
    else:
        # Fallback: if no ID is present, do loose text validation
        expected_technique_lower = expected_technique.lower()
        if expected_technique_lower not in technique_text.lower():
            errors.append(
                f"Invalid technique '{technique_text}' for alert type '{alert_type}'. "
                f"Expected technique related to '{expected_technique}'."
            )

    return errors

def validate_llm_output(output: dict, alert: dict, mitre_mapping: dict) -> dict:
    #normalized = normalize_llm_output(output)

    errors = []
    errors.extend(validate_required_fields(output))
    errors.extend(validate_severity(output))
    errors.extend(validate_confidence(output))
    errors.extend(validate_actions(output))
    errors.extend(validate_mitre_mapping(output, alert, mitre_mapping))

    return {
        "is_valid": len(errors) == 0,
        "errors": errors,
        "normalized_output": output
    }

def build_fallback_output(alert: dict) -> dict:
    return {
        "alert_id": alert.get("alert_id", "UNKNOWN"),
        "incident_summary": "LLM output could not be validated. Manual analyst review required.",
        "severity": "Medium",
        "confidence": 0.5,
        "mitre_tactic": "Unknown",
        "mitre_technique": "Unknown",
        "reasoning": "The model response failed validation checks, so the alert should be reviewed manually.",
        "recommended_actions": [
            "Review the raw alert manually",
            "Validate source telemetry",
            "Escalate to analyst if suspicious"
        ],
        "escalation_required": True
    }

def extract_attack_ids(text: str) -> list[str]:
    if not text:
        return []
    return re.findall(r'T\d{4}(?:\.\d{3})?', text.upper())

def attack_id_matches(found_id: str, expected_id: str, allowed_subtechniques: list[str]) -> bool:
    found_id = found_id.upper()
    expected_id = expected_id.upper()
    allowed_subtechniques = [x.upper() for x in allowed_subtechniques]

    if found_id == expected_id or found_id in allowed_subtechniques or found_id.startswith(expected_id + "."):
        return True

    return False