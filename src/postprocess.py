import json
from typing import Any


def parse_model_output(raw_text: str) -> dict[str, Any]:
    return json.loads(raw_text)


def finalize_output(
    parsed: Any,
    original_alert: dict[str, Any],
    rule_signals: dict[str, Any],
    apply_rule_overrides_fn,
    load_mitre_mapping_fn,
    validate_llm_output_fn,
    build_fallback_output_fn,
) -> dict[str, Any]:
    if isinstance(parsed, dict):
        parsed = apply_rule_overrides_fn(parsed, rule_signals)

    mitre_mapping = load_mitre_mapping_fn()
    validation = validate_llm_output_fn(parsed, original_alert, mitre_mapping)

    if validation["is_valid"]:
        return validation["normalized_output"]

    print(validation["errors"])
    return build_fallback_output_fn(original_alert)
