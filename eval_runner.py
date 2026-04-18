import json
import time
import re
from pathlib import Path
from typing import Any

from src.llm_engine import analyze_with_llm

ALERTS_PATH = Path("sample_alerts.json")
EXPECTED_PATH = Path("expected_outputs.json")

MITRE_ID_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)
FALLBACK_SUMMARY = "LLM output could not be validated. Manual analyst review required."
FALLBACK_REASONING = "The model response failed validation checks, so the alert should be reviewed manually."


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def to_expected_map(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    expected_map: dict[str, dict[str, Any]] = {}
    for row in records:
        alert_id = str(row.get("alert_id", "")).strip()
        if alert_id:
            expected_map[alert_id] = row
    return expected_map


def normalize_severity(value: Any) -> str:
    return str(value or "").strip().lower()


def extract_mitre_id(text: Any) -> str | None:
    match = MITRE_ID_PATTERN.search(str(text or ""))
    if not match:
        return None
    return match.group(0).upper()


def mitre_id_matches(found_id: str | None, expected_id: str | None) -> bool:
    if not found_id or not expected_id:
        return False

    found = found_id.upper()
    expected = expected_id.upper()
    # Accept exact, parent->sub, or sub->parent matching.
    return found == expected or found.startswith(expected + ".") or expected.startswith(found + ".")


def is_fallback_output(prediction: dict[str, Any]) -> bool:
    return (
        str(prediction.get("incident_summary", "")).strip() == FALLBACK_SUMMARY
        and str(prediction.get("reasoning", "")).strip() == FALLBACK_REASONING
        and str(prediction.get("mitre_tactic", "")).strip() == "Unknown"
        and str(prediction.get("mitre_technique", "")).strip() == "Unknown"
    )


def pct(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return (numerator / denominator) * 100.0


def avg(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def print_table(rows: list[tuple[str, str]]) -> None:
    metric_width = max(len("Metric"), *(len(row[0]) for row in rows))
    value_width = max(len("Value"), *(len(row[1]) for row in rows))

    border = f"+-{'-' * metric_width}-+-{'-' * value_width}-+"
    print(border)
    print(f"| {'Metric'.ljust(metric_width)} | {'Value'.ljust(value_width)} |")
    print(border)
    for metric, value in rows:
        print(f"| {metric.ljust(metric_width)} | {value.ljust(value_width)} |")
    print(border)


def run_evaluation() -> None:
    alerts = load_json(ALERTS_PATH)
    expected_records = load_json(EXPECTED_PATH)

    if not isinstance(alerts, list):
        raise ValueError("sample_alerts.json must contain a list of alerts")
    if not isinstance(expected_records, list):
        raise ValueError("expected_outputs.json must contain a list of expected records")

    expected_map = to_expected_map(expected_records)

    evaluated = 0
    severity_correct = 0
    mitre_correct = 0
    fallback_count = 0
    missing_expected = 0

    confidence_values: list[float] = []
    latency_ms_values: list[float] = []

    for alert in alerts:
        alert_id = str(alert.get("alert_id", "")).strip()
        expected = expected_map.get(alert_id)

        if not expected:
            missing_expected += 1
            continue

        start = time.perf_counter()
        prediction = analyze_with_llm(alert)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        latency_ms_values.append(elapsed_ms)

        evaluated += 1

        if normalize_severity(prediction.get("severity")) == normalize_severity(expected.get("expected_severity")):
            severity_correct += 1

        predicted_id = extract_mitre_id(prediction.get("mitre_technique"))
        expected_id = extract_mitre_id(expected.get("expected_mitre_technique_id"))
        if mitre_id_matches(predicted_id, expected_id):
            mitre_correct += 1

        if is_fallback_output(prediction):
            fallback_count += 1

        confidence = prediction.get("confidence")
        if isinstance(confidence, (int, float)):
            confidence_values.append(float(confidence))

    rows = [
        ("Total Alerts", str(len(alerts))),
        ("Evaluated Alerts", str(evaluated)),
        ("Missing Expected Labels", str(missing_expected)),
        ("Severity Accuracy %", f"{pct(severity_correct, evaluated):.2f}%"),
        ("MITRE Technique Accuracy %", f"{pct(mitre_correct, evaluated):.2f}%"),
        ("Fallback Rate %", f"{pct(fallback_count, evaluated):.2f}%"),
        ("Avg Confidence Score", f"{avg(confidence_values):.4f}"),
        ("Avg Latency per Alert (ms)", f"{avg(latency_ms_values):.2f}"),
    ]

    print_table(rows)


if __name__ == "__main__":
    run_evaluation()
