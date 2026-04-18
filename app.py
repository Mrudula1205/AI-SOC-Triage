import html
import json
import os
import importlib
from datetime import datetime
from typing import Any

import streamlit as st
from src.config import SAMPLE_ALERT

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_STYLE = {
    "CRITICAL": {"accent": "#E24B4A", "bg": "#FCEBEB", "text": "#A32D2D"},
    "HIGH": {"accent": "#BA7517", "bg": "#FAEEDA", "text": "#633806"},
    "MEDIUM": {"accent": "#1D9E75", "bg": "#E1F5EE", "text": "#085041"},
    "LOW": {"accent": "#185FA5", "bg": "#E6F1FB", "text": "#0C447C"},
    "INFO": {"accent": "#888780", "bg": "#F1EFE8", "text": "#444441"},
}


def _inject_css() -> None:
    st.markdown(
        """
<style>
[data-testid="stSidebar"] { min-width: 220px; max-width: 220px; }
[data-testid="stSidebar"] .block-container { padding-top: 1rem; }

.app-title { font-size: 1.1rem; font-weight: 700; margin-bottom: 0.1rem; }
.app-subtitle { color: #6a6a6a; font-size: 0.8rem; margin-bottom: 1rem; }

.metric-card {
    border: 1px solid #e8e8e8;
    border-radius: 10px;
    padding: 12px;
    background: #ffffff;
}
.metric-title { font-size: 0.75rem; color: #666; margin-bottom: 6px; }
.metric-value { font-size: 1.5rem; font-weight: 700; }

.alerts-scroll {
    max-height: 62vh;
    overflow-y: auto;
    padding-right: 6px;
}

.alert-card {
    border: 1px solid #e7e7e7;
    border-radius: 10px;
    margin: 0 0 10px 0;
    overflow: hidden;
    background: #fff;
}

.alert-summary {
    list-style: none;
    cursor: pointer;
    display: grid;
    grid-template-columns: 3px 1fr auto;
    gap: 10px;
    align-items: center;
    padding: 10px;
}

.alert-main { min-width: 0; }
.alert-id {
    font-family: "Courier New", monospace;
    font-size: 0.8rem;
    color: #555;
}
.alert-type {
    font-size: 1rem;
    font-weight: 600;
    margin: 2px 0 6px 0;
    color: #222;
}
.badge-row { display: flex; flex-wrap: wrap; gap: 6px; }
.badge {
    border-radius: 999px;
    padding: 3px 8px;
    font-size: 0.72rem;
    border: 1px solid #e6e6e6;
    color: #444;
    background: #fafafa;
}

.chevron { font-size: 1.1rem; color: #666; }

.card-body { padding: 0 12px 12px 12px; }

.raw-log {
    margin: 6px 0 10px 0;
    font-family: "Courier New", monospace;
    font-size: 0.82rem;
    background: #f6f7f9;
    border: 1px solid #e6e8eb;
    border-radius: 8px;
    padding: 10px;
    white-space: pre-wrap;
}

.two-col {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
}
.panel {
    border: 1px solid #ececec;
    border-radius: 8px;
    padding: 10px;
    background: #fff;
}
.panel-title { font-size: 0.82rem; color: #666; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.03em; }
.panel-content { font-size: 0.92rem; color: #222; line-height: 1.45; }

.fp-note {
    margin-top: 10px;
    background: #f9f9f9;
    border: 1px solid #ececec;
    border-radius: 8px;
    padding: 8px 10px;
    color: #5d5d5d;
    font-size: 0.85rem;
}

.source-box {
    margin-top: 1rem;
    font-size: 0.82rem;
    color: #666;
    border-top: 1px solid #e6e6e6;
    padding-top: 0.75rem;
}
</style>
        """,
        unsafe_allow_html=True,
    )


def _load_alerts_from_text(raw_text: str) -> list[dict[str, Any]]:
    payload = json.loads(raw_text)
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]
    raise ValueError("Input JSON must be an object or list of objects")


def _load_sample_alerts() -> list[dict[str, Any]]:
    with open(SAMPLE_ALERT, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def _normalize_severity(value: Any) -> str:
    sev = str(value or "INFO").strip().upper()
    aliases = {
        "CRIT": "CRITICAL",
        "INFORMATIONAL": "INFO",
    }
    sev = aliases.get(sev, sev)
    return sev if sev in SEVERITY_ORDER else "INFO"


def _ensure_llm_engine(api_key: str):
    """Load or reload llm_engine when API key changes in the UI."""
    api_key = api_key.strip()
    os.environ["GROQ_API"] = api_key

    engine = st.session_state.get("_llm_engine_module")
    loaded_key = st.session_state.get("_llm_engine_api_key", "")

    if engine is None or loaded_key != api_key:
        import src.llm_engine

        engine = importlib.reload(src.llm_engine)
        st.session_state["_llm_engine_module"] = engine
        st.session_state["_llm_engine_api_key"] = api_key

    return engine


def _map_engine_output_to_ui(triage: dict[str, Any]) -> dict[str, Any]:
    """Adapt llm_engine schema to UI card schema."""
    summary = str(triage.get("incident_summary", "")).strip() or "No summary available."
    reasoning = str(triage.get("reasoning", "")).strip()
    if reasoning:
        summary = f"{summary} {reasoning}"

    playbook = triage.get("recommended_actions", [])
    if not isinstance(playbook, list):
        playbook = []

    fp_note = ""
    if bool(triage.get("escalation_required")):
        fp_note = "Escalation recommended based on current evidence."
    else:
        fp_note = "Likely low-risk or potential false positive based on current evidence."

    return {
        "severity": _normalize_severity(triage.get("severity", "INFO")),
        "mitre_technique": str(triage.get("mitre_technique", "Unknown")),
        "mitre_tactic": str(triage.get("mitre_tactic", "Unknown")),
        "summary": summary,
        "playbook": [str(step).strip() for step in playbook if str(step).strip()],
        "false_positive_note": triage.get("false_positive_note", fp_note)
    }


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _time_range_text(alerts: list[dict[str, Any]]) -> str:
    times = [_parse_timestamp(a.get("timestamp")) for a in alerts]
    valid = [t for t in times if t is not None]
    if not valid:
        return "No timestamp range"
    start = min(valid).strftime("%Y-%m-%d %H:%M")
    end = max(valid).strftime("%Y-%m-%d %H:%M")
    return f"{start} to {end}"


def _safe_alert_id(alert: dict[str, Any], index: int) -> str:
    value = str(alert.get("alert_id") or "").strip()
    return value or f"ALERT-{index:04d}"


def _render_metric_card(title: str, value: int, severity: str | None = None) -> None:
    style = SEVERITY_STYLE.get(severity or "INFO")
    color = style["accent"] if style else "#222"
    st.markdown(
        f"""
<div class="metric-card">
  <div class="metric-title">{html.escape(title)}</div>
  <div class="metric-value" style="color:{color};">{value}</div>
</div>
        """,
        unsafe_allow_html=True,
    )


def _render_alert_card(alert: dict[str, Any], triage: dict[str, Any]) -> None:
    severity = _normalize_severity(triage.get("severity"))
    style = SEVERITY_STYLE[severity]

    alert_id = html.escape(str(alert.get("alert_id", "UNKNOWN")))
    alert_type = html.escape(str(alert.get("alert_type", "Unknown Alert Type")))
    source = html.escape(str(alert.get("source", "Unknown Source")))
    mitre_technique = html.escape(str(triage.get("mitre_technique", "T0000")))
    mitre_tactic = html.escape(str(triage.get("mitre_tactic", "Unknown")))
    summary = html.escape(str(triage.get("summary", "No summary available.")))
    false_positive_note = html.escape(str(triage.get("false_positive_note", "")).strip())
    raw_log = html.escape(str(alert.get("raw_log", "No raw log provided.")))

    playbook = triage.get("playbook", [])
    if not isinstance(playbook, list):
        playbook = []
    cleaned_steps = [html.escape(str(step)) for step in playbook if str(step).strip()]
    while len(cleaned_steps) < 4:
        cleaned_steps.append(html.escape(f"Step {len(cleaned_steps) + 1}: Manual review."))
    steps_html = "".join(f"<li>{step}</li>" for step in cleaned_steps[:4])

    if not false_positive_note:
        false_positive_note = "No explicit false-positive note provided by model."

    st.markdown(
        f"""
<details class="alert-card">
  <summary class="alert-summary">
    <div style="background:{style['accent']}; height: 100%; min-height: 58px;"></div>
    <div class="alert-main">
      <div class="alert-id">{alert_id}</div>
      <div class="alert-type">{alert_type}</div>
      <div class="badge-row">
        <span class="badge" style="background:{style['bg']}; color:{style['text']}; border-color:{style['bg']};">{severity}</span>
        <span class="badge">{source}</span>
        <span class="badge">{mitre_technique} - {mitre_tactic}</span>
      </div>
    </div>
    <div class="chevron">▼</div>
  </summary>
  <div class="card-body">
    <div class="raw-log">{raw_log}</div>
    <div class="two-col">
      <div class="panel">
        <div class="panel-title">AI Assessment</div>
        <div class="panel-content">{summary}</div>
      </div>
      <div class="panel">
        <div class="panel-title">Response Playbook</div>
        <div class="panel-content"><ol>{steps_html}</ol></div>
      </div>
    </div>
    <div class="fp-note">False positive note: {false_positive_note}</div>
  </div>
</details>
        """,
        unsafe_allow_html=True,
    )


def _to_splunk_soar_playbook(items: list[dict[str, Any]]) -> dict[str, Any]:
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    blocks = []

    for item in items:
        alert = item.get("alert", {})
        triage = item.get("triage", {})
        actions = triage.get("playbook", [])
        if not isinstance(actions, list):
            actions = []

        if not actions:
            actions = ["Review alert telemetry and validate impact"]

        for action in actions:
            action_text = str(action).strip() or "Review and investigate"
            blocks.append(
                {
                    "name": action_text,
                    "type": "action",
                    "action": "run query",
                    "parameters": {
                        "alert_id": str(alert.get("alert_id", "UNKNOWN")),
                        "severity": str(triage.get("severity", "INFO")),
                        "mitre_technique": str(triage.get("mitre_technique", "Unknown")),
                        "mitre_tactic": str(triage.get("mitre_tactic", "Unknown")),
                        "note": str(triage.get("summary", "")),
                    },
                }
            )

    return {
        "name": "SOC Triage Export Playbook",
        "description": "Mock Splunk SOAR playbook generated from triaged alerts",
        "created_time": timestamp,
        "platform": "Splunk SOAR",
        "start": "block_1" if blocks else None,
        "blocks": {
            f"block_{idx}": block for idx, block in enumerate(blocks, start=1)
        },
    }


def _soar_preview_payload(soar_payload: dict[str, Any]) -> dict[str, Any]:
    blocks = soar_payload.get("blocks", {})
    first_block = None
    for block_id in sorted(blocks.keys()):
        first_block = blocks[block_id]
        break

    return {
        "format": "Splunk SOAR",
        "playbook_name": soar_payload.get("name"),
        "start_block": soar_payload.get("start"),
        "block_count": len(blocks),
        "first_block": first_block,
    }


def main() -> None:
    st.set_page_config(page_title="SOC Triage Assistant", layout="wide")
    _inject_css()

    if "triage_results" not in st.session_state:
        st.session_state.triage_results = {}

    with st.sidebar:
        st.markdown('<div class="app-title">SOC Triage Assistant</div>', unsafe_allow_html=True)
        st.markdown('<div class="app-subtitle">AI-powered - MITRE ATT&CK</div>', unsafe_allow_html=True)

        uploaded_file = st.file_uploader("Alert JSON", type=["json"])
        use_sample = st.checkbox("Use sample alerts", value=uploaded_file is None)

        api_key = st.text_input("Groq API key", type="password", placeholder="gsk_...")
        run_clicked = st.button("Run AI Triage", type="primary", use_container_width=True)

        clear_clicked = st.button("Clear results", use_container_width=True)
        if clear_clicked:
            st.session_state.triage_results = {}
            st.rerun()

        st.markdown("#### Severity Filter")
        selected = set()
        for sev in SEVERITY_ORDER:
            dot = SEVERITY_STYLE[sev]["accent"]
            c1, c2 = st.columns([1, 7])
            c1.markdown(f'<div style="color:{dot}; font-size: 18px; line-height: 30px;">●</div>', unsafe_allow_html=True)
            checked = c2.checkbox(sev, value=True, key=f"filter_{sev}")
            if checked:
                selected.add(sev)

        st.markdown("#### SOAR Export")
        export_soar = st.toggle("Export as Splunk SOAR playbook", value=False)

    alerts: list[dict[str, Any]] = []
    source_name = "sample_alerts.json"

    if uploaded_file is not None:
        try:
            alerts = _load_alerts_from_text(uploaded_file.getvalue().decode("utf-8"))
            source_name = uploaded_file.name or "uploaded.json"
        except Exception as exc:
            st.error(f"Failed to parse uploaded JSON: {exc}")
            return
    elif use_sample:
        try:
            alerts = _load_sample_alerts()
            source_name = "sample_alerts.json"
        except Exception as exc:
            st.error(f"Failed to load sample alerts: {exc}")
            return

    with st.sidebar:
        st.markdown(
            f'<div class="source-box"><div><strong>Data source</strong></div><div>{html.escape(source_name)}</div><div>{len(alerts)} alerts</div></div>',
            unsafe_allow_html=True,
        )

    if not alerts:
        st.info("Upload a JSON file or enable sample alerts to start triage.")
        return

    header_left, header_right = st.columns([3, 2])
    with header_left:
        st.markdown("## Alert triage dashboard")
    with header_right:
        st.markdown(f"**Date range:** {_time_range_text(alerts)}")

    if run_clicked:
        if not api_key.strip():
            st.error("Provide Groq API key in sidebar before running triage.")
        else:
            progress = st.progress(0.0)
            status = st.empty()
            total = len(alerts)

            try:
                engine = _ensure_llm_engine(api_key)
            except Exception as exc:
                st.error(f"Failed to initialize llm_engine: {exc}")
                return

            for idx, alert in enumerate(alerts, start=1):
                alert_id = _safe_alert_id(alert, idx)
                status.write(f"Triaging {idx}/{total}: {alert_id}")
                if alert_id not in st.session_state.triage_results:
                    raw_output = engine.analyze_with_llm(alert)
                    st.session_state.triage_results[alert_id] = _map_engine_output_to_ui(raw_output)
                progress.progress(idx / total)

            status.empty()
            progress.empty()

    results: list[dict[str, Any]] = []
    for idx, alert in enumerate(alerts, start=1):
        alert_id = _safe_alert_id(alert, idx)
        triage = st.session_state.triage_results.get(alert_id)
        if triage is None:
            continue
        results.append({"alert": alert, "triage": triage})

    severity_counts = {sev: 0 for sev in SEVERITY_ORDER}
    for item in results:
        sev = _normalize_severity(item["triage"].get("severity"))
        severity_counts[sev] += 1

    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        _render_metric_card("Total", len(results))
    with m2:
        _render_metric_card("Critical", severity_counts["CRITICAL"], "CRITICAL")
    with m3:
        _render_metric_card("High", severity_counts["HIGH"], "HIGH")
    with m4:
        _render_metric_card("Medium", severity_counts["MEDIUM"], "MEDIUM")
    with m5:
        _render_metric_card("Low", severity_counts["LOW"], "LOW")

    filtered = [
        item
        for item in results
        if _normalize_severity(item["triage"].get("severity")) in selected
    ]

    st.markdown("### Alert cards")
    st.markdown('<div class="alerts-scroll">', unsafe_allow_html=True)
    if not filtered:
        st.info("No triaged alerts match the active severity filter.")
    else:
        for item in filtered:
            _render_alert_card(item["alert"], item["triage"])
    st.markdown("</div>", unsafe_allow_html=True)

    export_payload = json.dumps(filtered, indent=2)
    st.download_button(
        "Download filtered triage JSON",
        data=export_payload,
        file_name="triage_results.json",
        mime="application/json",
    )

    if export_soar:
        soar_payload = _to_splunk_soar_playbook(filtered)
        soar_file_name = "splunk_soar_playbook_export.json"

        st.markdown("### SOAR payload preview")
        st.caption("Preview of generated Splunk SOAR playbook metadata and first execution step.")
        preview_payload = _soar_preview_payload(soar_payload)
        st.code(json.dumps(preview_payload, indent=2), language="json")

        st.download_button(
            "Download Splunk SOAR playbook JSON",
            data=json.dumps(soar_payload, indent=2),
            file_name=soar_file_name,
            mime="application/json",
        )


if __name__ == "__main__":
    main()
