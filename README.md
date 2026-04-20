# AI SOC Triage Assistant

## Overview

AI-assisted SOC triage prototype that combines:

- LLM triage generation (Groq)
- deterministic security guardrails
- MITRE ATT&CK mapping checks
- deterministic rule-engine baselines
- optional threat-intel IOC enrichment
- analyst-facing Streamlit dashboard

The project demonstrates safe, structured AI usage for SOC workflows with explicit fallback behavior when model output is invalid.

![SOC Triage Dashboard](Images/App.png)

## Current Workflow

1. Ingest alerts from `sample_alerts.json` or uploaded JSON in the dashboard.
2. Sanitize untrusted text fields before model inference.
3. Enrich public IPv4 IOCs with AbuseIPDB (optional, non-blocking).
4. Generate deterministic rule signals (`severity_floor`, `confidence_floor`, MITRE hints).
5. Invoke Groq LLM for structured triage.
6. Apply rule-based post-processing overrides to enforce baseline safety.
7. Validate final output with guardrails and MITRE mapping.
8. Return a safe fallback output when parse/validation fails.
9. Display filterable alert cards and export outputs in Streamlit.

## Core Output Schema

Each triaged alert includes:

- `alert_id`
- `incident_summary`
- `severity`
- `confidence`
- `mitre_tactic`
- `mitre_technique`
- `reasoning`
- `recommended_actions`
- `escalation_required`
- `false_positive_note`

## Key Implemented Capabilities

- Input sanitization against prompt-injection-like patterns.
- Deterministic output validation and normalization.
- MITRE tactic/technique consistency checks.
- Threat-intel IOC enrichment with AbuseIPDB for public IPs.
- Hybrid triage model: deterministic rules + LLM reasoning.
- Splunk SOAR mock playbook export with in-app preview.
- Batch KPI evaluation runner (`eval_runner.py`).
- Reliability tests covering enrichment and rule behavior.
- Incident support runbook for demo/ops troubleshooting.

## Project Structure

- `app.py`: Streamlit dashboard, triage orchestration, filters, SOAR export.
- `eval_runner.py`: batch KPI metrics (accuracy, fallback, confidence, latency).
- `src/llm_engine.py`: core triage pipeline + environment/client wiring.
- `src/postprocess.py`: model-output parsing and final validation/fallback routing.
- `src/enrichment.py`: IOC extraction and AbuseIPDB enrichment helpers.
- `src/rule_engine.py`: deterministic rule signal generation and override logic.
- `src/guardrails.py`: schema + range + MITRE validation and fallback handling.
- `src/prompt.py`: strict JSON prompt contract.
- `src/config.py`: sanitization and safety constants.
- `mitre_mapping.json`: expected MITRE mappings by alert type.
- `sample_alerts.json`: synthetic alert dataset.
- `expected_outputs.json`: expected labels for evaluation.
- `INCIDENT_SUPPORT_RUNBOOK.md`: operational troubleshooting checklist.

Note: reliability tests are in the workspace-level file `../tests/test_soc_reliability.py`.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment variables

Create `.env` in the project root:

```env
GROQ_API=<your_groq_api_key>
MODEL=llama-openai/gpt-oss-120b

# Optional threat-intel enrichment
ABUSEIPDB_API_KEY=<your_abuseipdb_api_key>
THREAT_INTEL_TIMEOUT_SEC=3
MALICIOUS_SCORE_THRESHOLD=25
```

Threat-intel enrichment behavior:

- Extracts IPv4 candidates from `raw_log`.
- Skips invalid/private/non-public IPs safely.
- Continues triage even when lookup fails or API key is missing.

### 3. Run dashboard

```bash
streamlit run app.py
```

## Evaluation Metrics Runner

Run batch evaluation using `sample_alerts.json` and `expected_outputs.json`:

```bash
python eval_runner.py
```

The runner prints:

- Total/evaluated alerts
- Missing expected labels
- Severity accuracy %
- MITRE technique accuracy %
- Fallback rate %
- Average confidence score
- Average latency per alert (ms)

## Reliability Tests

From workspace root (`SOC Analysis`):

```bash
python tests/test_soc_reliability.py
```

Current coverage includes:

- invalid/private IP handling in enrichment
- non-blocking enrichment lookup failure
- fallback-output detection
- deterministic rule detection
- post-LLM rule override enforcement

## Security and Safety Design

- Treats alert payloads as untrusted input.
- Sanitizes dangerous patterns and control characters.
- Caps field lengths sent to LLM.
- Enforces strict output schema and value constraints.
- Uses deterministic guardrails and safe fallback output.
- Preserves triage availability when external enrichment is unavailable.

