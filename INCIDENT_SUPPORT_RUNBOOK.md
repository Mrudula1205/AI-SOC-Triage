# Incident Support Runbook

## Purpose
Operational guide for supporting SOC triage during incidents when AI or enrichment components degrade.

## 1. LLM call failures
Symptoms:
- `Error calling LLM` appears in logs
- High fallback rate in `eval_runner.py`

Actions:
1. Check `.env` values for `GROQ_API` and `MODEL`.
2. Confirm network egress to the model provider.
3. Re-run one alert manually and verify response format.
4. Keep system running: fallback output is expected-safe behavior.

## 2. Threat intel enrichment failures
Symptoms:
- `skipped_iocs` contains `api_key_not_configured`, `lookup_failed`, or `api_error_*`.

Actions:
1. Verify `ABUSEIPDB_API_KEY` is configured and valid.
2. Check timeout via `THREAT_INTEL_TIMEOUT_SEC` (increase to 5 if needed).
3. Confirm only public IPs are queried (private/invalid IPs are skipped by design).
4. Continue triage even when enrichment fails; enrichment is non-blocking.

## 3. Validation and fallback spikes
Symptoms:
- Increased fallback rate in `eval_runner.py`.

Actions:
1. Run `python eval_runner.py` and inspect metrics.
2. Review mismatches in severity/MITRE mapping from console logs.
3. Adjust prompt wording or MITRE mapping entries as needed.
4. Re-run evaluation and compare fallback + accuracy deltas.

## 4. SOAR export checks (Splunk SOAR mock)
Symptoms:
- Exported playbook missing blocks or fields.

Actions:
1. Ensure triage results exist for selected alerts.
2. Toggle `Export as Splunk SOAR playbook` and verify preview panel.
3. Download JSON and confirm `start`, `blocks`, and alert metadata fields.

## 5. Reliability checkpoints before demo
1. `python -m py_compile app.py`
2. `python eval_runner.py`
3. Validate KPI outputs: fallback rate, MITRE accuracy, latency.
4. Export one Splunk SOAR playbook JSON and verify first block.
