import json
import os
from dotenv import load_dotenv
load_dotenv()  
from groq import Groq
from .guardrails import load_mitre_mapping, validate_llm_output, build_fallback_output
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

def analyze_with_llm(alert: dict):
    original_alert = alert
    sanitized_alert = sanitize_input(alert)
    user_prompt = f"""
Analyze this security alert:

{json.dumps(sanitized_alert, indent=2)}

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

    mitre_mapping = load_mitre_mapping()
    validation = validate_llm_output(parsed, original_alert, mitre_mapping)

    if validation["is_valid"]:
        return validation["normalized_output"]
    else: 
        print(validation["errors"])

    return build_fallback_output(original_alert)