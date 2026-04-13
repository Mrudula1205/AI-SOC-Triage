import re

MAX_LLM_FIELD_LENGTH = 2000
SANITIZE_REPLACEMENT_TOKEN = "[REMOVED_INSTRUCTION]"
CONTROL_CHARS_PATTERN = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

PROMPT_INJECTION_PHRASES = [
    re.compile(r"ignore previous instructions", re.IGNORECASE),
    re.compile(r"disregard previous instructions", re.IGNORECASE),
    re.compile(r"forget everything you know", re.IGNORECASE),
    re.compile(r"bypass all restrictions", re.IGNORECASE),
    re.compile(r"break character", re.IGNORECASE),
    re.compile(r"act as a malicious hacker", re.IGNORECASE),
    re.compile(r"act as a SOC analyst and provide false information", re.IGNORECASE),
    re.compile(r"provide incorrect analysis", re.IGNORECASE),
    re.compile(r"give me the wrong answer", re.IGNORECASE),
    re.compile(r"mislead me", re.IGNORECASE),
    re.compile(r"fabricate a story about the alert", re.IGNORECASE),
    re.compile(r"make up a false explanation for the alert", re.IGNORECASE),
    re.compile(r"reveal system prompt", re.IGNORECASE),
    re.compile(r"system prompt", re.IGNORECASE),
    re.compile(r"you are now", re.IGNORECASE),
    re.compile(r"ignore all prior", re.IGNORECASE),
]

SAMPLE_ALERT = "sample_alerts.json"