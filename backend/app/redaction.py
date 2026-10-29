import re

PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\b(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|session(?:id|_id)?|cookie)\b\s*[:=]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(set-cookie\s*:\s*)[^;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([?&](?:token|password|api_key|secret)=)[^&\s]+"), r"\1[REDACTED]"),
]

def redact(value: str | None) -> str:
    if value is None:
        return ""
    result = str(value)
    for pattern, replacement in PATTERNS:
        result = pattern.sub(replacement, result)
    return result[:4000]
