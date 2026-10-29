import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from .redaction import redact

CUSTOM_RE = re.compile(
    r"^\s*(?P<timestamp>[^|]+?)\s*\|\s*(?P<source_ip>[^|]*?)\s*\|\s*"
    r"(?P<username>[^|]*?)\s*\|\s*(?P<event_type>[^|]+?)\s*\|\s*(?P<message>.*)\s*$"
)
EVENT_ALIASES = {
    "login_failed": "login_failure", "login_failure": "login_failure",
    "failed_login": "login_failure", "auth_failure": "login_failure",
    "login_success": "login_success", "successful_login": "login_success",
    "auth_success": "login_success", "access_denied": "access_denied",
    "request": "request", "http_request": "request", "logout": "logout",
}

@dataclass
class ParseResult:
    events: list[dict[str, Any]]
    total_lines: int
    malformed_count: int
    skipped_count: int
    missing_timestamp_count: int
    notes: list[str]

def parse_timestamp(value: Any) -> datetime | None:
    if value is None or str(value).strip() == "":
        return None
    try:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None

def normalize_event(raw: dict[str, Any], line_number: int) -> dict[str, Any]:
    timestamp = parse_timestamp(raw.get("timestamp") or raw.get("time") or raw.get("@timestamp"))
    raw_type = str(raw.get("event_type") or raw.get("event") or raw.get("action") or "").strip().lower()
    status = str(raw.get("status") or "").strip().lower() or None
    status_code = raw.get("status_code", raw.get("http_status", raw.get("statusCode")))
    try:
        status_code = int(status_code) if status_code not in (None, "") else None
    except (ValueError, TypeError):
        status_code = None
    if not raw_type:
        message_lower = str(raw.get("message") or "").lower()
        if "login" in message_lower and any(x in message_lower for x in ("fail", "invalid", "incorrect")):
            raw_type = "login_failure"
        elif "login" in message_lower and any(x in message_lower for x in ("success", "successful")):
            raw_type = "login_success"
        elif status_code in (401, 403):
            raw_type = "access_denied"
        elif status_code is not None:
            raw_type = "request"
    event_type = EVENT_ALIASES.get(raw_type, raw_type if raw_type else "unknown")
    if status_code in (401, 403) and event_type == "request":
        event_type = "access_denied"
    source_ip = raw.get("source_ip") or raw.get("ip") or raw.get("remote_addr") or raw.get("client_ip")
    username = raw.get("username") or raw.get("user") or raw.get("account") or raw.get("principal")
    path = raw.get("path") or raw.get("endpoint") or raw.get("url")
    method = raw.get("http_method") or raw.get("method")
    message = redact(str(raw.get("message") or raw.get("msg") or raw.get("description") or ""))
    if not status:
        if event_type == "login_failure": status = "failure"
        elif event_type == "login_success": status = "success"
        elif event_type == "access_denied": status = "denied"
    return {
        "timestamp": timestamp,
        "event_type": event_type,
        "username": str(username).strip()[:255] if username not in (None, "") else None,
        "source_ip": str(source_ip).strip()[:100] if source_ip not in (None, "") else None,
        "status": status,
        "http_method": str(method).upper()[:16] if method not in (None, "") else None,
        "path": redact(str(path))[:1000] if path not in (None, "") else None,
        "status_code": status_code,
        "message": message,
        "source_line_number": line_number,
    }

def parse_content(filename: str, content: bytes) -> ParseResult:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("File must use UTF-8 encoding.") from exc
    lines = text.splitlines()
    events: list[dict[str, Any]] = []
    malformed = 0
    skipped = 0
    missing_ts = 0
    notes: list[str] = []
    is_jsonl = filename.lower().endswith(".json")
    nonempty = [(i, line) for i, line in enumerate(lines, start=1) if line.strip()]
    for line_number, line in nonempty:
        raw: dict[str, Any] | None = None
        if is_jsonl:
            try:
                parsed = json.loads(line)
                if not isinstance(parsed, dict):
                    malformed += 1
                    continue
                raw = parsed
            except json.JSONDecodeError:
                malformed += 1
                continue
        else:
            match = CUSTOM_RE.match(line)
            if match:
                raw = match.groupdict()
            else:
                # A minimal common key=value parser improves tolerance without pretending to support every format.
                pairs = dict(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)=([^\s]+)", line))
                if pairs and any(k.lower() in {"timestamp", "time", "event", "event_type", "message"} for k in pairs):
                    raw = {k.lower(): v for k, v in pairs.items()}
                else:
                    malformed += 1
                    continue
        event = normalize_event(raw, line_number)
        if event["timestamp"] is None:
            missing_ts += 1
        if event["event_type"] == "unknown":
            skipped += 1
        events.append(event)
    if not nonempty:
        raise ValueError("The file contains no non-empty lines.")
    if not events:
        raise ValueError("No usable log records were found. Check the supported input format.")
    if missing_ts:
        notes.append(f"{missing_ts} parsed event(s) have missing or invalid timestamps; time-window rules may be skipped.")
    if skipped:
        notes.append(f"{skipped} event(s) have unknown event types.")
    ratio = malformed / len(nonempty)
    if ratio > 0.20:
        notes.append(f"Parser quality warning: {ratio:.0%} of non-empty lines were unparsed.")
    return ParseResult(events, len(lines), malformed, skipped, missing_ts, notes)
