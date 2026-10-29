from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from .config import RULE_THRESHOLDS as T

RULE_VERSION = "1.0.0"

def _dt(event):
    value = event.get("timestamp")
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    return None

def _in_window(events, seconds, predicate):
    usable = [e for e in events if _dt(e) is not None and predicate(e)]
    usable.sort(key=lambda e: (_dt(e), e["source_line_number"]))
    result = []
    left = 0
    for right, event in enumerate(usable):
        while _dt(event) - _dt(usable[left]) > timedelta(seconds=seconds):
            left += 1
        window = usable[left:right+1]
        result.append((event, window))
    return result

def _alert(rule_id, rule_name, severity, title, description, reason, events, entities, limitations=None, next_steps=None):
    events = sorted(events, key=lambda e: ( _dt(e) or datetime.min.replace(tzinfo=timezone.utc), e["source_line_number"]))
    times = [_dt(e) for e in events if _dt(e)]
    evidence = [{
        "source_line_number": e["source_line_number"],
        "timestamp": _dt(e).isoformat().replace("+00:00", "Z") if _dt(e) else None,
        "event_type": e["event_type"],
        "username": e.get("username"),
        "source_ip": e.get("source_ip"),
        "message": e.get("message", "")[:500],
    } for e in events[:20]]
    return {
        "rule_id": rule_id, "rule_name": rule_name, "severity": severity, "title": title,
        "description": description, "reason": reason, "event_count": len(events),
        "time_start": min(times).isoformat() if times else None,
        "time_end": max(times).isoformat() if times else None,
        "entities": entities, "evidence": evidence,
        "limitations": limitations or ["This alert identifies a pattern that warrants review; it does not prove compromise."],
        "recommended_next_steps": next_steps or ["Review the evidence and correlate with application, identity-provider, and change-management records."]
    }

def detect(events: list[dict[str, Any]], malformed_count: int, total_lines: int) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    failures = [e for e in events if e["event_type"] == "login_failure"]
    successes = [e for e in events if e["event_type"] == "login_success"]
    denials = [e for e in events if e["event_type"] == "access_denied" or e.get("status_code") in (401, 403)]
    requests = [e for e in events if e["event_type"] in ("request", "access_denied")]

    # AUTH-001: repeated failures grouped by source IP.
    by_ip = defaultdict(list)
    for e in failures:
        if e.get("source_ip") and _dt(e): by_ip[e["source_ip"]].append(e)
    for ip, group in by_ip.items():
        windows = _in_window(group, T["AUTH_001_WINDOW_SECONDS"], lambda e: e.get("source_ip") == ip)
        if windows:
            _, window = max(windows, key=lambda pair: len(pair[1]))
            count = len(window)
            if count >= T["AUTH_001_MEDIUM"]:
                severity = "High" if count >= T["AUTH_001_HIGH"] else "Medium"
                alerts.append(_alert("AUTH-001", "Repeated login failures from one IP", severity,
                    "Repeated authentication failures from one source IP",
                    "Multiple failed login events from the same source IP occurred in a short time window.",
                    f"Observed {count} failed logins in {T['AUTH_001_WINDOW_SECONDS']//60} minutes; Medium threshold is {T['AUTH_001_MEDIUM']} and High threshold is {T['AUTH_001_HIGH']}.",
                    window, {"source_ip": ip}, ["Shared NAT, user error, automated tests, or identity-provider retries can produce this pattern."]))

    # AUTH-002: repeated failures for one account.
    by_user = defaultdict(list)
    for e in failures:
        if e.get("username") and _dt(e): by_user[e["username"].casefold()].append(e)
    for user_key, group in by_user.items():
        windows = _in_window(group, T["AUTH_002_WINDOW_SECONDS"], lambda e: (e.get("username") or "").casefold() == user_key)
        if windows:
            _, window = max(windows, key=lambda pair: len(pair[1]))
            count = len(window)
            if count >= T["AUTH_002_MEDIUM"]:
                severity = "High" if count >= T["AUTH_002_HIGH"] else "Medium"
                alerts.append(_alert("AUTH-002", "Repeated login failures against one account", severity,
                    "Repeated authentication failures for one account",
                    "A single account received multiple failed login attempts within the configured time window.",
                    f"Observed {count} failures for account '{group[0].get('username')}' in {T['AUTH_002_WINDOW_SECONDS']//60} minutes; threshold is {T['AUTH_002_MEDIUM']}; High threshold is {T['AUTH_002_HIGH']}.",
                    window, {"username": group[0].get("username")}, ["Account names may be normalized differently by different applications."]))

    # AUTH-003: at least N failures followed by success for same username.
    for user_key, group in by_user.items():
        user_successes = [e for e in successes if e.get("username") and e["username"].casefold() == user_key and _dt(e)]
        for success in sorted(user_successes, key=lambda e: _dt(e)):
            prior = [e for e in group if _dt(e) < _dt(success) and _dt(success) - _dt(e) <= timedelta(seconds=T["AUTH_003_WINDOW_SECONDS"])]
            if len(prior) >= T["AUTH_003_MIN_FAILURES"]:
                matched = prior + [success]
                alerts.append(_alert("AUTH-003", "Failures followed by successful login", "High",
                    "Login success followed a burst of failures",
                    "Several failed attempts for the same account were followed by a successful login.",
                    f"Observed {len(prior)} failure(s) followed by success within {T['AUTH_003_WINDOW_SECONDS']//60} minutes.",
                    matched, {"username": success.get("username"), "source_ip": success.get("source_ip")},
                    ["The successful login may be legitimate; correlate with MFA, device, location and session evidence."]))
                break

    # AUTH-004: one IP failing against many accounts.
    by_ip_all = defaultdict(list)
    for e in failures:
        if e.get("source_ip") and e.get("username") and _dt(e): by_ip_all[e["source_ip"]].append(e)
    for ip, group in by_ip_all.items():
        for end, window in _in_window(group, T["AUTH_004_WINDOW_SECONDS"], lambda e: e.get("source_ip") == ip):
            users = {e["username"].casefold() for e in window if e.get("username")}
            if len(users) >= T["AUTH_004_MIN_USERNAMES"]:
                alerts.append(_alert("AUTH-004", "One IP targeting many accounts", "High",
                    "Authentication failures across many accounts",
                    "One source IP generated failed login events for many distinct usernames.",
                    f"Observed {len(users)} distinct usernames in {T['AUTH_004_WINDOW_SECONDS']//60} minutes; threshold is {T['AUTH_004_MIN_USERNAMES']}.",
                    window, {"source_ip": ip, "distinct_usernames": len(users)},
                    ["Authorized scanners and identity-provider behavior can create similar patterns."]))
                break

    # ACCESS-001: repeated access denials from one IP.
    denied_by_ip = defaultdict(list)
    for e in denials:
        if e.get("source_ip") and _dt(e): denied_by_ip[e["source_ip"]].append(e)
    for ip, group in denied_by_ip.items():
        for end, window in _in_window(group, T["ACCESS_001_WINDOW_SECONDS"], lambda e: e.get("source_ip") == ip):
            if len(window) >= T["ACCESS_001_MEDIUM"]:
                alerts.append(_alert("ACCESS-001", "Repeated access denials", "Medium",
                    "Repeated access denials from one source IP",
                    "Multiple HTTP 401/403 or access-denied events came from the same IP.",
                    f"Observed {len(window)} denials in {T['ACCESS_001_WINDOW_SECONDS']//60} minutes; threshold is {T['ACCESS_001_MEDIUM']}.",
                    window, {"source_ip": ip}, ["HTTP 401/403 responses are context-dependent and are not inherently malicious."]))
                break

    # TRAFFIC-001: request burst from one IP.
    req_by_ip = defaultdict(list)
    for e in requests:
        if e.get("source_ip") and _dt(e): req_by_ip[e["source_ip"]].append(e)
    for ip, group in req_by_ip.items():
        for end, window in _in_window(group, T["TRAFFIC_001_WINDOW_SECONDS"], lambda e: e.get("source_ip") == ip):
            if len(window) >= T["TRAFFIC_001_MEDIUM"]:
                alerts.append(_alert("TRAFFIC-001", "Request burst from one IP", "Medium",
                    "High request volume from one source IP",
                    "A large number of request-level events occurred in a short window.",
                    f"Observed {len(window)} requests in {T['TRAFFIC_001_WINDOW_SECONDS']} seconds; threshold is {T['TRAFFIC_001_MEDIUM']}.",
                    window, {"source_ip": ip}, ["Only meaningful when the input contains a sufficiently complete request-level log."]))
                break

    nonempty = max(total_lines, 1)
    ratio = malformed_count / nonempty
    if ratio > T["DATA_001_UNPARSED_RATIO"]:
        alerts.append(_alert("DATA-001", "Parser quality warning", "Low",
            "A significant portion of log lines could not be parsed",
            "The input may not match a supported format or may contain malformed records.",
            f"{malformed_count} lines were unparsed out of {total_lines} total lines ({ratio:.1%}); warning threshold is greater than {T['DATA_001_UNPARSED_RATIO']:.0%}.",
            [], {"malformed_count": malformed_count, "total_lines": total_lines},
            ["Parser quality warnings describe data coverage, not necessarily a security event."]))
    # Correlate duplicate alerts generated at multiple sliding-window endpoints by rule and entity.
    deduped = []
    seen = set()
    for a in alerts:
        key = (a["rule_id"], tuple(sorted((k, str(v)) for k, v in a["entities"].items())))
        if key not in seen:
            seen.add(key)
            deduped.append(a)
    return deduped
