from app.parsers import parse_content

def test_custom_text_parser_normalizes_fields():
    content = b"2026-10-28T10:01:02Z | 203.0.113.10 | admin | LOGIN_FAILED | Invalid password\n"
    result = parse_content("sample.log", content)
    assert result.total_lines == 1
    assert result.malformed_count == 0
    assert result.events[0]["event_type"] == "login_failure"
    assert result.events[0]["username"] == "admin"
    assert result.events[0]["source_ip"] == "203.0.113.10"

def test_json_lines_parser_redacts_secret():
    content = b'{"timestamp":"2026-10-28T10:01:02Z","event_type":"login_failure","username":"admin","message":"password=hunter2"}\n'
    result = parse_content("sample.json", content)
    assert result.events[0]["message"] == "password=[REDACTED]"

def test_malformed_lines_are_counted():
    result = parse_content("sample.log", b"not a supported log line\n2026-10-28T10:01:02Z | 203.0.113.1 | a | LOGIN_FAILED | bad\n")
    assert result.malformed_count == 1
    assert len(result.events) == 1
