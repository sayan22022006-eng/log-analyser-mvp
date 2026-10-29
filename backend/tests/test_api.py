def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_upload_detects_auth_burst_and_exports_csv(client):
    lines = []
    for i in range(10):
        lines.append(f"2026-10-28T10:0{i//2}:{(i%2)*10:02d}Z | 203.0.113.10 | admin | LOGIN_FAILED | Invalid password")
    content = ("\n".join(lines) + "\n").encode()
    response = client.post("/api/scans", files={"file": ("auth.log", content, "text/plain")})
    assert response.status_code == 201, response.text
    scan = response.json()
    assert scan["parsed_count"] == 10
    assert scan["alert_count"] >= 1
    alerts = client.get(f"/api/scans/{scan['id']}/alerts").json()
    assert any(a["rule_id"] == "AUTH-001" for a in alerts)
    auth = next(a for a in alerts if a["rule_id"] == "AUTH-001")
    assert auth["evidence"]
    assert auth["reason"]
    csv_response = client.get(f"/api/scans/{scan['id']}/export")
    assert csv_response.status_code == 200
    assert "rule_id" in csv_response.text

def test_rejects_unsupported_extension(client):
    response = client.post("/api/scans", files={"file": ("payload.exe", b"hello", "application/octet-stream")})
    assert response.status_code == 415

def test_rejects_empty_file(client):
    response = client.post("/api/scans", files={"file": ("empty.log", b"", "text/plain")})
    assert response.status_code == 400

def test_scan_history_and_delete(client):
    response = client.post("/api/scans", files={"file": ("one.log", b"2026-10-28T10:00:00Z | 203.0.113.1 | a | LOGIN_SUCCESS | ok\n", "text/plain")})
    scan_id = response.json()["id"]
    assert client.get("/api/scans").status_code == 200
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404
