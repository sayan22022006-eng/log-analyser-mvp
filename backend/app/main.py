import csv
import io
import json
import os
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
from .config import CORS_ORIGINS, MAX_UPLOAD_BYTES
from .db import Base, engine, get_db
from .models import Alert, Scan
from .schemas import AlertOut, ScanDetail, ScanSummary
from .parsers import parse_content
from .detection import detect, RULE_VERSION

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Log Analyser API", version="1.0.0", description="Defensive, evidence-backed application log analysis MVP.")
app.add_middleware(CORSMiddleware, allow_origins=CORS_ORIGINS, allow_credentials=False, allow_methods=["GET", "POST", "DELETE"], allow_headers=["*"])

def as_alert(alert: Alert) -> dict:
    return {
        "id": alert.id, "scan_id": alert.scan_id, "rule_id": alert.rule_id,
        "rule_name": alert.rule_name, "severity": alert.severity, "title": alert.title,
        "description": alert.description, "reason": alert.reason, "event_count": alert.event_count,
        "time_start": alert.time_start, "time_end": alert.time_end,
        "entities": json.loads(alert.entities_json or "{}"),
        "evidence": json.loads(alert.evidence_json or "[]"),
        "limitations": json.loads(alert.limitations_json or "[]"),
        "recommended_next_steps": json.loads(alert.next_steps_json or "[]"),
        "created_at": alert.created_at,
    }

def get_scan_or_404(scan_id: int, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan

@app.get("/api/health")
def health():
    return {"status": "ok", "service": "log-analyser-api", "version": "1.0.0"}

@app.get("/api/dashboard")
def get_dashboard(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(desc(Scan.created_at)).all()
    alerts = db.query(Alert).all()

    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }

    for alert in alerts:
        if alert.severity in severity_counts:
            severity_counts[alert.severity] += 1

    return {
        "total_scans": len(scans),
        "total_events": sum(scan.parsed_count for scan in scans),
        "total_alerts": len(alerts),
        "high_alerts": severity_counts["High"],
        "medium_alerts": severity_counts["Medium"],
        "low_alerts": severity_counts["Low"],
        "malformed_events": sum(
            scan.malformed_count for scan in scans
        ),
        "skipped_events": sum(
            scan.skipped_count for scan in scans
        ),
        "recent_scans": [
            ScanSummary.model_validate(scan).model_dump(mode="json")
            for scan in scans[:5]
        ],
    }

@app.post("/api/scans", response_model=ScanDetail, status_code=201)
async def create_scan(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = (file.filename or "uploaded.log").replace("\\", "/").split("/")[-1]
    ext = os.path.splitext(filename)[1].lower()
    if ext not in {".log", ".txt", ".json"}:
        raise HTTPException(status_code=415, detail="Unsupported file type. Upload .log, .txt, or JSON Lines .json.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)} MB upload limit.")
    if not content:
        raise HTTPException(status_code=400, detail="The uploaded file is empty.")
    try:
        parsed = parse_content(filename, content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    now = datetime.now(timezone.utc)
    scan = Scan(
        original_filename=filename[:255], status="completed", file_size_bytes=len(content),
        created_at=now, completed_at=now, total_lines=parsed.total_lines,
        parsed_count=len(parsed.events), malformed_count=parsed.malformed_count,
        skipped_count=parsed.skipped_count, missing_timestamp_count=parsed.missing_timestamp_count,
        rule_version=RULE_VERSION,
    )
    db.add(scan)
    db.flush()
    findings = detect(parsed.events, parsed.malformed_count, parsed.total_lines)
    for item in findings:
        alert = Alert(
            scan_id=scan.id, rule_id=item["rule_id"], rule_name=item["rule_name"],
            severity=item["severity"], title=item["title"], description=item["description"],
            reason=item["reason"], event_count=item["event_count"],
            time_start=datetime.fromisoformat(item["time_start"]) if item["time_start"] else None,
            time_end=datetime.fromisoformat(item["time_end"]) if item["time_end"] else None,
            entities_json=json.dumps(item["entities"]), evidence_json=json.dumps(item["evidence"]),
            limitations_json=json.dumps(item["limitations"]), next_steps_json=json.dumps(item["recommended_next_steps"]),
        )
        db.add(alert)
    scan.alert_count = len(findings)
    db.commit()
    db.refresh(scan)
    counts = {s: sum(1 for a in findings if a["severity"] == s) for s in ("High", "Medium", "Low")}
    notes = list(parsed.notes)
    if parsed.missing_timestamp_count:
        notes.append("Time-window rules only consider events with usable timestamps.")
    if not any(e.get("source_ip") for e in parsed.events):
        notes.append("No source IP fields were recognized; IP-based rules may not trigger.")
    return {
        **ScanSummary.model_validate(scan).model_dump(),
        "severity_counts": counts,
        "coverage_notes": notes,
    }

@app.get("/api/scans", response_model=list[ScanSummary])
def list_scans(limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db)):
    return db.query(Scan).order_by(desc(Scan.created_at)).limit(limit).all()

@app.get("/api/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan_or_404(scan_id, db)
    alerts = db.query(Alert).filter(Alert.scan_id == scan_id).all()
    counts = {s: sum(1 for a in alerts if a.severity == s) for s in ("High", "Medium", "Low")}
    notes = []
    if scan.missing_timestamp_count: notes.append("Some events lacked usable timestamps; time-window coverage is reduced.")
    if scan.malformed_count: notes.append(f"{scan.malformed_count} line(s) were malformed or unparsed.")
    if scan.skipped_count: notes.append(f"{scan.skipped_count} event(s) had unknown event types.")
    return {**ScanSummary.model_validate(scan).model_dump(), "severity_counts": counts, "coverage_notes": notes}

@app.get("/api/scans/{scan_id}/alerts", response_model=list[AlertOut])
def list_alerts(
    scan_id: int, severity: str | None = None, rule_id: str | None = None,
    username: str | None = None, source_ip: str | None = None,
    db: Session = Depends(get_db)
):
    get_scan_or_404(scan_id, db)
    query = db.query(Alert).filter(Alert.scan_id == scan_id)
    if severity:
        if severity not in {"High", "Medium", "Low"}:
            raise HTTPException(status_code=400, detail="severity must be High, Medium, or Low.")
        query = query.filter(Alert.severity == severity)
    if rule_id: query = query.filter(Alert.rule_id == rule_id)
    alerts = query.order_by(desc(Alert.id)).all()
    output = []
    for alert in alerts:
        item = as_alert(alert)
        entities = item["entities"]
        if username and username.casefold() not in str(entities.get("username", "")).casefold(): continue
        if source_ip and source_ip not in str(entities.get("source_ip", "")): continue
        output.append(item)
    return output

@app.get("/api/scans/{scan_id}/alerts/{alert_id}", response_model=AlertOut)
def get_alert(scan_id: int, alert_id: int, db: Session = Depends(get_db)):
    get_scan_or_404(scan_id, db)
    alert = db.query(Alert).filter(Alert.scan_id == scan_id, Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found for this scan.")
    return as_alert(alert)

@app.get("/api/scans/{scan_id}/export")
def export_scan(scan_id: int, format: str = "csv", db: Session = Depends(get_db)):
    if format.lower() != "csv":
        raise HTTPException(status_code=400, detail="Only CSV export is implemented in the MVP.")
    scan = get_scan_or_404(scan_id, db)
    alerts = db.query(Alert).filter(Alert.scan_id == scan_id).order_by(Alert.id).all()
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["scan_id", "filename", "scan_status", "created_at", "rule_version", "alert_id", "rule_id", "severity", "title", "reason", "event_count", "time_start", "time_end", "entities", "evidence_line_numbers", "limitations", "recommended_next_steps"])
    for a in alerts:
        evidence = json.loads(a.evidence_json or "[]")
        writer.writerow([scan.id, scan.original_filename, scan.status, scan.created_at.isoformat(), scan.rule_version,
            a.id, a.rule_id, a.severity, a.title, a.reason, a.event_count,
            a.time_start.isoformat() if a.time_start else "", a.time_end.isoformat() if a.time_end else "",
            a.entities_json, ";".join(str(e.get("source_line_number")) for e in evidence),
            a.limitations_json, a.next_steps_json])
    buffer.seek(0)
    safe_name = f"log-analyser-scan-{scan_id}.csv"
    return StreamingResponse(iter([buffer.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'})

@app.delete("/api/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = get_scan_or_404(scan_id, db)
    db.delete(scan)
    db.commit()
    return None
