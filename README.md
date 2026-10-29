# Log Analyser MVP

A defensive, upload-based application log analysis tool. It parses supported `.log`, `.txt`, and JSON Lines (`.json`) files, normalizes events, runs deterministic rules, shows evidence-backed alerts, stores scan metadata and alerts, and exports CSV.

## MVP scope

- FastAPI backend; React + Vite + Tailwind-style CSS frontend (plain CSS for a dependency-light, easy-to-run MVP).
- PostgreSQL with SQLAlchemy in Docker; SQLite by default for quick local testing.
- Supported inputs:
  - JSON Lines: one JSON object per line, using fields such as `timestamp`, `event_type`, `username`, `source_ip`, `status`, `status_code`, `method`/`http_method`, `path`, `message`.
  - A documented custom text format: `TIMESTAMP | IP | USERNAME | EVENT_TYPE | MESSAGE`
    - Example: `2026-10-28T10:01:02Z | 203.0.113.10 | admin | LOGIN_FAILED | Invalid password`
- Detection rules: AUTH-001, AUTH-002, AUTH-003, AUTH-004, ACCESS-001, TRAFFIC-001, DATA-001.
- Scan history, alert filters, alert detail/evidence, CSV export, scan deletion.
- Raw upload bytes are processed in memory and are not persisted as files. Sensitive-looking values are redacted before storage/display/export.
- No accounts, live monitoring, blocking, AI, or external LLM calls in this MVP.

## Requirements

- Python 3.11+
- Node.js 20+
- Optional: Docker + Docker Compose (recommended for PostgreSQL mode)

## Quick start (no Docker; SQLite)

### 1. Backend

Windows PowerShell:

```powershell
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

macOS/Linux:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload
```

Backend: http://127.0.0.1:8000  
Swagger API docs: http://127.0.0.1:8000/docs  
Health check: http://127.0.0.1:8000/api/health

### 2. Frontend

Open a second terminal:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

### 3. Run tests

From the project root:

```bash
cd backend
python -m pytest -q
```

## PostgreSQL mode with Docker

From the project root:

```bash
docker compose up --build
```

Then open http://localhost:5173. The API is available at http://localhost:8000. Compose sets `DATABASE_URL` to PostgreSQL and persists database data in a Docker volume.

To stop:

```bash
docker compose down
```

To stop and remove the database volume as well:

```bash
docker compose down -v
```

## Sample files

Use `samples/authentication_burst.log` or `samples/mixed_events.json`. The sample data is synthetic and uses documentation-only IP addresses.

## Detection rules and limitations

Thresholds are demo defaults and configurable in `backend/app/config.py`:

- `AUTH-001`: at least 10 failed logins from one source IP in 5 minutes; High at 25.
- `AUTH-002`: at least 8 failed logins for one username in 5 minutes; High at 20.
- `AUTH-003`: at least 5 failures followed by success for the same username within 10 minutes.
- `AUTH-004`: at least 10 distinct usernames with failures from one IP in 10 minutes.
- `ACCESS-001`: at least 20 access-denied events from one IP in 5 minutes.
- `TRAFFIC-001`: at least 100 requests from one IP in 1 minute.
- `DATA-001`: more than 20% of non-empty lines are unparsed.

Alerts indicate patterns that deserve human review; they do not prove compromise. Time-window rules require usable timestamps. Identity-based rules require the relevant username/IP. Timezone-naive timestamps are interpreted as UTC for this MVP; in production, ambiguous timezone assumptions should be surfaced and configurable. The MVP is designed for small uploads and synchronous analysis, with a 10 MB default upload limit.

## API overview

- `GET /api/health`
- `POST /api/scans` (multipart field: `file`)
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/alerts?severity=High&rule_id=AUTH-001&username=admin&source_ip=203.0.113.10`
- `GET /api/scans/{scan_id}/alerts/{alert_id}`
- `GET /api/scans/{scan_id}/export?format=csv`
- `DELETE /api/scans/{scan_id}`

## Security notes

- The backend validates extension, size, empty content and UTF-8 decoding; it does not trust frontend validation.
- Uploaded content is never executed.
- Evidence is redacted before persistence/display/export and rendered as text in the frontend.
- Raw uploaded files are not written to disk by this MVP.
- This is a local/demo MVP, not a hardened public multi-tenant service. Before public deployment, add authentication/authorization, rate limits, request-level resource controls, production CORS configuration, structured audit logging, and a deployment threat model.
