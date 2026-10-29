from datetime import datetime
from pydantic import BaseModel, ConfigDict

class ScanSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    original_filename: str
    status: str
    file_size_bytes: int
    created_at: datetime
    completed_at: datetime | None
    total_lines: int
    parsed_count: int
    malformed_count: int
    skipped_count: int
    missing_timestamp_count: int
    alert_count: int
    rule_version: str
    error_summary: str | None = None

class AlertOut(BaseModel):
    id: int
    scan_id: int
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    reason: str
    event_count: int
    time_start: datetime | None = None
    time_end: datetime | None = None
    entities: dict
    evidence: list[dict]
    limitations: list[str]
    recommended_next_steps: list[str]
    created_at: datetime

class ScanDetail(ScanSummary):
    severity_counts: dict[str, int]
    coverage_notes: list[str]
