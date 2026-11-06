import csv
import io
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import SecurityEvent, User
from app.schemas.schemas import EventCreate, BatchEventCreate, EventResponse, AlertResponse
from app.detection.engine import ingest_single_event
from app.api.auth import get_current_user

router = APIRouter(prefix="/events", tags=["Security Events"])

@router.post("", response_model=Dict[str, Any])
def ingest_event(
    event_in: EventCreate,
    db: Session = Depends(get_db)
):
    event, alerts = ingest_single_event(db, event_in)
    return {
        "status": "ingested",
        "event_id": event.event_id,
        "alerts_triggered_count": len(alerts),
        "alerts": [AlertResponse.from_orm(a) for a in alerts]
    }

@router.post("/batch", response_model=Dict[str, Any])
def ingest_batch_events(
    batch: BatchEventCreate,
    db: Session = Depends(get_db)
):
    results = []
    total_alerts = 0
    for evt in batch.events:
        try:
            event, alerts = ingest_single_event(db, evt)
            total_alerts += len(alerts)
            results.append({"event_id": event.event_id, "status": "success", "alerts": len(alerts)})
        except Exception as e:
            results.append({"status": "error", "message": str(e)})

    return {
        "total_submitted": len(batch.events),
        "processed": len(results),
        "total_alerts_generated": total_alerts,
        "details": results
    }

@router.get("", response_model=Dict[str, Any])
def list_events(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    hostname: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    username: Optional[str] = None,
    source: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = db.query(SecurityEvent)

    if hostname:
        query = query.filter(SecurityEvent.hostname.ilike(f"%{hostname}%"))
    if category:
        query = query.filter(SecurityEvent.event_category == category)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if username:
        query = query.filter(SecurityEvent.username.ilike(f"%{username}%"))
    if source:
        query = query.filter(SecurityEvent.source == source)
    if search:
        query = query.filter(
            (SecurityEvent.event_name.ilike(f"%{search}%")) |
            (SecurityEvent.details.ilike(f"%{search}%")) |
            (SecurityEvent.source_ip.ilike(f"%{search}%"))
        )

    total = query.count()
    events = query.order_by(desc(SecurityEvent.timestamp)).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [EventResponse.from_orm(e) for e in events]
    }

@router.get("/{event_id}", response_model=EventResponse)
def get_event_details(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    event = db.query(SecurityEvent).filter(SecurityEvent.event_id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail=f"Event {event_id} not found.")
    return event

@router.post("/upload-csv", response_model=Dict[str, Any])
async def upload_csv_events(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are supported.")

    content = await file.read()
    decoded = content.decode("utf-8", errors="replace")
    reader = csv.DictReader(io.StringIO(decoded))

    ingested_count = 0
    alerts_count = 0
    errors = []

    for idx, row in enumerate(reader):
        try:
            evt_in = EventCreate(
                hostname=row.get("hostname", "unknown-host"),
                event_category=row.get("event_category", "System"),
                severity=row.get("severity", "Info"),
                event_name=row.get("event_name", "CSV Imported Event"),
                username=row.get("username"),
                process_name=row.get("process_name"),
                source_ip=row.get("source_ip"),
                destination_ip=row.get("destination_ip"),
                source="csv_import",
                details={k: v for k, v in row.items() if k not in ["hostname", "event_category", "severity", "event_name", "username", "source_ip", "destination_ip"]}
            )
            _, alerts = ingest_single_event(db, evt_in)
            ingested_count += 1
            alerts_count += len(alerts)
        except Exception as e:
            errors.append(f"Row {idx+1}: {str(e)}")

    return {
        "status": "completed",
        "ingested_count": ingested_count,
        "alerts_generated": alerts_count,
        "errors_sample": errors[:5]
    }
