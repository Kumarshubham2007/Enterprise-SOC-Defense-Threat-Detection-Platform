from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from app.core.database import get_db
from app.core.config import settings
from app.models.models import (
    Asset, SecurityEvent, Alert, Incident, FimBaseline, FimFinding,
    DlpFinding, VulnerabilityFinding, DetectionRule, AuditLog, User
)
from app.schemas.schemas import SystemHealthResponse
from app.api.auth import get_current_user

router = APIRouter(tags=["System Health & Dashboard"])

@router.get("/health", response_model=SystemHealthResponse)
def get_system_health(db: Session = Depends(get_db)):
    db_ok = "Healthy"
    try:
        db.execute(func.now())
    except Exception:
        db_ok = "Degraded"

    total_events = db.query(SecurityEvent).count()
    total_alerts = db.query(Alert).count()
    total_incidents = db.query(Incident).count()
    active_rules = db.query(DetectionRule).filter(DetectionRule.is_enabled == True).count()
    active_assets = db.query(Asset).filter(Asset.status == "Active").count()

    last_event = db.query(SecurityEvent).order_by(desc(SecurityEvent.ingested_at)).first()
    last_fim = db.query(FimFinding).order_by(desc(FimFinding.detected_at)).first()
    last_dlp = db.query(DlpFinding).order_by(desc(DlpFinding.scan_time)).first()

    return {
        "backend_status": "Healthy",
        "database_status": db_ok,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "collector_count": 1,
        "active_assets": active_assets,
        "last_ingestion_time": last_event.ingested_at if last_event else None,
        "last_fim_scan_time": last_fim.detected_at if last_fim else None,
        "last_dlp_scan_time": last_dlp.scan_time if last_dlp else None,
        "active_rules_count": active_rules,
        "total_events_stored": total_events,
        "total_alerts_stored": total_alerts,
        "total_incidents_stored": total_incidents,
    }

@router.get("/dashboard/overview")
def get_dashboard_overview(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total_assets = db.query(Asset).count()
    active_assets = db.query(Asset).filter(Asset.status == "Active").count()
    total_events = db.query(SecurityEvent).count()

    # Alerts by severity
    alerts_by_sev = {
        "Critical": db.query(Alert).filter(Alert.severity == "Critical", Alert.status != "Resolved").count(),
        "High": db.query(Alert).filter(Alert.severity == "High", Alert.status != "Resolved").count(),
        "Medium": db.query(Alert).filter(Alert.severity == "Medium", Alert.status != "Resolved").count(),
        "Low": db.query(Alert).filter(Alert.severity == "Low", Alert.status != "Resolved").count(),
    }
    open_alerts_total = sum(alerts_by_sev.values())

    active_incidents = db.query(Incident).filter(Incident.status != "Closed").count()
    fim_violations = db.query(FimFinding).filter(FimFinding.status == "Unreviewed").count()
    dlp_findings = db.query(DlpFinding).count()

    # Vulns by severity
    vulns_by_sev = {
        "Critical": db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "Critical").count(),
        "High": db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "High").count(),
        "Medium": db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "Medium").count(),
        "Low": db.query(VulnerabilityFinding).filter(VulnerabilityFinding.severity == "Low").count(),
    }

    # Recent High/Critical events
    recent_high_events = db.query(SecurityEvent).filter(
        SecurityEvent.severity.in_(["Critical", "High"])
    ).order_by(desc(SecurityEvent.timestamp)).limit(5).all()

    # Recent Audit Activity
    recent_audit = db.query(AuditLog).order_by(desc(AuditLog.id)).limit(5).all()

    # Last ingestion
    last_event = db.query(SecurityEvent).order_by(desc(SecurityEvent.ingested_at)).first()

    return {
        "total_assets": total_assets,
        "active_assets": active_assets,
        "total_events": total_events,
        "open_alerts_total": open_alerts_total,
        "alerts_by_severity": alerts_by_sev,
        "active_incidents": active_incidents,
        "fim_violations": fim_violations,
        "dlp_findings": dlp_findings,
        "vulns_by_severity": vulns_by_sev,
        "last_successful_ingestion": last_event.ingested_at.isoformat() if last_event else None,
        "recent_high_events": [
            {
                "id": e.id,
                "event_id": e.event_id,
                "event_name": e.event_name,
                "hostname": e.hostname,
                "severity": e.severity,
                "category": e.event_category,
                "timestamp": e.timestamp.isoformat(),
                "username": e.username,
            }
            for e in recent_high_events
        ],
        "recent_activity": [
            {
                "id": a.id,
                "actor": a.actor,
                "action": a.action,
                "resource_type": a.resource_type,
                "timestamp": a.timestamp.isoformat(),
            }
            for a in recent_audit
        ],
        "system_status": "Healthy"
    }
