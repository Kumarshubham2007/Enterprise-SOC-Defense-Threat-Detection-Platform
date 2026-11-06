from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import Alert, DetectionRule, User
from app.schemas.schemas import AlertResponse, AlertUpdate, DetectionRuleResponse, DetectionRuleUpdate
from app.api.auth import get_current_user, require_role
from app.core.audit import log_audit_event

router = APIRouter(prefix="/alerts", tags=["Detection & Alerts"])

@router.get("", response_model=Dict[str, Any])
def list_alerts(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    hostname: Optional[str] = None,
    rule_id: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if hostname:
        query = query.filter(Alert.hostname.ilike(f"%{hostname}%"))
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)

    total = query.count()
    alerts = query.order_by(desc(Alert.timestamp)).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [AlertResponse.from_orm(a) for a in alerts]
    }

@router.get("/rules", response_model=List[DetectionRuleResponse])
def list_detection_rules(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    rules = db.query(DetectionRule).all()
    return rules

@router.patch("/rules/{rule_id}", response_model=DetectionRuleResponse)
def update_detection_rule(
    rule_id: str,
    update_data: DetectionRuleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    rule = db.query(DetectionRule).filter(DetectionRule.rule_id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found.")

    if update_data.is_enabled is not None:
        rule.is_enabled = update_data.is_enabled
    if update_data.severity is not None:
        rule.severity = update_data.severity
    if update_data.threshold is not None:
        rule.threshold = update_data.threshold
    if update_data.time_window_seconds is not None:
        rule.time_window_seconds = update_data.time_window_seconds

    db.commit()
    db.refresh(rule)

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="DETECTION_RULE_CONFIG_UPDATED",
        resource_type="DetectionRule",
        resource_id=rule.rule_id,
        details={"is_enabled": rule.is_enabled, "severity": rule.severity}
    )

    return rule

@router.get("/{alert_id}", response_model=AlertResponse)
def get_alert_details(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")
    return alert

@router.patch("/{alert_id}", response_model=AlertResponse)
def update_alert(
    alert_id: str,
    update_in: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found.")

    old_status = alert.status
    if update_in.status:
        alert.status = update_in.status
    if update_in.incident_id:
        alert.incident_id = update_in.incident_id

    db.commit()
    db.refresh(alert)

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="ALERT_STATUS_UPDATED",
        resource_type="Alert",
        resource_id=alert.alert_id,
        details={"old_status": old_status, "new_status": alert.status}
    )

    return alert
