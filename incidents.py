from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import Incident, IncidentComment, IncidentEvidence, User
from app.schemas.schemas import (
    IncidentCreate, IncidentUpdate, IncidentResponse, IncidentCommentCreate, IncidentEvidenceAdd
)
from app.services.incident_service import create_incident_from_alerts, update_incident_status, SOC_PLAYBOOKS
from app.api.auth import get_current_user
from app.core.audit import log_audit_event

router = APIRouter(prefix="/incidents", tags=["Incident Response & Case Management"])

@router.get("", response_model=List[IncidentResponse])
def list_incidents(
    db: Session = Depends(get_db),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = db.query(Incident)
    if status:
        query = query.filter(Incident.status == status)
    if severity:
        query = query.filter(Incident.severity == severity)
    if category:
        query = query.filter(Incident.category == category)

    incidents = query.order_by(desc(Incident.created_at)).all()
    return incidents

@router.post("", response_model=IncidentResponse)
def create_incident(
    req: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = create_incident_from_alerts(
        db=db,
        incident_in=req,
        creator_username=current_user.username
    )
    return incident

@router.get("/playbooks", response_model=Dict[str, Any])
def get_soc_playbooks(
    current_user: User = Depends(get_current_user)
):
    return SOC_PLAYBOOKS

@router.get("/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    return incident

@router.patch("/{incident_id}", response_model=IncidentResponse)
def update_incident(
    incident_id: int,
    req: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        updated = update_incident_status(
            db=db,
            incident_id=incident_id,
            update_data=req,
            analyst_username=current_user.username
        )
        return updated
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/{incident_id}/comments", response_model=Dict[str, Any])
def add_incident_comment(
    incident_id: int,
    req: IncidentCommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    comment = IncidentComment(
        incident_id=incident.id,
        author=current_user.username,
        comment=req.comment
    )
    db.add(comment)
    db.commit()

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="INCIDENT_COMMENT_ADDED",
        resource_type="Incident",
        resource_id=incident.incident_id,
        details={"comment_snippet": req.comment[:50]}
    )
    return {"status": "success", "comment_id": comment.id}

@router.post("/{incident_id}/evidence", response_model=Dict[str, Any])
def add_incident_evidence(
    incident_id: int,
    req: IncidentEvidenceAdd,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")

    ev = IncidentEvidence(
        incident_id=incident.id,
        evidence_type=req.evidence_type,
        reference_id=req.reference_id,
        notes=req.notes
    )
    db.add(ev)
    db.commit()

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="INCIDENT_EVIDENCE_ATTACHED",
        resource_type="Incident",
        resource_id=incident.incident_id,
        details={"type": req.evidence_type, "ref": req.reference_id}
    )
    return {"status": "success", "evidence_id": ev.id}
