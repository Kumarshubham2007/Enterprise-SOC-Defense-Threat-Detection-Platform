from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import ThreatIntelIndicator, User
from app.schemas.schemas import ThreatIntelIndicatorResponse, ThreatIntelCreate
from app.api.auth import get_current_user, require_role
from app.core.audit import log_audit_event

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

class TestMatchRequest(BaseModel):
    indicator_type: str # ip, domain, sha256, url
    value: str

@router.get("/indicators", response_model=List[ThreatIntelIndicatorResponse])
def list_indicators(
    db: Session = Depends(get_db),
    indicator_type: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.is_active == True)
    if indicator_type:
        query = query.filter(ThreatIntelIndicator.indicator_type == indicator_type)
    return query.order_by(desc(ThreatIntelIndicator.last_seen)).all()

@router.post("/indicators", response_model=ThreatIntelIndicatorResponse)
def add_indicator(
    req: ThreatIntelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    existing = db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.value == req.value.strip()).first()
    if existing:
        existing.is_active = True
        existing.confidence = req.confidence
        existing.description = req.description
        db.commit()
        db.refresh(existing)
        return existing

    ioc = ThreatIntelIndicator(
        indicator_type=req.indicator_type.strip().lower(),
        value=req.value.strip(),
        threat_group=req.threat_group.strip(),
        confidence=req.confidence,
        description=req.description,
        is_active=True
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="THREAT_INTEL_IOC_ADDED",
        resource_type="ThreatIntelIndicator",
        resource_id=ioc.value,
        details={"type": ioc.indicator_type, "group": ioc.threat_group}
    )
    return ioc

@router.post("/match", response_model=Dict[str, Any])
def test_indicator_match(
    req: TestMatchRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    val = req.value.strip().lower()
    ioc = db.query(ThreatIntelIndicator).filter(
        ThreatIntelIndicator.is_active == True,
        ThreatIntelIndicator.value.ilike(val)
    ).first()

    if ioc:
        return {
            "matched": True,
            "indicator": ThreatIntelIndicatorResponse.from_orm(ioc),
            "recommendation": f"Known malicious indicator linked to {ioc.threat_group}. Immediate triage recommended."
        }
    return {
        "matched": False,
        "indicator": None,
        "recommendation": "No match found in current threat intelligence database."
    }
