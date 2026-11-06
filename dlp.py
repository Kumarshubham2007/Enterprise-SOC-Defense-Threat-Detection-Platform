from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import DlpFinding, User
from app.schemas.schemas import DlpScanRequest, DlpFindingResponse
from app.services.dlp_service import scan_directory_for_dlp, correlate_dlp_exposure
from app.api.auth import get_current_user, require_role
from app.core.audit import log_audit_event

router = APIRouter(prefix="/dlp", tags=["Data Loss Prevention & Sensitive Data"])

@router.post("/scan", response_model=Dict[str, Any])
def scan_dlp(
    request: DlpScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer", "soc_analyst"]))
):
    try:
        result = scan_directory_for_dlp(
            db=db,
            directory_path=request.directory_path
        )
        log_audit_event(
            db=db,
            actor=current_user.username,
            action="DLP_SCAN_EXECUTED",
            resource_type="DlpScan",
            resource_id=request.directory_path,
            details=result
        )
        return {
            "status": "success",
            "results": result
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/findings", response_model=List[DlpFindingResponse])
def list_dlp_findings(
    db: Session = Depends(get_db),
    category: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = db.query(DlpFinding)
    if category:
        query = query.filter(DlpFinding.category == category)
    findings = query.order_by(desc(DlpFinding.scan_time)).limit(100).all()
    return findings

@router.get("/findings/{finding_id}/investigate", response_model=Dict[str, Any])
def investigate_exposure(
    finding_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        correlation = correlate_dlp_exposure(db, finding_id)
        return correlation
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
