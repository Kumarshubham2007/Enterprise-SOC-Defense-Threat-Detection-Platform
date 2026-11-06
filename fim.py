from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import FimBaseline, FimFinding, User
from app.schemas.schemas import (
    BaselineCreateRequest, FimBaselineResponse, FimFindingResponse, FimBaselineEntryResponse
)
from app.services.fim_service import (
    create_directory_baseline, verify_and_reconcile_fim, approve_baseline_update
)
from app.api.auth import get_current_user, require_role
from app.core.audit import log_audit_event

router = APIRouter(prefix="/fim", tags=["File Integrity Monitoring"])

class FimScanRequest(BaseModel):
    baseline_id: int
    hostname: Optional[str] = "localhost"

class FimApproveRequest(BaseModel):
    baseline_id: int
    justification: str

@router.post("/baseline", response_model=Dict[str, Any])
def create_baseline(
    request: BaselineCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    try:
        baseline, message = create_directory_baseline(
            db=db,
            directory_path=request.directory_path,
            name=request.name,
            creator_username=current_user.username
        )
        log_audit_event(
            db=db,
            actor=current_user.username,
            action="FIM_BASELINE_CREATED",
            resource_type="FimBaseline",
            resource_id=baseline.baseline_id,
            details={"path": baseline.monitored_path, "total_files": baseline.total_files, "version": baseline.version}
        )
        return {
            "status": "success",
            "message": message,
            "baseline": FimBaselineResponse.from_orm(baseline)
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/baselines", response_model=List[FimBaselineResponse])
def list_baselines(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    baselines = db.query(FimBaseline).order_by(desc(FimBaseline.created_at)).all()
    return baselines

@router.get("/baselines/{baseline_id}", response_model=Dict[str, Any])
def get_baseline_detail(
    baseline_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    baseline = db.query(FimBaseline).filter(FimBaseline.id == baseline_id).first()
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found.")
    
    entries = [FimBaselineEntryResponse.from_orm(e) for e in baseline.entries]
    return {
        "baseline": FimBaselineResponse.from_orm(baseline),
        "entries": entries
    }

@router.post("/scan", response_model=Dict[str, Any])
def run_fim_scan(
    scan_req: FimScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        result = verify_and_reconcile_fim(
            db=db,
            baseline_id=scan_req.baseline_id,
            hostname=scan_req.hostname
        )
        log_audit_event(
            db=db,
            actor=current_user.username,
            action="FIM_RECONCILIATION_SCAN_EXECUTED",
            resource_type="FimBaseline",
            resource_id=result["baseline_id"],
            details={"violations_detected": result["violations_detected"]}
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/findings", response_model=List[FimFindingResponse])
def list_fim_findings(
    db: Session = Depends(get_db),
    status: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    query = db.query(FimFinding)
    if status:
        query = query.filter(FimFinding.status == status)
    findings = query.order_by(desc(FimFinding.detected_at)).limit(100).all()
    return findings

@router.post("/approve-update", response_model=Dict[str, Any])
def approve_update(
    req: FimApproveRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    try:
        new_baseline = approve_baseline_update(
            db=db,
            baseline_id=req.baseline_id,
            analyst_username=current_user.username,
            justification=req.justification
        )
        log_audit_event(
            db=db,
            actor=current_user.username,
            action="FIM_BASELINE_UPDATE_APPROVED",
            resource_type="FimBaseline",
            resource_id=new_baseline.baseline_id,
            details={"justification": req.justification, "new_version": new_baseline.version}
        )
        return {
            "status": "success",
            "message": f"Baseline updated to v{new_baseline.version} with analyst approval.",
            "new_baseline": FimBaselineResponse.from_orm(new_baseline)
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
