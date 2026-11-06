from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import VulnerabilityFinding, User
from app.schemas.schemas import VulnerabilityFindingResponse
from app.services.vuln_service import (
    run_local_vulnerability_assessment, import_external_vulnerability_scan
)
from app.api.auth import get_current_user, require_role
from app.core.audit import log_audit_event

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerability Assessment"])

class VulnScanRequest(BaseModel):
    asset_id: Optional[int] = None

class VulnImportRequest(BaseModel):
    asset_id: Optional[int] = None
    findings: List[Dict[str, Any]]

class VulnStatusUpdate(BaseModel):
    status: str # Open, In_Progress, Remediated, Accepted_Risk

@router.get("", response_model=List[VulnerabilityFindingResponse])
def list_vulnerabilities(
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    asset_id: Optional[int] = None,
    current_user: User = Depends(get_current_user)
):
    query = db.query(VulnerabilityFinding)
    if severity:
        query = query.filter(VulnerabilityFinding.severity == severity)
    if status:
        query = query.filter(VulnerabilityFinding.status == status)
    if asset_id:
        query = query.filter(VulnerabilityFinding.asset_id == asset_id)

    findings = query.order_by(desc(VulnerabilityFinding.assessment_timestamp)).all()
    return findings

@router.post("/scan", response_model=List[VulnerabilityFindingResponse])
def run_vulnerability_scan(
    req: VulnScanRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    findings = run_local_vulnerability_assessment(db, req.asset_id)
    log_audit_event(
        db=db,
        actor=current_user.username,
        action="VULNERABILITY_ASSESSMENT_RUN",
        resource_type="Asset",
        resource_id=str(req.asset_id or "all"),
        details={"findings_generated": len(findings)}
    )
    return findings

@router.post("/import", response_model=Dict[str, Any])
def import_vulnerabilities(
    req: VulnImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    count = import_external_vulnerability_scan(db, req.findings, req.asset_id)
    log_audit_event(
        db=db,
        actor=current_user.username,
        action="VULNERABILITY_DATA_IMPORTED",
        resource_type="Asset",
        resource_id=str(req.asset_id or "all"),
        details={"count": count}
    )
    return {"status": "success", "imported_count": count}

@router.patch("/{finding_id}", response_model=VulnerabilityFindingResponse)
def update_vulnerability_status(
    finding_id: int,
    req: VulnStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    old_status = finding.status
    finding.status = req.status
    db.commit()
    db.refresh(finding)

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="VULNERABILITY_STATUS_UPDATED",
        resource_type="VulnerabilityFinding",
        resource_id=finding.cve_id,
        details={"old_status": old_status, "new_status": req.status}
    )
    return finding
