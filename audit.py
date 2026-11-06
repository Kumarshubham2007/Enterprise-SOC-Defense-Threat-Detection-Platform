from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import AuditLog, User
from app.schemas.schemas import AuditLogResponse
from app.core.audit import verify_audit_chain
from app.api.auth import get_current_user, require_role

router = APIRouter(prefix="/audit", tags=["Auditability & Integrity"])

@router.get("/logs", response_model=Dict[str, Any])
def get_audit_logs(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    actor: Optional[str] = None,
    action: Optional[str] = None,
    current_user: User = Depends(require_role(["admin", "soc_analyst", "read_only_auditor"]))
):
    query = db.query(AuditLog)
    if actor:
        query = query.filter(AuditLog.actor.ilike(f"%{actor}%"))
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))

    total = query.count()
    logs = query.order_by(desc(AuditLog.id)).offset((page - 1) * limit).limit(limit).all()

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [AuditLogResponse.from_orm(l) for l in logs]
    }

@router.get("/verify", response_model=Dict[str, Any])
def verify_integrity(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "read_only_auditor", "security_engineer"]))
):
    is_valid, details = verify_audit_chain(db)
    return {
        "chain_intact": is_valid,
        "status": "SECURE_VERIFIED" if is_valid else "TAMPERING_DETECTED",
        "verification_notes": details,
        "technical_limitation_disclosure": (
            "Cryptographic SHA-256 hash chaining verifies database immutability and detects post-hoc modifications. "
            "However, if an adversary gains root execution access to the host operating system, local databases can be overwritten alongside application code. "
            "In production environments, forward audit logs via TLS syslog/SIEM to a write-once read-many (WORM) storage destination."
        )
    }
