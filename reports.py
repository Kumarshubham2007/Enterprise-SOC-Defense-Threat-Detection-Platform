from typing import Dict, Any
from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.schemas import ReportGenerateRequest
from app.services.report_service import generate_soc_report, export_report_csv, export_report_html
from app.models.models import User
from app.api.auth import get_current_user
from app.core.audit import log_audit_event

router = APIRouter(prefix="/reports", tags=["Reporting & Compliance"])

@router.post("/generate", response_model=Dict[str, Any])
def generate_report(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    report_data = generate_soc_report(db, req)
    log_audit_event(
        db=db,
        actor=current_user.username,
        action="SOC_REPORT_GENERATED",
        resource_type="Report",
        resource_id=report_data["report_id"],
        details={"filters": req.dict(exclude_none=True)}
    )
    return report_data

@router.post("/export/csv")
def download_report_csv(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    report_data = generate_soc_report(db, req)
    csv_content = export_report_csv(report_data)
    log_audit_event(
        db=db,
        actor=current_user.username,
        action="SOC_REPORT_EXPORTED_CSV",
        resource_type="Report",
        resource_id=report_data["report_id"]
    )
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={report_data['report_id']}.csv"}
    )

@router.post("/export/html")
def download_report_html(
    req: ReportGenerateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    report_data = generate_soc_report(db, req)
    html_content = export_report_html(report_data)
    log_audit_event(
        db=db,
        actor=current_user.username,
        action="SOC_REPORT_EXPORTED_HTML",
        resource_type="Report",
        resource_id=report_data["report_id"]
    )
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f"inline; filename={report_data['report_id']}.html"}
    )
