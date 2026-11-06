from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.models import Asset, Alert, Incident, SecurityEvent, User
from app.schemas.schemas import AssetCreate, AssetUpdate, AssetResponse, AlertResponse, EventResponse
from app.api.auth import get_current_user, require_role
from app.core.audit import log_audit_event

router = APIRouter(prefix="/assets", tags=["Asset Inventory"])

@router.get("", response_model=List[Dict[str, Any]])
def list_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    assets = db.query(Asset).all()
    result = []
    for a in assets:
        alert_count = db.query(Alert).filter(Alert.asset_id == a.id, Alert.status.in_(["New", "Triaged", "Investigating"])).count()
        event_count = db.query(SecurityEvent).filter(SecurityEvent.asset_id == a.id).count()
        result.append({
            "id": a.id,
            "asset_identifier": a.asset_identifier,
            "hostname": a.hostname,
            "ip_address": a.ip_address,
            "os_type": a.os_type,
            "department": a.department,
            "criticality": a.criticality,
            "status": a.status,
            "agent_version": a.agent_version,
            "last_seen": a.last_seen.isoformat(),
            "active_alerts_count": alert_count,
            "total_events_count": event_count,
        })
    return result

@router.post("", response_model=AssetResponse)
def register_asset(
    asset_in: AssetCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    existing = db.query(Asset).filter(
        (Asset.asset_identifier == asset_in.asset_identifier) | (Asset.hostname == asset_in.hostname)
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Asset identifier or hostname already registered.")

    new_asset = Asset(
        asset_identifier=asset_in.asset_identifier,
        hostname=asset_in.hostname,
        ip_address=asset_in.ip_address,
        os_type=asset_in.os_type,
        department=asset_in.department,
        criticality=asset_in.criticality,
        status="Active"
    )
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="ASSET_REGISTERED",
        resource_type="Asset",
        resource_id=new_asset.asset_identifier,
        details={"hostname": new_asset.hostname, "ip": new_asset.ip_address}
    )

    return new_asset

@router.get("/{asset_id}", response_model=Dict[str, Any])
def get_asset_details(
    asset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    alerts = db.query(Alert).filter(Alert.asset_id == asset.id).order_by(desc(Alert.timestamp)).limit(10).all()
    events = db.query(SecurityEvent).filter(SecurityEvent.asset_id == asset.id).order_by(desc(SecurityEvent.timestamp)).limit(15).all()

    return {
        "asset": AssetResponse.from_orm(asset),
        "recent_alerts": [AlertResponse.from_orm(a) for a in alerts],
        "recent_events": [EventResponse.from_orm(e) for e in events]
    }

@router.patch("/{asset_id}", response_model=AssetResponse)
def update_asset(
    asset_id: int,
    asset_up: AssetUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["admin", "security_engineer"]))
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found.")

    if asset_up.hostname:
        asset.hostname = asset_up.hostname
    if asset_up.ip_address:
        asset.ip_address = asset_up.ip_address
    if asset_up.department:
        asset.department = asset_up.department
    if asset_up.criticality:
        asset.criticality = asset_up.criticality
    if asset_up.status:
        asset.status = asset_up.status

    db.commit()
    db.refresh(asset)

    log_audit_event(
        db=db,
        actor=current_user.username,
        action="ASSET_UPDATED",
        resource_type="Asset",
        resource_id=asset.asset_identifier,
        details=asset_up.dict(exclude_unset=True)
    )

    return asset
