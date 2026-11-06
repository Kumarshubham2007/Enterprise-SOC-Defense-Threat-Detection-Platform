import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.config import settings
from app.schemas.schemas import EventCreate, IncidentCreate
from app.detection.engine import ingest_single_event
from app.services.fim_service import create_directory_baseline, verify_and_reconcile_fim
from app.services.dlp_service import scan_directory_for_dlp
from app.services.incident_service import create_incident_from_alerts
from app.models.models import Alert, User
from app.api.auth import get_current_user

router = APIRouter(prefix="/demo", tags=["Demonstration & Simulation"])

@router.post("/seed", response_model=Dict[str, Any])
def seed_demo_scenario(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Seeds a realistic end-to-end SOC demonstration scenario:
    1. Repeated failed logons -> Brute force detection.
    2. Correlated successful logon -> Account compromise detection.
    3. Malicious process launch from Temp directory.
    4. Threat intelligence C2 indicator match.
    5. FIM baseline creation and simulated file modification.
    6. Synthetic document creation and DLP sensitive data detection.
    All events and alerts are explicitly labeled with is_demo=True.
    """
    now = datetime.now(timezone.utc)
    demo_hostname = "dc01.corp.internal"
    targeted_user = "b.anderson"
    attacker_ip = "198.51.100.45" # Matches Threat Intel IOC!

    alerts_created = []

    # 1. Simulate 3 failed logon attempts
    for i in range(3):
        evt = EventCreate(
            timestamp=now - timedelta(seconds=120 - (i * 20)),
            source="demo_simulator",
            hostname=demo_hostname,
            event_category="Authentication",
            severity="Medium",
            event_name="Logon Failed - Bad Password (Event ID 4625)",
            username=targeted_user,
            source_ip=attacker_ip,
            details={"logon_type": 3, "failure_code": "0xC000006A", "simulated_note": "Demo brute force sequence"},
            is_demo=True
        )
        _, alts = ingest_single_event(db, evt)
        alerts_created.extend(alts)

    # 2. Correlated successful logon post failures
    success_evt = EventCreate(
        timestamp=now - timedelta(seconds=30),
        source="demo_simulator",
        hostname=demo_hostname,
        event_category="Authentication",
        severity="High",
        event_name="Logon Succeeded (Event ID 4624)",
        username=targeted_user,
        source_ip=attacker_ip,
        details={"logon_type": 3, "auth_package": "Kerberos", "simulated_note": "Demo compromise sequence"},
        is_demo=True
    )
    _, alts2 = ingest_single_event(db, success_evt)
    alerts_created.extend(alts2)

    # 3. Process execution in temp directory
    proc_evt = EventCreate(
        timestamp=now - timedelta(seconds=15),
        source="demo_simulator",
        hostname=demo_hostname,
        event_category="Process",
        severity="High",
        event_name="Process Creation (Event ID 4688)",
        username=targeted_user,
        process_name="C:\\Users\\banderson\\AppData\\Local\\Temp\\update_agent.exe",
        details={"command_line": "update_agent.exe -silent -payload C2", "parent_process": "cmd.exe"},
        is_demo=True
    )
    _, alts3 = ingest_single_event(db, proc_evt)
    alerts_created.extend(alts3)

    # 4. Create FIM demo directory and baseline
    demo_fim_dir = settings.DATA_DIR / "demo_monitored_sys32"
    demo_fim_dir.mkdir(parents=True, exist_ok=True)
    
    config_file = demo_fim_dir / "security_policy.cfg"
    config_file.write_text("ENFORCE_MFA=1\nMIN_PASS_LEN=14\nLOG_LEVEL=DEBUG", encoding="utf-8")

    sys_file = demo_fim_dir / "net_driver.sys"
    sys_file.write_text("GENUINE_SYSTEM_DRIVER_CONTENT_v1", encoding="utf-8")

    baseline, _ = create_directory_baseline(
        db=db,
        directory_path=str(demo_fim_dir),
        name="Demo Infrastructure Security Directory",
        creator_username=current_user.username
    )

    # Now tamper with config_file and add an unauthorized file
    config_file.write_text("ENFORCE_MFA=0\nMIN_PASS_LEN=6\nLOG_LEVEL=NONE", encoding="utf-8")
    malicious_script = demo_fim_dir / "backdoor_loader.ps1"
    malicious_script.write_text("Write-Output 'Simulated unauthorized payload staging'", encoding="utf-8")

    # Run FIM reconciliation scan to detect modifications
    fim_results = verify_and_reconcile_fim(
        db=db,
        baseline_id=baseline.id,
        hostname=demo_hostname
    )

    # 5. Create synthetic sensitive DLP document
    demo_dlp_dir = settings.DATA_DIR / "demo_shares"
    demo_dlp_dir.mkdir(parents=True, exist_ok=True)
    
    payroll_doc = demo_dlp_dir / "Q3_Payroll_Staging.csv"
    payroll_doc.write_text(
        "employee_name,work_email,contact_phone,national_id,pan_id,salary_account\n"
        "Alice Smith,alice.smith@corp.internal,555-234-5678,2345 6789 0123,ABCDE1234F,4111111111111111\n"
        "Bob Johnson,bob.j@corp.internal,555-876-5432,9876 5432 1098,WXYZP9876L,4242424242424242\n",
        encoding="utf-8"
    )

    dlp_results = scan_directory_for_dlp(
        db=db,
        directory_path=str(demo_dlp_dir)
    )

    # 6. Create an incident linking the generated alerts
    recent_alts = db.query(Alert).filter(Alert.is_demo == True).order_by(Alert.id.desc()).limit(3).all()
    alt_ids = [a.id for a in recent_alts]

    incident = create_incident_from_alerts(
        db=db,
        incident_in=IncidentCreate(
            title="Simulated Adversary Intrusion: Brute Force & Temp Execution",
            summary="Demonstration incident correlated from brute force login attempts, subsequent logon success from known C2 indicator IP, and unauthorized process execution.",
            severity="Critical",
            category="Credential Compromise",
            alert_ids=alt_ids
        ),
        creator_username=current_user.username
    )

    return {
        "status": "success",
        "message": "Demo scenario loaded successfully. All records flagged with is_demo=True.",
        "alerts_generated_count": len(alerts_created),
        "fim_violations_detected": fim_results["violations_detected"],
        "dlp_findings_detected": dlp_results["findings_count"],
        "incident_created": incident.incident_id,
    }
