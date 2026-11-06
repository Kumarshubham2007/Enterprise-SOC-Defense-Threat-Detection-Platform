"""
ESMIR Demonstration Data Seeder Script
Executes the end-to-end simulation scenario directly via API or database.
"""
import sys
import json
from pathlib import Path

# Add backend directory to sys.path
backend_path = Path(__file__).resolve().parent.parent / "backend"
if str(backend_path) not in sys.path:
    sys.path.insert(0, str(backend_path))

from app.core.database import SessionLocal, init_db
from app.api.demo import seed_demo_scenario
from app.models.models import User

def main():
    print("[*] Initializing ESMIR Database and Seeding Demonstration Telemetry...")
    init_db()
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            print("[-] Admin user missing.")
            return

        result = seed_demo_scenario(db=db, current_user=admin)
        print("[+] Demonstration scenario loaded successfully!")
        print(f"    - Alerts Generated: {result['alerts_generated_count']}")
        print(f"    - FIM Violations Detected: {result['fim_violations_detected']}")
        print(f"    - DLP Findings Discovered: {result['dlp_findings_detected']}")
        print(f"    - Incident Case Opened: {result['incident_created']}")
        print("[*] All generated records are clearly flagged with is_demo=True.")
    finally:
        db.close()

if __name__ == "__main__":
    main()
