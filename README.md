Enterprise SOC Defense & Threat Detection Platform
A defensive cybersecurity project designed to support common Security
Operations Center (SOC) workflows. It brings together areas such as
security-event review, indicator-of-compromise (IOC) matching,
file-integrity monitoring, alert investigation, and reporting.
Project status: Under development and testing. Verify each module
in the running application before describing it as production-ready.
Demo and synthetic records are for testing and do not represent
confirmed real-world threats.

Key Modules
- Overview Dashboard --- review the available security-event and
  alert summaries.
- Live Security Events --- inspect, search, filter, or import
  event records where supported.
- Detection & Alerts --- review suspicious activity flagged by the
  configured detection logic.
- IOC Engine --- compare submitted indicators against the dataset
  configured in the platform.
- Asset Inventory --- view tracked systems and available asset
  metadata.
- File Integrity Monitoring (FIM) --- review monitored-file
  changes and compare SHA-256 hashes with a baseline.
- DLP & Exposure --- review sensitive-data exposure findings where
  implemented.
- Vulnerability Assessment --- review vulnerability findings where
  implemented.
- Incident Response --- organize investigation details and
  response workflow where implemented.
- Reports & Audit Logs --- review or export records where
  supported.
- System Health & Settings --- inspect available service status
  and configuration.
Technology Stack
Current development setup:
- Frontend: React 19, Vite
- Backend: Python, FastAPI, Uvicorn
- Security concepts: SOC workflows, event analysis, IOC matching,
  SHA-256 file-integrity checks
Update this section to reflect the exact libraries, database,
collectors, and integrations in your repository.
Getting Started
Prerequisites
- Node.js and npm
- Python 3
- Git
1. Clone the repository
git clone <YOUR_REPOSITORY_URL>
cd <YOUR_PROJECT_DIRECTORY>
Replace the placeholders with your repository URL and directory name.
2. Start the backend
Open a terminal in the backend directory:
cd backend
python -m venv .venv
Activate the environment.

Windows PowerShell
.\.venv\Scripts\Activate.ps1
Linux/macOS
source .venv/bin/activate
Install dependencies using the dependency file included in your
repository. If it contains requirements.txt, run:
pip install -r requirements.txt
Start the application using the entry point configured in your code. For
example, if main.py contains a FastAPI object named app:
uvicorn main:app --reload --port 8000
If your entry point or port differs, use your project's configured
command. FastAPI documentation is commonly available at
http://127.0.0.1:8000/docs.
3. Start the frontend
Open a second terminal in the frontend directory:
cd frontend
npm install
npm run dev
Open the local URL printed by Vite, often http://localhost:5173.
Folder names, ports, and commands may differ in your repository. Check
its package scripts and configuration before running these examples.

Example Testing Workflow
1. Open Live Security Events and inspect the records available in
   the application.
2. Search or filter for a specific event, if supported.
3. Open Detection & Alerts and review the reason and evidence for
   an alert.
4. Submit a test indicator in the IOC Engine and compare the result
   with the configured dataset.
5. Review a FIM finding and compare its expected and observed SHA-256
   hashes.
6. Check whether reports or audit logs record the activity, if those
   features are implemented.
Use only systems and data you own or are authorized to test. Synthetic
indicators and sample files are recommended for demonstrations.
Testing Notes and Limitations
- An IOC match means the indicator matched the configured dataset; it
  does not independently establish real-world malicious reputation.
- Documentation-reserved IP addresses and synthetic threat-group
  labels should be clearly identified as test data.
- A SHA-256 mismatch indicates that file contents differ from the
  recorded baseline; it does not by itself prove malicious activity.
- Imported CSV records and demo events should not be described as live
  production telemetry unless the collection path has been verified.
- External threat-intelligence feeds, live endpoint collection,
  automated containment, vulnerability scanning, and production-grade
  DLP should only be claimed after they have been implemented and
  tested.
Security and Privacy
- Never commit passwords, API keys, access tokens, private
  certificates, or other secrets.
- Keep development secrets in environment variables or a local .env
  file, and ensure .env is included in .gitignore.
- Do not use real customer, personal, or confidential data in test
  workflows.
- Restrict access to the application and its data when running it on a
  network.
Future Improvements
- Add and validate more authorized log sources.
- Improve alert context, severity handling, and false-positive review.
- Add repeatable tests for event ingestion, IOC matching, and FIM.
- Implement role-based access control and secure configuration
  management.
- Improve reporting, auditability, and error handling.
- Document supported integrations and deployment requirements.
Contributing
1. Create a branch for your change.
2. Keep changes focused and add tests where practical.
3. Never include secrets or sensitive production data.
4. Document tested behavior and known limitations.
Disclaimer
This project is intended for defensive security learning, authorized
testing, and SOC workflow development. It is not a substitute for a
validated production security platform. Verify findings before taking
response actions.
Author
Shubham Kumar Bal
Cybersecurity | Blue Team | SOC Analyst Learning Journey
