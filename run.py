#!/usr/bin/env python3
"""
Enterprise Security Monitoring & Incident Response Platform (ESMIR)
Unified Execution Manager & Service Launcher

Usage:
    python run.py                 # Runs both Backend & Frontend and opens browser
    python run.py --backend       # Runs only FastAPI Backend (port 8000)
    python run.py --frontend      # Runs only Vite Frontend (port 5173)
    python run.py --seed          # Seeds demo attack telemetry & incidents
    python run.py --test          # Runs all 20 automated pytest test suites
    python run.py --no-browser    # Starts services without auto-opening web browser
"""

import sys
import os
import time
import shutil
import signal
import argparse
import threading
import subprocess
import webbrowser
import urllib.request
import urllib.error
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"

# Reconfigure stdout/stderr for UTF-8 compatibility on Windows terminals
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI Colors for Terminal Output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = f"""{CYAN}{BOLD}
+=================================================================================+
|   ENTERPRISE SECURITY MONITORING & INCIDENT RESPONSE PLATFORM (ESMIR)           |
|   Defensive SOC Operations, SIEM Correlation, FIM, DLP & Incident Playbooks     |
+=================================================================================+{RESET}
"""
    print(banner)


def ensure_virtualenv():
    """If invoked with global Python, automatically re-exec within .venv if present."""
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if in_venv:
        return sys.executable

    # Check for local .venv
    if os.name == "nt":
        venv_python = ROOT_DIR / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = ROOT_DIR / ".venv" / "bin" / "python"

    if venv_python.exists():
        return str(venv_python)

    return sys.executable


def check_node():
    """Verify that node and npm/vite dependencies exist."""
    node_bin = shutil.which("node")
    if not node_bin:
        print(f"{RED}[!] Error: 'node' executable not found in PATH.{RESET}")
        print("    Please install Node.js (v18+) to run the ESMIR SOC frontend.")
        return None

    vite_script = FRONTEND_DIR / "node_modules" / "vite" / "bin" / "vite.js"
    if not vite_script.exists():
        print(f"{YELLOW}[*] Installing frontend dependencies (npm install)...{RESET}")
        subprocess.run(["npm", "install"], cwd=FRONTEND_DIR, shell=(os.name == "nt"))

    return node_bin


def stream_logs(pipe, prefix, color):
    """Read process output line-by-line and print with a colored prefix."""
    try:
        for line in iter(pipe.readline, ""):
            if not line:
                break
            clean_line = line.rstrip()
            if clean_line:
                print(f"{color}[{prefix}]{RESET} {clean_line}")
    except Exception:
        pass


def find_available_port(preferred_port=8000, fallback_ports=(8001, 8008, 8080)):
    """Check if preferred_port is free; otherwise search fallback ports."""
    import socket
    for port in [preferred_port, *fallback_ports]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('127.0.0.1', port))
            s.close()
            return port
        except Exception:
            continue
    return preferred_port


def wait_for_backend(port=8000, timeout=20):
    """Poll the backend health endpoint until it responds."""
    url = f"http://127.0.0.1:{port}/api/health"
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ESMIR-Launcher"})
            with urllib.request.urlopen(req, timeout=1.0) as res:
                if res.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def run_tests(python_exe):
    """Run all 20 automated tests."""
    print(f"\n{CYAN}[*] Executing ESMIR Automated Test Suite (20 tests)...{RESET}\n")
    test_file = BACKEND_DIR / "tests" / "test_esmir_comprehensive.py"
    cmd = [python_exe, "-m", "pytest", str(test_file), "-v", "-W", "ignore"]
    res = subprocess.run(cmd, cwd=ROOT_DIR)
    sys.exit(res.returncode)


def run_seed(python_exe):
    """Seed demonstration data."""
    print(f"\n{CYAN}[*] Seeding Demonstration Telemetry & Attack Scenarios...{RESET}\n")
    seed_script = ROOT_DIR / "scripts" / "seed_demo_data.py"
    res = subprocess.run([python_exe, str(seed_script)], cwd=ROOT_DIR)
    sys.exit(res.returncode)


def main():
    parser = argparse.ArgumentParser(description="ESMIR Platform Unified Runner")
    parser.add_argument("--backend", action="store_true", help="Launch only the FastAPI Backend server")
    parser.add_argument("--frontend", action="store_true", help="Launch only the Vite Frontend server")
    parser.add_argument("--seed", action="store_true", help="Seed attack scenario telemetry into the database")
    parser.add_argument("--test", action="store_true", help="Execute the 20-test automated verification suite")
    parser.add_argument("--no-browser", action="store_true", help="Do not automatically launch web browser")
    args = parser.parse_args()

    print_banner()

    python_exe = ensure_virtualenv()

    # Route special single-task flags
    if args.test:
        run_tests(python_exe)
        return

    if args.seed:
        run_seed(python_exe)
        return

    launch_backend = True
    launch_frontend = True

    if args.backend and not args.frontend:
        launch_frontend = False
    elif args.frontend and not args.backend:
        launch_backend = False

    processes = []

    def shutdown_all(signum=None, frame=None):
        print(f"\n{YELLOW}[*] Received termination signal. Stopping all ESMIR services...{RESET}")
        for p, name in processes:
            try:
                if p.poll() is None:
                    p.terminate()
            except Exception:
                pass
        time.sleep(1.0)
        for p, name in processes:
            try:
                if p.poll() is None:
                    p.kill()
            except Exception:
                pass
        print(f"{GREEN}[+] ESMIR SOC Platform stopped cleanly. Goodbye!{RESET}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_all)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown_all)

    backend_port = find_available_port(8000)
    if backend_port != 8000:
        print(f"{YELLOW}[!] Port 8000 is occupied by an external service (e.g. Splunk).{RESET}")
        print(f"{GREEN}[+] Dynamically assigning ESMIR Backend to free port: {backend_port}{RESET}")

    # Set environment for Vite proxy & backend
    os.environ["ESMIR_BACKEND_PORT"] = str(backend_port)
    proc_env = os.environ.copy()
    proc_env["ESMIR_BACKEND_PORT"] = str(backend_port)

    # 1. Launch Backend
    if launch_backend:
        print(f"{CYAN}[*] Starting Backend API Server (FastAPI / Uvicorn on port {backend_port})...{RESET}")
        backend_cmd = [
            python_exe, "-m", "uvicorn", "app.main:app",
            "--host", "127.0.0.1", "--port", str(backend_port)
        ]
        backend_proc = subprocess.Popen(
            backend_cmd,
            cwd=BACKEND_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=proc_env
        )
        processes.append((backend_proc, "Backend"))
        t_backend = threading.Thread(
            target=stream_logs,
            args=(backend_proc.stdout, "BACKEND", CYAN),
            daemon=True
        )
        t_backend.start()

    # 2. Launch Frontend
    if launch_frontend:
        node_bin = check_node()
        if not node_bin:
            shutdown_all()
            return

        vite_script = FRONTEND_DIR / "node_modules" / "vite" / "bin" / "vite.js"
        print(f"{MAGENTA}[*] Starting Frontend SOC Console (React 19 / Vite)...{RESET}")
        frontend_cmd = [node_bin, str(vite_script)]
        frontend_proc = subprocess.Popen(
            frontend_cmd,
            cwd=FRONTEND_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=proc_env
        )
        processes.append((frontend_proc, "Frontend"))
        t_frontend = threading.Thread(
            target=stream_logs,
            args=(frontend_proc.stdout, "FRONTEND", MAGENTA),
            daemon=True
        )
        t_frontend.start()

    # 3. Healthcheck & Browser Launch
    if launch_backend:
        print(f"{YELLOW}[*] Awaiting backend health verification on port {backend_port}...{RESET}")
        healthy = wait_for_backend(port=backend_port, timeout=15)
        if healthy:
            print(f"{GREEN}[+] Backend API is online and responding!{RESET}")
        else:
            print(f"{YELLOW}[!] Warning: Backend healthcheck timed out. Process is still running.{RESET}")

    # Information Card
    print(f"""
{GREEN}{BOLD}===================================================================================
  ESMIR SOC PLATFORM ACTIVE & READY
==================================================================================={RESET}
  {BOLD}Frontend Console:{RESET}   {CYAN}http://localhost:5173{RESET}
  {BOLD}Backend API Docs:{RESET}   {CYAN}http://127.0.0.1:{backend_port}/docs{RESET}
  {BOLD}System Health:{RESET}      {CYAN}http://127.0.0.1:{backend_port}/api/health{RESET}

  {BOLD}Pre-configured Authentication Credentials:{RESET}
    * {BOLD}SOC Administrator:{RESET}  {GREEN}admin{RESET}   / {GREEN}Admin@ESMIR2026!{RESET}
    * {BOLD}Tier 2 Analyst:{RESET}     {GREEN}analyst{RESET} / {GREEN}Analyst@ESMIR2026!{RESET}
    * {BOLD}Security Auditor:{RESET}   {GREEN}viewer{RESET}  / {GREEN}Viewer@ESMIR2026!{RESET}

  {YELLOW}Press Ctrl+C in this terminal to shut down all platform services cleanly.{RESET}
{GREEN}{BOLD}==================================================================================={RESET}
""")

    if launch_frontend and not args.no_browser:
        # Give Vite a second to bind port 5173 then open browser
        time.sleep(1.5)
        try:
            webbrowser.open("http://localhost:5173")
        except Exception:
            pass

    # Keep main thread alive monitoring children
    try:
        while True:
            time.sleep(0.5)
            for proc, name in processes:
                ret = proc.poll()
                if ret is not None:
                    print(f"{RED}[!] {name} process exited unexpectedly with code {ret}.{RESET}")
                    shutdown_all()
    except KeyboardInterrupt:
        shutdown_all()


if __name__ == "__main__":
    main()
