import platform
import socket
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List
import httpx

logger = logging.getLogger("esmir.collector")

class LocalEndpointCollector:
    """
    Lightweight, modular endpoint telemetry collector for ESMIR.
    Gathers local host metadata, system health metrics, and normalizes events for ingestion.
    """
    def __init__(self, backend_url: str = "http://127.0.0.1:8000", collector_token: str = None):
        self.backend_url = backend_url.rstrip("/")
        self.collector_token = collector_token or "esmir-collector-token-sec-ops-987123"
        self.hostname = socket.gethostname()
        self.os_type = f"{platform.system()} {platform.release()}"

    def get_host_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def collect_heartbeat_event(self) -> Dict[str, Any]:
        """Collects genuine system heartbeat and telemetry event."""
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "local_collector",
            "hostname": self.hostname,
            "event_category": "System",
            "severity": "Info",
            "event_name": "Endpoint Collector Heartbeat",
            "source_ip": self.get_host_ip(),
            "details": {
                "os": self.os_type,
                "python_version": platform.python_version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
            },
            "is_demo": False
        }

    def send_event(self, event_data: Dict[str, Any]) -> bool:
        """Sends a single normalized event to the ESMIR API."""
        try:
            with httpx.Client(timeout=5.0) as client:
                res = client.post(
                    f"{self.backend_url}/api/events",
                    json=event_data,
                    headers={"X-Collector-Token": self.collector_token}
                )
                return res.status_code == 200
        except Exception as e:
            logger.error(f"Failed to transmit event to {self.backend_url}: {str(e)}")
            return False

    def send_batch(self, events: List[Dict[str, Any]]) -> bool:
        """Sends batch of normalized events to the ESMIR API."""
        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(
                    f"{self.backend_url}/api/events/batch",
                    json={"events": events},
                    headers={"X-Collector-Token": self.collector_token}
                )
                return res.status_code == 200
        except Exception as e:
            logger.error(f"Failed to transmit batch events to {self.backend_url}: {str(e)}")
            return False

if __name__ == "__main__":
    collector = LocalEndpointCollector()
    evt = collector.collect_heartbeat_event()
    print("Collected heartbeat event:")
    print(json.dumps(evt, indent=2))
