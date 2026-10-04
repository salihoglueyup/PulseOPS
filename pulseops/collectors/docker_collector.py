import json
import re
import shutil
import socket
import subprocess
import time
from typing import Optional
from pulseops.models.docker import ContainerSummary
from pulseops.models.proxy import ProxyRoute
from pulseops.collectors.http_health import HTTPHealthChecker

DB_PORTS = {3306, 5432, 6379, 27017, 9200, 11211}

class DockerCollector:
    """Collects container information via the docker CLI if available."""

    def __init__(self):
        self._health_checker = HTTPHealthChecker()

    def collect(self) -> list[ContainerSummary]:
        if not shutil.which("docker"):
            return []
            
        try:
            res = subprocess.run(
                ["docker", "ps", "-a", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=3
            )
            if res.returncode != 0:
                return []
                
            containers: list[ContainerSummary] = []
            for line in res.stdout.strip().splitlines():
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    ports_str = data.get("Ports", "")
                    port_list = [p.strip() for p in ports_str.split(",") if p.strip()]
                    containers.append(ContainerSummary(
                        id=data.get("ID", "")[:12],
                        name=data.get("Names", "unknown"),
                        image=data.get("Image", "unknown"),
                        status=data.get("Status", "unknown"),
                        ports=port_list,
                        uptime=data.get("RunningFor", "")
                    ))
                except Exception:
                    continue
            return containers
        except Exception:
            return []

    def get_container_routes(self, containers: list[ContainerSummary]) -> list[ProxyRoute]:
        """Synthesizes ProxyRoute objects from running Docker containers with published ports."""
        routes: list[ProxyRoute] = []
        for c in containers:
            if not c.is_running or not c.ports:
                continue
            
            for p_mapping in c.ports:
                # Example: "127.0.0.1:3001->3001/tcp" or "0.0.0.0:8080->80/tcp" or ":::80->80/tcp"
                match = re.search(r'(?:[\d\.]+|\[::\]|\*):(\d+)->(\d+)/(tcp|udp)', p_mapping)
                if match:
                    host_port = int(match.group(1))
                    container_port = int(match.group(2))
                    
                    if host_port in DB_PORTS:
                        # TCP check for database/cache containers
                        t0 = time.time()
                        try:
                            s = socket.create_connection(("127.0.0.1", host_port), timeout=0.5)
                            s.close()
                            status = 200
                            latency = round((time.time() - t0) * 1000.0, 1)
                        except Exception:
                            status = 502
                            latency = round((time.time() - t0) * 1000.0, 1)
                        target_url = f"tcp://127.0.0.1:{host_port}"
                    else:
                        target_url = f"http://127.0.0.1:{host_port}"
                        status, latency = self._health_checker.check_url(target_url, timeout=0.8)

                    routes.append(ProxyRoute(
                        domain=f"{c.name}.docker",
                        listen_port=host_port,
                        target_url=target_url,
                        is_ssl=False,
                        target_process=f"docker:{c.name} (:{container_port})",
                        http_status=status,
                        response_time_ms=latency
                    ))
        return routes

    def get_recent_logs(self, container_name: Optional[str] = None, tail: int = 25) -> list[str]:
        """Tails recent stdout/stderr lines from a running Docker container."""
        if not shutil.which("docker"):
            return []
            
        containers = self.collect()
        running = [c for c in containers if c.is_running]
        if not running:
            return []
            
        target = container_name
        if not target:
            # Prefer web container (containing 'web', 'app', 'n8n', 'api') or first running
            web_candidates = [c for c in running if any(k in c.name.lower() for k in ("web", "app", "api", "n8n", "frontend"))]
            target = web_candidates[0].name if web_candidates else running[0].name

        try:
            res = subprocess.run(
                ["docker", "logs", "--tail", str(tail), target],
                capture_output=True,
                timeout=2
            )
            raw_bytes = (res.stdout or b"") + (b"\n" + res.stderr if res.stderr else b"")
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            # Filter clean lines
            lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
            return [f"[{target}] {line[:120]}" for line in lines[-tail:]]
        except Exception:
            return []

