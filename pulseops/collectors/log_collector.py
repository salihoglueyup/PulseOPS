import time
import random
from collections import deque
from pathlib import Path
from typing import Deque

SAMPLE_LOG_PATTERNS = [
    ("GET", "/api/v1/health", 200, "1.2ms", "api.sirket-ana.com"),
    ("GET", "/urunler/liste", 200, "8.4ms", "sirket-ana.com"),
    ("POST", "/api/v1/auth/login", 200, "24.1ms", "api.sirket-ana.com"),
    ("GET", "/static/css/main.css", 304, "0.8ms", "sirket-ana.com"),
    ("GET", "/wp-login.php", 404, "1.5ms", "sirket-ana.com [GÜVENLİK ENGELİ]"),
    ("POST", "/api/v1/odemeler/webhook", 200, "12.7ms", "api.sirket-ana.com"),
    ("GET", "/admin/dashboard", 200, "15.0ms", "yonetim.sirket-ana.com"),
    ("GET", "/feed", 200, "6.2ms", "blog.sirket-ana.com"),
]

def tail_lines(path: Path, count: int, max_bytes: int = 64 * 1024) -> list[str]:
    """Last `count` lines of a file without reading it whole (access logs can be gigabytes)."""
    with open(path, "rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        data = f.read().decode("utf-8", errors="replace")
    lines = data.splitlines()
    if size > max_bytes and lines:
        lines = lines[1:]  # first line is probably cut in half
    return lines[-count:]


class LogCollector:
    """Collects recent log entries or generates simulated web traffic for demo mode in corporate style."""

    def __init__(self, max_entries: int = 50):
        self.logs: Deque[str] = deque(maxlen=max_entries)

    def poll_mock(self) -> list[str]:
        """Appends 1-2 simulated log events per tick."""
        now_str = time.strftime("%H:%M:%S")
        method, path, status, latency, domain = random.choice(SAMPLE_LOG_PATTERNS)
        
        log_line = f"{now_str} {status} {method:<4} {path:<28} {latency:>6} ({domain})"
        self.logs.append(log_line)
        return list(self.logs)

    def poll_live(self) -> list[str]:
        """Tails /var/log/nginx/access.log, Docker container logs, or system logs."""
        # 1. Nginx log file
        nginx_log = Path("/var/log/nginx/access.log")
        if nginx_log.exists():
            try:
                return tail_lines(nginx_log, 35)
            except Exception:
                pass

        # 2. Docker container logs if Docker is running
        try:
            from pulseops.collectors.docker_collector import DockerCollector
            docker_logs = DockerCollector().get_recent_logs(tail=30)
            if docker_logs:
                return docker_logs
        except Exception:
            pass

        # 3. Informative fallback
        return [
            f"[#6f737a]{time.strftime('%H:%M:%S')}[/#6f737a] [#589df6]● Log Gözlemcisi Aktif[/#589df6] [#9da0a8](Nginx veya Docker erişim logu bekleniyor...)[/#9da0a8]"
        ]
