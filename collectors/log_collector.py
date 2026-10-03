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

class LogCollector:
    """Collects recent log entries or generates simulated web traffic for demo mode in corporate style."""

    def __init__(self, max_entries: int = 50):
        self.logs: Deque[str] = deque(maxlen=max_entries)

    def poll_mock(self) -> list[str]:
        """Appends 1-2 simulated log events per tick."""
        now_str = time.strftime("%H:%M:%S")
        method, path, status, latency, domain = random.choice(SAMPLE_LOG_PATTERNS)
        
        status_color = "#57a773" if status < 400 else "bold #e05353"
        log_line = (
            f"[#6f737a]{now_str}[/#6f737a] "
            f"[{status_color}]{status}[/{status_color}] "
            f"[bold #589df6]{method:<4}[/bold #589df6] "
            f"[#dfe1e5]{path:<28}[/#dfe1e5] "
            f"[#9da0a8]{latency:>6}[/#9da0a8] "
            f"[#6f737a]({domain})[/#6f737a]"
        )
        self.logs.append(log_line)
        return list(self.logs)

    def poll_live(self) -> list[str]:
        """Tails /var/log/nginx/access.log, Docker container logs, or system logs."""
        # 1. Nginx log file
        nginx_log = Path("/var/log/nginx/access.log")
        if nginx_log.exists():
            try:
                lines = nginx_log.read_text(encoding="utf-8", errors="ignore").splitlines()
                return lines[-35:]
            except Exception:
                pass

        # 2. Docker container logs if Docker is running
        try:
            from collectors.docker_collector import DockerCollector
            docker_logs = DockerCollector().get_recent_logs(tail=30)
            if docker_logs:
                return docker_logs
        except Exception:
            pass

        # 3. Informative fallback
        return [
            f"[#6f737a]{time.strftime('%H:%M:%S')}[/#6f737a] [#589df6]● Log Gözlemcisi Aktif[/#589df6] [#9da0a8](Nginx veya Docker erişim logu bekleniyor...)[/#9da0a8]"
        ]
