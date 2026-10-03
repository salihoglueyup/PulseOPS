from typing import Optional
from pydantic import BaseModel

class DatabaseInstance(BaseModel):
    engine: str               # "PostgreSQL", "MySQL", "MariaDB", "Redis", "MongoDB"
    version: str = "Unknown"  # e.g. "16.2", "8.0", "7.2"
    port: int
    status: str = "RUNNING"   # "RUNNING", "STOPPED"
    bind_ip: str = "127.0.0.1"
    is_external_open: bool = False  # True if 0.0.0.0 / :: / *
    metric_summary: str = ""  # e.g. "Connections: 18 | DBs: 6" or "RAM: 142 MB | Clients: 8"
    process_pid: Optional[int] = None
    managed_by: str = "Native Service"  # "Native Service", "Docker Container"

    @property
    def badge(self) -> str:
        if self.status == "RUNNING":
            return "[bold #3fb950]● RUNNING[/bold #3fb950]"
        return "[#6e7681]○ STOPPED[/#6e7681]"

    @property
    def security_badge(self) -> str:
        if self.is_external_open:
            return "[bold #ffffff on #da3633] ⚠ Dış Dünyaya Açık! [/bold #ffffff on #da3633]"
        return "[bold #3fb950]Dahili (127.0.0.1) ✓[/bold #3fb950]"
