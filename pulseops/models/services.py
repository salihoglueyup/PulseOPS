from enum import Enum
from pydantic import BaseModel

class ServiceState(str, Enum):
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"

class ServiceUnit(BaseModel):
    name: str                 # e.g. "nginx.service"
    display_name: str         # e.g. "Nginx Reverse Proxy"
    state: ServiceState = ServiceState.UNKNOWN
    enabled: str = "unknown"  # "enabled", "disabled", "static"
    description: str = ""
    active_since: str = ""

    @property
    def badge(self) -> str:
        if self.state == ServiceState.RUNNING:
            return "[bold #3fb950]● RUNNING[/bold #3fb950]"
        elif self.state == ServiceState.FAILED:
            return "[bold #ffffff on #da3633] ● FAILED [/bold #ffffff on #da3633]"
        elif self.state == ServiceState.STOPPED:
            return "[#6e7681]○ STOPPED[/#6e7681]"
        return "[#484f58]UNKNOWN[/#484f58]"
