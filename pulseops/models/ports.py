from enum import Enum
from pydantic import BaseModel

class PortExposure(str, Enum):
    SAFE_INTERNAL = "SAFE_INTERNAL"       # 127.0.0.1 or ::1
    LAN_ONLY = "LAN_ONLY"                 # 192.168.x.x, 10.x.x.x, 172.16-31.x.x
    PUBLIC_WEB = "PUBLIC_WEB"             # 80, 443, 8080, 8443
    ADMIN_SSH = "ADMIN_SSH"               # 22
    EXPOSED_RISK = "EXPOSED_RISK"         # 0.0.0.0 on db, smb, rpc, or sensitive ports
    SYSTEM_RPC = "SYSTEM_RPC"             # Dynamic high RPC sockets (49152+)
    EXPOSED_GENERAL = "EXPOSED_GENERAL"   # 0.0.0.0 on general apps

class ListeningPort(BaseModel):
    proto: str                            # tcp, udp
    ip: str                               # 0.0.0.0, 127.0.0.1, ::
    port: int
    pid: int | None = None
    process_name: str | None = None
    service_name: str | None = None       # PostgreSQL, Redis, SMB, Web, etc.
    exposure: PortExposure = PortExposure.SAFE_INTERNAL

    def is_safe(self) -> bool:
        return self.exposure in (
            PortExposure.SAFE_INTERNAL,
            PortExposure.LAN_ONLY,
            PortExposure.PUBLIC_WEB,
            PortExposure.ADMIN_SSH,
            PortExposure.SYSTEM_RPC,
        )

    @property
    def status_label(self) -> str:
        if self.exposure == PortExposure.SAFE_INTERNAL:
            return "[#3fb950]● Dahili (Localhost) ✓[/#3fb950]"
        elif self.exposure == PortExposure.LAN_ONLY:
            return "[#58a6ff]● Yerel Ağ (LAN)[/#58a6ff]"
        elif self.exposure == PortExposure.PUBLIC_WEB:
            return "[#f0f6fc]● Web Servisi[/#f0f6fc]"
        elif self.exposure == PortExposure.ADMIN_SSH:
            return "[#d29922]● Yönetim SSH (22)[/#d29922]"
        elif self.exposure == PortExposure.SYSTEM_RPC:
            return "[#6e7681]○ Sistem Dinamik RPC[/#6e7681]"
        elif self.exposure == PortExposure.EXPOSED_GENERAL:
            return "[#e3b341]● Dışa Açık (0.0.0.0)[/#e3b341]"
        return "[bold #ffffff on #da3633] ⚠ DIŞ DÜNYAYA AÇIK! [/bold #ffffff on #da3633]"
