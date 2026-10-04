from typing import Optional

from pydantic import BaseModel, Field

# Host paths whose bind mount gives a container control over the host
SENSITIVE_MOUNTS = ("/", "/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/var/lib/docker", "/home", "/run")
DANGEROUS_CAPS = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_READ_SEARCH", "NET_ADMIN", "SYS_RAWIO",
                  "BPF", "PERFMON"}


class ContainerRisk(BaseModel):
    severity: str      # HIGH, MEDIUM, LOW
    text: str


class ContainerSecurity(BaseModel):
    user: str = ""                 # "" = root (image default)
    privileged: bool = False
    network_mode: str = ""
    pid_mode: str = ""
    cap_add: list[str] = Field(default_factory=list)
    restart_count: int = 0
    health: str = ""               # healthy, unhealthy, starting, "" (no healthcheck)
    mounts: list[tuple[str, str, bool]] = Field(default_factory=list)   # (source, destination, read-write)
    read_only_root: bool = False

    @property
    def runs_as_root(self) -> bool:
        return self.user.split(":")[0] in ("", "0", "root")

    @property
    def risks(self) -> list[ContainerRisk]:
        risks = []
        if self.privileged:
            risks.append(ContainerRisk(severity="HIGH", text="--privileged (host'a tam erişim)"))
        for source, dest, rw in self.mounts:
            if source.endswith("docker.sock") or source.endswith("containerd.sock"):
                risks.append(ContainerRisk(severity="HIGH", text=f"Docker soketi bağlı ({dest}): host'ta root"))
            elif source.rstrip("/") in SENSITIVE_MOUNTS or source == "/":
                risks.append(ContainerRisk(severity="HIGH" if rw else "MEDIUM",
                                           text=f"Host dizini bağlı: {source} -> {dest}" + (" (yazılabilir)" if rw else "")))
        caps = sorted({c.upper().removeprefix("CAP_") for c in self.cap_add} & DANGEROUS_CAPS)
        if caps:
            risks.append(ContainerRisk(severity="HIGH" if {"ALL", "SYS_ADMIN", "SYS_MODULE"} & set(caps) else "MEDIUM",
                                       text="Tehlikeli yetenek: " + ", ".join(caps)))
        if self.pid_mode == "host":
            risks.append(ContainerRisk(severity="MEDIUM", text="Host PID ad alanı (--pid=host)"))
        if self.network_mode == "host":
            risks.append(ContainerRisk(severity="MEDIUM", text="Host ağı (--network=host)"))
        if self.runs_as_root:
            risks.append(ContainerRisk(severity="LOW", text="root kullanıcısıyla çalışıyor"))
        return risks


class ContainerSummary(BaseModel):
    id: str
    name: str
    image: str
    status: str                       # Up 2 hours, Exited (0) 5 minutes ago, etc.
    ports: list[str] = Field(default_factory=list)
    uptime: str = ""
    security: Optional[ContainerSecurity] = None   # running containers, when docker inspect was readable

    @property
    def is_running(self) -> bool:
        return self.status.lower().startswith("up")

    @property
    def status_badge(self) -> str:
        if self.is_running:
            return "[bold green]ÇALIŞIYOR ✓[/bold green]"
        return "[dim red]DURDU[/dim red]"
