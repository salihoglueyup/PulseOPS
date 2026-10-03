from pydantic import BaseModel, Field

class CpuMetric(BaseModel):
    cores: int
    total_percent: float
    per_core_percent: list[float] = Field(default_factory=list)
    load_avg: tuple[float, float, float] = (0.0, 0.0, 0.0)

class MemoryMetric(BaseModel):
    total_bytes: int
    used_bytes: int
    free_bytes: int
    available_bytes: int
    percent: float
    swap_total_bytes: int = 0
    swap_used_bytes: int = 0
    swap_percent: float = 0.0

    @property
    def total_gb(self) -> float:
        return round(self.total_bytes / (1024**3), 2)

    @property
    def used_gb(self) -> float:
        return round(self.used_bytes / (1024**3), 2)

class DiskPartition(BaseModel):
    device: str
    mountpoint: str
    fstype: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    percent: float

    @property
    def total_gb(self) -> float:
        return round(self.total_bytes / (1024**3), 1)

    @property
    def used_gb(self) -> float:
        return round(self.used_bytes / (1024**3), 1)

class NetworkRate(BaseModel):
    interface: str
    rx_bytes_sec: float = 0.0
    tx_bytes_sec: float = 0.0

    @property
    def rx_human(self) -> str:
        if self.rx_bytes_sec > 1024 * 1024:
            return f"{self.rx_bytes_sec / (1024 * 1024):.1f} MB/s"
        return f"{self.rx_bytes_sec / 1024:.1f} KB/s"

    @property
    def tx_human(self) -> str:
        if self.tx_bytes_sec > 1024 * 1024:
            return f"{self.tx_bytes_sec / (1024 * 1024):.1f} MB/s"
        return f"{self.tx_bytes_sec / 1024:.1f} KB/s"

class DiskIoRate(BaseModel):
    read_bytes_sec: float = 0.0
    write_bytes_sec: float = 0.0

    @property
    def read_human(self) -> str:
        if self.read_bytes_sec > 1024 * 1024:
            return f"{self.read_bytes_sec / (1024 * 1024):.1f} MB/s"
        return f"{self.read_bytes_sec / 1024:.1f} KB/s"

    @property
    def write_human(self) -> str:
        if self.write_bytes_sec > 1024 * 1024:
            return f"{self.write_bytes_sec / (1024 * 1024):.1f} MB/s"
        return f"{self.write_bytes_sec / 1024:.1f} KB/s"

class FirewallStatus(BaseModel):
    is_active: bool = True
    backend: str = "UFW"
    summary: str = "Aktif (22, 80, 443 izinli)"

    @property
    def badge(self) -> str:
        if self.is_active:
            return "[bold green]UFW AKTİF ✓[/bold green]"
        return "[bold red]⚠️ UFW DEVRE DIŞI![/bold red]"

class ProcessInfo(BaseModel):
    pid: int
    name: str
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    memory_percent: float = 0.0
    username: str = ""

class SystemSnapshot(BaseModel):
    hostname: str
    os_name: str
    kernel: str
    uptime_seconds: float
    cpu: CpuMetric
    memory: MemoryMetric
    disks: list[DiskPartition] = Field(default_factory=list)
    network: list[NetworkRate] = Field(default_factory=list)
    top_processes: list[ProcessInfo] = Field(default_factory=list)
    disk_io: DiskIoRate = Field(default_factory=DiskIoRate)
    firewall: FirewallStatus = Field(default_factory=FirewallStatus)
    timestamp: float

    @property
    def uptime_human(self) -> str:
        days = int(self.uptime_seconds // 86400)
        hours = int((self.uptime_seconds % 86400) // 3600)
        minutes = int((self.uptime_seconds % 3600) // 60)
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        return f"{hours}h {minutes}m"
