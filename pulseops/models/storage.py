from typing import Optional

from pydantic import BaseModel, Field


def human_bytes(n: Optional[float]) -> str:
    """1536 -> '1.5 KB' (binary units, the way df -h and du -h count)."""
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


class StorageItem(BaseModel):
    """One row of `docker system df`."""

    name: str                       # Images, Containers, Local Volumes, Build Cache
    total_bytes: int = 0
    reclaimable_bytes: int = 0
    reclaimable_percent: float = 0.0
    count: Optional[int] = None
    active: Optional[int] = None
    is_critical: bool = False

    @property
    def total_human(self) -> str:
        return human_bytes(self.total_bytes)

    @property
    def reclaimable_human(self) -> str:
        return human_bytes(self.reclaimable_bytes)

    @property
    def details(self) -> str:
        if self.count is None:
            return ""
        return f"{self.active if self.active is not None else '?'}/{self.count} aktif"


class FileUsage(BaseModel):
    path: str
    bytes: int


class DeletedOpenFile(BaseModel):
    """A file that was deleted but is still held open: its space is freed only when the process lets go."""

    pid: int
    process: str
    path: str
    bytes: int


# Mounts that must be writable on a healthy server; a read-only one here means disk/filesystem errors
CRITICAL_RW_MOUNTS = ("/", "/var", "/var/lib", "/var/log", "/home", "/srv", "/tmp", "/opt")


class StorageOverview(BaseModel):
    # Root filesystem (filled from the disk list)
    root_used_gb: float = 0.0
    root_total_gb: float = 0.0
    root_percent: float = 0.0

    # Docker
    items: list[StorageItem] = Field(default_factory=list)
    buildkit_cache_bytes: int = 0
    containerd_bytes: Optional[int] = None
    is_cache_bloated: bool = False  # BuildKit cache > 10 GB

    # Filesystem health (STORAGE probe section; refreshed every 10 minutes)
    known: bool = False
    complete: bool = False          # root/sudo: other users' files and processes are included
    inode_percent: dict[str, float] = Field(default_factory=dict)
    read_only_mounts: list[str] = Field(default_factory=list)
    journal_bytes: Optional[int] = None
    var_log_bytes: Optional[int] = None
    big_logs: list[FileUsage] = Field(default_factory=list)
    docker_logs: list[FileUsage] = Field(default_factory=list)
    deleted_open: list[DeletedOpenFile] = Field(default_factory=list)
    top_dirs: list[FileUsage] = Field(default_factory=list)
    top_dirs_partial: bool = False

    # Trend from the local history (None: not enough samples, or usage is not growing)
    forecast_days: Optional[float] = None
    growth_percent_per_day: Optional[float] = None

    recommendations: list[str] = Field(default_factory=list)

    @property
    def docker_reclaimable_bytes(self) -> int:
        return sum(i.reclaimable_bytes for i in self.items)

    @property
    def deleted_open_bytes(self) -> int:
        return sum(f.bytes for f in self.deleted_open)

    @property
    def docker_log_bytes(self) -> int:
        return sum(f.bytes for f in self.docker_logs)

    @property
    def critical_read_only(self) -> list[str]:
        return [m for m in self.read_only_mounts if m in CRITICAL_RW_MOUNTS]

    # Display helpers kept for the report and older call sites
    @property
    def buildkit_cache_human(self) -> str:
        return human_bytes(self.buildkit_cache_bytes)

    @property
    def containerd_overlayfs_human(self) -> str:
        return human_bytes(self.containerd_bytes) if self.containerd_bytes is not None else "-"

    @property
    def total_reclaimable_human(self) -> str:
        return human_bytes(self.docker_reclaimable_bytes + self.deleted_open_bytes)
