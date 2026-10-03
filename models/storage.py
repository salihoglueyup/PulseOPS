from pydantic import BaseModel, Field

class StorageItem(BaseModel):
    name: str                       # e.g. "BuildKit Cache", "Docker Images", "Writable Containers", "Local Volumes"
    total_bytes: int = 0
    total_human: str = "0 B"
    reclaimable_bytes: int = 0
    reclaimable_human: str = "0 B"
    reclaimable_percent: float = 0.0
    is_critical: bool = False
    details: str = ""

class ContainerdSnapshotGroup(BaseModel):
    count: int = 1
    size_human: str = "0 B"
    inodes: int = 0
    state: str = "Active"           # "Active" (writable/locked) or "Committed" (read-only)
    note: str = ""

class StorageOverview(BaseModel):
    root_used_gb: float = 0.0
    root_total_gb: float = 0.0
    root_percent: float = 0.0
    containerd_overlayfs_human: str = "0 B"
    buildkit_cache_human: str = "0 B"
    total_reclaimable_human: str = "0 B"
    items: list[StorageItem] = Field(default_factory=list)
    snapshot_groups: list[ContainerdSnapshotGroup] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    is_cache_bloated: bool = False  # True if BuildKit > 10GB or reclaimable > 20GB
