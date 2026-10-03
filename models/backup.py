from enum import Enum
from typing import Optional
from pydantic import BaseModel

class BackupStatus(str, Enum):
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    RUNNING = "RUNNING"
    UNKNOWN = "UNKNOWN"

class BackupTask(BaseModel):
    name: str
    mechanism: str                    # systemd-timer, cron, restic, borg, script
    schedule: str                     # "Every day at 03:00", "hourly", etc.
    last_run: str | None = None
    status: BackupStatus = BackupStatus.UNKNOWN
    exit_code: int | None = None
    target_path: str | None = None

    @property
    def badge(self) -> str:
        if self.status == BackupStatus.SUCCESS:
            return "[bold #3fb950]BAŞARILI ✓[/bold #3fb950]"
        elif self.status == BackupStatus.FAILED:
            return "[bold #ffffff on #da3633] HATA ALDI ✗ [/bold #ffffff on #da3633]"
        elif self.status == BackupStatus.RUNNING:
            return "[bold #d29922]ÇALIŞIYOR...[/bold #d29922]"
        return "[#6e7681]BİLİNMİYOR[/#6e7681]"

class BackupSnapshot(BaseModel):
    """Represents a discrete state dump or deployment snapshot (e.g. store-20260929-160647.json)."""
    filename: str
    timestamp_str: str                # e.g. "2026-09-29 16:06:47"
    age_days: float                   # e.g. 1.2
    age_human: str                    # e.g. "Dün 16:06" or "36 gün önce"
    size_bytes: int = 0
    size_human: str = "0 KB"
    kind: str = "JSON Store Snapshot"
    is_stale_warning: bool = False    # True if > 30 days old

class DeploymentState(BaseModel):
    """Tracks deploy commit hashes for rollback visibility."""
    last_deploy_sha: Optional[str] = None
    prev_deploy_sha: Optional[str] = None
    last_deploy_time: Optional[str] = None

    @property
    def has_rollback_target(self) -> bool:
        return bool(self.prev_deploy_sha and self.prev_deploy_sha != self.last_deploy_sha)

class BackupRetentionAudit(BaseModel):
    """Audit analysis of snapshot age, total disk footprint, and retention recommendations."""
    total_snapshots: int = 0
    total_size_human: str = "0 MB"
    oldest_snapshot_date: Optional[str] = None
    newest_snapshot_date: Optional[str] = None
    days_span: int = 0
    files_older_than_30d: int = 0
    retention_status: str = "SAĞLIKLI"
    risk_level: str = "NORMAL"
    recommendation: str = "Snapshot saklama politikası iyi durumda."

class BackupData(BaseModel):
    """Aggregate payload for the Backup & Snapshot observability module."""
    tasks: list[BackupTask] = []
    snapshots: list[BackupSnapshot] = []
    deployment: DeploymentState = DeploymentState()
    retention: BackupRetentionAudit = BackupRetentionAudit()

