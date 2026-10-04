from pydantic import BaseModel, Field

from pulseops.models.system import SystemSnapshot
from pulseops.models.ports import ListeningPort
from pulseops.models.proxy import ProxyRoute
from pulseops.models.backup import BackupTask, BackupData
from pulseops.models.docker import ContainerSummary
from pulseops.models.services import ServiceUnit
from pulseops.models.database import DatabaseInstance
from pulseops.models.security import SecurityOverview
from pulseops.models.storage import StorageOverview
from pulseops.models.privileges import PrivilegeInfo


class Telemetry(BaseModel):
    """A complete, single-poll picture of a host collected by any collector."""

    snapshot: SystemSnapshot
    ports: list[ListeningPort] = Field(default_factory=list)
    routes: list[ProxyRoute] = Field(default_factory=list)
    backups: list[BackupTask] = Field(default_factory=list)
    backup_data: BackupData = Field(default_factory=BackupData)
    containers: list[ContainerSummary] = Field(default_factory=list)
    services: list[ServiceUnit] = Field(default_factory=list)
    databases: list[DatabaseInstance] = Field(default_factory=list)
    security: SecurityOverview = Field(default_factory=SecurityOverview)
    storage: StorageOverview = Field(default_factory=StorageOverview)
    privileges: PrivilegeInfo = Field(default_factory=PrivilegeInfo)
    logs: list[str] = Field(default_factory=list)
    # Stable identity of the observed machine (/etc/machine-id), shared by every way of reaching it
    machine_id: str = ""
    # Unix timestamps of this poll and of the last refresh of the slow tier (services, docker...)
    collected_at: float = 0.0
    slow_collected_at: float = 0.0
