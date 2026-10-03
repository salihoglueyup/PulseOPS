from pydantic import BaseModel, Field

from models.system import SystemSnapshot
from models.ports import ListeningPort
from models.proxy import ProxyRoute
from models.backup import BackupTask, BackupData
from models.docker import ContainerSummary
from models.services import ServiceUnit
from models.database import DatabaseInstance
from models.security import SecurityOverview
from models.storage import StorageOverview
from models.privileges import PrivilegeInfo


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
