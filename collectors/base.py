from abc import ABC
from typing import Tuple
from models.system import SystemSnapshot
from models.ports import ListeningPort
from models.proxy import ProxyRoute
from models.backup import BackupTask
from models.docker import ContainerSummary

from collectors.system_collector import SystemCollector
from collectors.port_collector import PortCollector
from collectors.nginx_parser import NginxParser
from collectors.backup_collector import BackupCollector
from collectors.docker_collector import DockerCollector
from collectors.mock_collector import MockCollector

def read_machine_id() -> str:
    """This machine's systemd/dbus machine id, the identity used for local history."""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path, encoding="ascii") as f:
                value = f.read().strip()
            if len(value) >= 16:
                return value
        except OSError:
            continue
    return ""


class BaseCollector(ABC):
    """Abstract collector. `collect()` is the single entry point used by the TUI and the CLI.

    Legacy collectors implement `poll()` + `poll_*()`; the default `collect()` assembles them and
    caches the slow parts between `include_slow=True` refreshes.
    """

    def collect(self, include_slow: bool = True, include_logs: bool = True):
        import time
        from models.telemetry import Telemetry

        snapshot, ports, routes, backups, containers = self.poll()
        now = time.time()
        cache = getattr(self, "_slow_cache", None)
        if include_slow or cache is None:
            backup_data = self.poll_backup_data()
            cache = {
                "backup_data": backup_data,
                "backups": backup_data.tasks or backups,
                "services": self.poll_services(),
                "databases": self.poll_databases(ports, containers),
                "security": self.poll_security(ports),
                "storage": self.poll_storage(),
                "privileges": self.poll_privileges(),
                "slow_collected_at": now,
            }
            self._slow_cache = cache
        if include_logs or not hasattr(self, "_last_logs"):
            self._last_logs = self.poll_logs()
        return Telemetry(
            snapshot=snapshot,
            ports=ports,
            routes=routes,
            containers=containers,
            logs=self._last_logs,
            machine_id=self.machine_id(),
            collected_at=now,
            **cache,
        )

    def machine_id(self) -> str:
        return read_machine_id()

    def poll(self) -> Tuple[SystemSnapshot, list[ListeningPort], list[ProxyRoute], list[BackupTask], list[ContainerSummary]]:
        raise NotImplementedError

    def poll_logs(self) -> list[str]:
        return []

    def close(self) -> None:
        pass

    def poll_backup_data(self):
        """Returns comprehensive BackupData including snapshots and retention audit."""
        from models.backup import BackupData
        return BackupData()

    def poll_services(self):
        return []

    def poll_databases(self, ports, containers):
        return []

    def poll_security(self, ports):
        from models.security import SecurityOverview
        return SecurityOverview()

    def poll_storage(self):
        from models.storage import StorageOverview
        return StorageOverview()

    def poll_privileges(self):
        from models.privileges import PrivilegeInfo
        return PrivilegeInfo()

class LocalLiveCollector(BaseCollector):
    """Collects actual data from the local host system."""

    def __init__(self):
        from collectors.service_collector import ServiceCollector
        from collectors.db_collector import DatabaseCollector
        from collectors.security_collector import SecurityCollector
        from collectors.storage_collector import StorageCollector

        self.system = SystemCollector()
        self.ports = PortCollector()
        self.nginx = NginxParser()
        self.backup = BackupCollector()
        self.docker = DockerCollector()
        self.services = ServiceCollector()
        self.db = DatabaseCollector()
        self.security = SecurityCollector()
        self.storage = StorageCollector()
        self._privileges = None
        from collectors.log_collector import LogCollector
        self._log_collector = LogCollector()

    def poll_logs(self) -> list[str]:
        return self._log_collector.poll_live()

    def poll(self) -> Tuple[SystemSnapshot, list[ListeningPort], list[ProxyRoute], list[BackupTask], list[ContainerSummary]]:
        snapshot = self.system.collect_snapshot()
        listening_ports = self.ports.collect_local()
        
        # Nginx routes from /etc/nginx
        routes = self.nginx.collect_from_filesystem()
        routes = self.nginx.enrich_routes_with_ports(routes, listening_ports)
        
        backup_tasks = self.backup.collect_local()
        containers = self.docker.collect()
        
        # If Nginx routes are absent or to supplement container microservices
        if containers:
            docker_routes = self.docker.get_container_routes(containers)
            # Combine without duplicating ports
            existing_ports = {r.listen_port for r in routes}
            for dr in docker_routes:
                if dr.listen_port not in existing_ports:
                    routes.append(dr)
        
        return snapshot, listening_ports, routes, backup_tasks, containers

    def poll_backup_data(self):
        return self.backup.collect_backup_data()

    def poll_services(self):
        return self.services.collect_local()

    def poll_databases(self, ports, containers):
        return self.db.discover_databases(ports, containers)

    def poll_security(self, ports):
        return self.security.collect_local(ports)

    def poll_storage(self):
        return self.storage.collect_local()

    def poll_privileges(self):
        from collectors.privilege_collector import collect_local_privileges
        if self._privileges is None:
            self._privileges = collect_local_privileges()
        return self._privileges

class DemoCollector(BaseCollector):
    """Provides simulated realistic server telemetry for demonstration and UI testing."""

    def __init__(self):
        self.mock = MockCollector()
        from collectors.log_collector import LogCollector
        self._log_collector = LogCollector()

    def poll_logs(self) -> list[str]:
        return self._log_collector.poll_mock()

    def machine_id(self) -> str:
        return "demo-0000000000000000"

    def poll(self) -> Tuple[SystemSnapshot, list[ListeningPort], list[ProxyRoute], list[BackupTask], list[ContainerSummary]]:
        snapshot = self.mock.get_snapshot()
        ports = self.mock.get_listening_ports()
        routes = self.mock.get_proxy_routes()
        backups = self.mock.get_backup_tasks()
        containers = self.mock.get_containers()
        return snapshot, ports, routes, backups, containers

    def poll_backup_data(self):
        return self.mock.get_backup_data()

    def poll_services(self):
        return self.mock.get_services()

    def poll_databases(self, ports, containers):
        return self.mock.get_databases()

    def poll_security(self, ports):
        return self.mock.get_security()

    def poll_storage(self):
        return self.mock.get_storage()


def create_local_collector(use_sudo: bool = True) -> BaseCollector:
    """Linux: the shared shell probe (same code path as SSH). Elsewhere: the psutil-based collector."""
    import platform

    if platform.system() == "Linux":
        from collectors.probe_collector import ProbeCollector
        from collectors.transport import LocalTransport

        return ProbeCollector(LocalTransport(), use_sudo=use_sudo)
    return LocalLiveCollector()
