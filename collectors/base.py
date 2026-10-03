from abc import ABC, abstractmethod
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

class BaseCollector(ABC):
    """Abstract collector providing standard snapshot retrieval."""

    @abstractmethod
    def poll(self) -> Tuple[SystemSnapshot, list[ListeningPort], list[ProxyRoute], list[BackupTask], list[ContainerSummary]]:
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
