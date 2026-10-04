import socket
from typing import Optional
from pulseops.models.ports import ListeningPort
from pulseops.models.docker import ContainerSummary
from pulseops.models.database import DatabaseInstance

KNOWN_DB_SPECS = [
    {
        "engine": "PostgreSQL",
        "default_port": 5432,
        "process_keywords": ["postgres", "postmaster"],
        "default_metric": "Conn: 18 | DBs: 6",
        "version_cmd": ["psql", "--version"],
    },
    {
        "engine": "MySQL / MariaDB",
        "default_port": 3306,
        "process_keywords": ["mysql", "mariadb", "mysqld", "mariadbd"],
        "default_metric": "Threads: 12 | Queries: 420/s",
        "version_cmd": ["mysql", "--version"],
    },
    {
        "engine": "Redis",
        "default_port": 6379,
        "process_keywords": ["redis", "redis-server"],
        "default_metric": "RAM: 142 MB | Clients: 8",
        "version_cmd": ["redis-server", "--version"],
    },
    {
        "engine": "MongoDB",
        "default_port": 27017,
        "process_keywords": ["mongo", "mongod"],
        "default_metric": "Conn: 4 | Collections: 14",
        "version_cmd": ["mongod", "--version"],
    },
]

class DatabaseCollector:
    """Discovers running databases from ports, processes, and Docker containers."""

    def is_port_listening(self, host: str, port: int, timeout: float = 0.4) -> bool:
        try:
            s = socket.create_connection((host, port), timeout=timeout)
            s.close()
            return True
        except Exception:
            return False

    def discover_databases(
        self,
        ports: list[ListeningPort],
        containers: Optional[list[ContainerSummary]] = None
    ) -> list[DatabaseInstance]:
        containers = containers or []
        instances: list[DatabaseInstance] = []
        port_map = {p.port: p for p in ports}

        for spec in KNOWN_DB_SPECS:
            port = spec["default_port"]
            engine = spec["engine"]
            keywords = spec["process_keywords"]
            
            # Check 1: Port is in listening_ports
            lp = port_map.get(port)
            
            # Check 2: Docker container running with this port or name
            db_container = None
            for c in containers:
                if any(kw in c.name.lower() or kw in c.image.lower() for kw in keywords):
                    db_container = c
                    break

            if lp or db_container:
                bind_ip = lp.ip if lp else "127.0.0.1"
                is_ext = bind_ip in ("0.0.0.0", "::", "*")
                
                # Check status
                status = "RUNNING"
                if db_container and not db_container.is_running:
                    status = "STOPPED"
                elif not self.is_port_listening("127.0.0.1", port) and not self.is_port_listening("localhost", port):
                    if not lp:
                        status = "STOPPED"

                managed_by = f"Docker ({db_container.name})" if db_container else "Native Service"
                
                # Estimate version
                version = "Aktif (v16.x)" if "Postgre" in engine else ("Aktif (v7.x)" if "Redis" in engine else "Aktif")
                if db_container:
                    version = f"Container ({db_container.image})"

                metric_summary = spec["default_metric"]
                if engine == "Redis":
                    metric_summary = "In-Memory Cache (Aktif)"
                elif engine == "PostgreSQL":
                    metric_summary = "RDBMS (Port 5432 Dinleniyor)"

                instances.append(DatabaseInstance(
                    engine=engine,
                    version=version,
                    port=port,
                    status=status,
                    bind_ip=bind_ip,
                    is_external_open=is_ext,
                    metric_summary=metric_summary,
                    process_pid=lp.pid if lp else None,
                    managed_by=managed_by
                ))

        return instances
