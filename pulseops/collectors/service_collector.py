import shutil
import subprocess
from pulseops.models.services import ServiceUnit, ServiceState

CRITICAL_SERVICES = [
    ("nginx.service", "Nginx Reverse Proxy"),
    ("docker.service", "Docker Container Engine"),
    ("postgresql.service", "PostgreSQL Database"),
    ("mysql.service", "MySQL / MariaDB"),
    ("redis-server.service", "Redis In-Memory Cache"),
    ("ssh.service", "OpenSSH Daemon"),
    ("ufw.service", "UFW Firewall"),
    ("cron.service", "Cron Scheduler"),
]

class ServiceCollector:
    """Discovers and inspects system services via systemd on Linux or native services."""

    def parse_systemctl_units(self, text: str, unit_files_text: str = "") -> list[ServiceUnit]:
        """Parses output from `systemctl list-units --type=service --all` and unit-files."""
        enabled_map: dict[str, str] = {}
        for line in unit_files_text.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[0].endswith(".service"):
                enabled_map[parts[0]] = parts[1]

        services: list[ServiceUnit] = []
        seen = set()

        for line in text.splitlines():
            line_str = line.strip()
            if not line_str or not line_str.startswith("●") and not ".service" in line_str:
                continue

            parts = line_str.lstrip("●* ").split()
            if len(parts) < 4:
                continue

            unit_name = parts[0]
            if not unit_name.endswith(".service"):
                continue

            # Load, Active, Sub
            active_state = parts[2].lower() if len(parts) > 2 else "unknown"
            sub_state = parts[3].lower() if len(parts) > 3 else "unknown"
            desc = " ".join(parts[4:]) if len(parts) > 4 else ""

            if active_state == "active" or sub_state == "running":
                state = ServiceState.RUNNING
            elif active_state == "failed":
                state = ServiceState.FAILED
            else:
                state = ServiceState.STOPPED

            enabled = enabled_map.get(unit_name, "static")

            # Check display name
            display_name = unit_name.replace(".service", "").title()
            for crit_name, crit_display in CRITICAL_SERVICES:
                if unit_name == crit_name or unit_name.startswith(crit_name.split(".")[0]):
                    display_name = crit_display
                    break

            services.append(ServiceUnit(
                name=unit_name,
                display_name=display_name,
                state=state,
                enabled=enabled,
                description=desc[:40],
            ))
            seen.add(unit_name)

        return services

    def collect_local(self) -> list[ServiceUnit]:
        """Collects service statuses on Linux or Windows."""
        if shutil.which("systemctl"):
            try:
                res1 = subprocess.run(
                    ["systemctl", "list-units", "--type=service", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                res2 = subprocess.run(
                    ["systemctl", "list-unit-files", "--type=service", "--no-pager"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                if res1.returncode == 0:
                    all_services = self.parse_systemctl_units(res1.stdout, res2.stdout if res2.returncode == 0 else "")
                    # Prioritize critical services
                    critical = [s for s in all_services if any(c[0].split('.')[0] in s.name for c in CRITICAL_SERVICES)]
                    other = [s for s in all_services if s not in critical]
                    return critical + other[:25]
            except Exception:
                pass

        # Windows fallback: query key services
        return self._collect_windows_services()

    def _collect_windows_services(self) -> list[ServiceUnit]:
        services: list[ServiceUnit] = []
        import psutil
        if hasattr(psutil, "win_service_iter"):
            try:
                priority_keywords = [
                    "docker", "wsl", "postgres", "mysql", "mariadb", "redis", "nginx", "apache",
                    "ssh", "sshd", "mongodb", "mssql", "sql", "defender", "mpssvc", "firewall",
                    "eventlog", "spooler", "bits", "w32time"
                ]
                all_win_services = list(psutil.win_service_iter())
                priority_list: list[ServiceUnit] = []
                other_list: list[ServiceUnit] = []

                for s in all_win_services:
                    try:
                        name = s.name()
                        display = s.display_name()
                        status = s.status()
                        start_type = s.start_type() if hasattr(s, "start_type") else "auto"
                        state = ServiceState.RUNNING if status == "running" else (
                            ServiceState.STOPPED if status == "stopped" else ServiceState.UNKNOWN
                        )
                        enabled = "enabled" if start_type in ("automatic", "auto") else "disabled"
                        unit = ServiceUnit(
                            name=f"{name}.service",
                            display_name=display or name,
                            state=state,
                            enabled=enabled,
                            description=display[:40] if display else name,
                        )
                        n_lower = name.lower()
                        d_lower = (display or "").lower()
                        if any(pk in n_lower or pk in d_lower for pk in priority_keywords):
                            priority_list.append(unit)
                        elif status == "running":
                            other_list.append(unit)
                    except Exception:
                        continue

                return priority_list + other_list[:max(0, 30 - len(priority_list))]
            except Exception:
                pass

        # Fallback if psutil win_service_iter fails
        win_targets = [
            ("Docker", "com.docker.service", "Docker Desktop Engine"),
            ("WSL", "WslService", "Windows Subsystem for Linux"),
            ("Spooler", "Spooler", "Yazdırma Biriktiricisi"),
            ("EventLog", "EventLog", "Windows Olay Günlüğü"),
            ("Defender", "WinDefend", "Microsoft Defender Virüsten Koruma"),
            ("Firewall", "mpssvc", "Windows Defender Güvenlik Duvarı"),
        ]
        for short_name, svc_name, desc in win_targets:
            state = ServiceState.RUNNING
            try:
                res = subprocess.run(
                    ["sc", "query", svc_name],
                    capture_output=True,
                    text=True,
                    timeout=1
                )
                if "RUNNING" in res.stdout:
                    state = ServiceState.RUNNING
                elif "STOPPED" in res.stdout:
                    state = ServiceState.STOPPED
                else:
                    state = ServiceState.UNKNOWN
            except Exception:
                state = ServiceState.UNKNOWN

            services.append(ServiceUnit(
                name=f"{svc_name}.service",
                display_name=desc,
                state=state,
                enabled="enabled" if state == ServiceState.RUNNING else "disabled",
                description=desc,
            ))
        return services
