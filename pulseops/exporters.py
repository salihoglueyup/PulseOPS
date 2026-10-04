"""Machine-readable outputs of `pulseops check`: Prometheus text format (node_exporter textfile collector)."""
import os
import tempfile
import time
from pathlib import Path

EXIT_CODE_HELP = "0=OK 1=WARNING 2=CRITICAL 3=UNKNOWN"


def _label_value(value: str) -> str:
    """Escaping required by the Prometheus text format inside "..."."""
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _labels(**labels) -> str:
    return "{" + ",".join(f'{k}="{_label_value(v)}"' for k, v in labels.items()) + "}"


class _Metrics:
    def __init__(self):
        self._order: list[str] = []
        self._meta: dict[str, tuple[str, str]] = {}
        self._samples: dict[str, list[str]] = {}

    def add(self, name: str, help_text: str, value, kind: str = "gauge", **labels) -> None:
        if value is None:
            return  # unknown is left out, never exported as 0
        if name not in self._meta:
            self._order.append(name)
            self._meta[name] = (help_text, kind)
            self._samples[name] = []
        if isinstance(value, bool):
            value = int(value)
        self._samples[name].append(f"{name}{_labels(**labels)} {value}")

    def render(self) -> str:
        out = []
        for name in self._order:
            help_text, kind = self._meta[name]
            out.append(f"# HELP {name} {help_text}")
            out.append(f"# TYPE {name} {kind}")
            out.extend(self._samples[name])
        return "\n".join(out) + "\n"


def prometheus_text(results) -> str:
    """CheckResult list -> Prometheus exposition text. Labels: target (as configured) and hostname."""
    m = _Metrics()
    now = int(time.time())
    for r in results:
        t = r.telemetry
        base = {"target": r.target, "hostname": t.snapshot.hostname if t else ""}
        m.add("pulseops_up", "1 if the host could be reached and probed", int(t is not None), **base)
        m.add("pulseops_check_state", f"Check result ({EXIT_CODE_HELP})", r.code, **base)
        m.add("pulseops_last_check_timestamp_seconds", "Unix time of this check", now, **base)
        if t is None:
            continue
        sec = t.security
        m.add("pulseops_score", "Health and security score (0-100)", r.score, **base)
        m.add("pulseops_alerts", "Active alerts", len(r.alerts), **base)
        m.add("pulseops_security_changes", "New security changes since the previous check", len(r.changes), **base)
        m.add("pulseops_cpu_percent", "CPU usage", round(t.snapshot.cpu.total_percent, 2), **base)
        m.add("pulseops_memory_percent", "Memory usage", round(t.snapshot.memory.percent, 2), **base)
        for d in t.snapshot.disks:
            m.add("pulseops_disk_used_percent", "Filesystem usage", round(d.percent, 2), mountpoint=d.mountpoint, **base)
        if sec.updates.known:
            m.add("pulseops_pending_updates", "Pending package updates", sec.updates.total, **base)
            m.add("pulseops_security_updates", "Pending security updates", sec.updates.security, **base)
        m.add("pulseops_reboot_required", "1 if a reboot is needed to apply updates", sec.updates.reboot_required, **base)
        if sec.hardening.known:
            for severity in ("HIGH", "MEDIUM", "LOW"):
                m.add("pulseops_hardening_failed_checks", "Failed hardening checks",
                      sum(1 for c in sec.hardening.failed if c.severity == severity), severity=severity.lower(), **base)
        m.add("pulseops_risky_containers", "Containers with a host-takeover risk",
              sum(1 for c in t.containers if c.security and any(x.severity == "HIGH" for x in c.security.risks))
              if t.privileges.docker_access else None, **base)
        if sec.auth.known:
            m.add("pulseops_ssh_failed_logins", "Failed SSH logins in the observed window", sec.auth.failed_total, **base)
        m.add("pulseops_firewall_active", "1 if the host firewall is active",
              sec.firewall_active if sec.firewall_known else None, **base)
        m.add("pulseops_exposed_risky_ports", "Risky ports reachable from outside", len(sec.exposed_risky_ports), **base)
    return m.render()


def write_atomic(path: Path, content: str) -> None:
    """Writes via a temp file + rename so a scraper never reads a half-written file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
