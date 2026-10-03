"""Pure parsers for probe sections. No I/O, no state: everything stateful lives in ProbeCollector."""
import re
from typing import NamedTuple

from models.ports import ListeningPort
from models.system import DiskPartition, FirewallStatus, MemoryMetric
from collectors.port_collector import classify_exposure, get_service_hint


# --- host ---------------------------------------------------------------------------------------

def parse_host(text: str) -> tuple[str, str, str]:
    """-> (hostname, kernel, os_name)"""
    lines = [line.strip() for line in text.splitlines()]
    hostname = lines[0] if lines and lines[0] else "linux"
    kernel = lines[1] if len(lines) > 1 and lines[1] else "Linux"
    os_name = "Linux"
    for line in lines:
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip("\"'") or os_name
            break
    return hostname, kernel, os_name


def parse_uptime(text: str) -> float:
    try:
        return float(text.split()[0])
    except (IndexError, ValueError):
        return 0.0


def parse_loadavg(text: str) -> tuple[float, float, float]:
    parts = text.split()
    try:
        return float(parts[0]), float(parts[1]), float(parts[2])
    except (IndexError, ValueError):
        return 0.0, 0.0, 0.0


def parse_sysconf(text: str) -> tuple[int, int, int]:
    """-> (cpu cores, clock ticks per second, page size)"""
    values = []
    for line in text.splitlines():
        line = line.strip()
        values.append(int(line) if line.isdigit() else 0)
    values += [0, 0, 0]
    cores, clk, page = values[:3]
    return max(cores, 1), clk or 100, page or 4096


# --- cpu ----------------------------------------------------------------------------------------

def parse_cpustat(text: str) -> dict[str, tuple[int, int]]:
    """/proc/stat cpu lines -> {"cpu": (busy_jiffies, total_jiffies), "cpu0": ...}"""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if not parts or not parts[0].startswith("cpu"):
            continue
        try:
            values = [int(v) for v in parts[1:]]
        except ValueError:
            continue
        if len(values) < 4:
            continue
        # user nice system idle iowait irq softirq steal [guest guest_nice are already in user/nice]
        values = values[:8]
        idle = values[3] + (values[4] if len(values) > 4 else 0)
        total = sum(values)
        out[parts[0]] = (total - idle, total)
    return out


def cpu_percent(prev: tuple[int, int], cur: tuple[int, int]) -> float:
    busy = cur[0] - prev[0]
    total = cur[1] - prev[1]
    if total <= 0:
        return 0.0
    return round(max(0.0, min(100.0, busy * 100.0 / total)), 1)


# --- memory -------------------------------------------------------------------------------------

def parse_meminfo(text: str) -> MemoryMetric:
    kb: dict[str, int] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, rest = line.split(":", 1)
        parts = rest.split()
        if parts and parts[0].isdigit():
            kb[key.strip()] = int(parts[0]) * 1024

    total = kb.get("MemTotal", 0)
    free = kb.get("MemFree", 0)
    available = kb.get("MemAvailable")
    if available is None:  # kernels < 3.14
        available = free + kb.get("Buffers", 0) + kb.get("Cached", 0) + kb.get("SReclaimable", 0)
    used = max(total - available, 0)
    swap_total = kb.get("SwapTotal", 0)
    swap_used = max(swap_total - kb.get("SwapFree", 0), 0)
    return MemoryMetric(
        total_bytes=total,
        used_bytes=used,
        free_bytes=free,
        available_bytes=available,
        percent=round(used * 100.0 / total, 1) if total else 0.0,
        swap_total_bytes=swap_total,
        swap_used_bytes=swap_used,
        swap_percent=round(swap_used * 100.0 / swap_total, 1) if swap_total else 0.0,
    )


# --- disks --------------------------------------------------------------------------------------

def parse_df(text: str) -> list[DiskPartition]:
    """`df -P -T -B1` (or -k, detected from the header)."""
    lines = text.strip().splitlines()
    if not lines:
        return []
    multiplier = 1024 if "1024-blocks" in lines[0] else 1
    disks: list[DiskPartition] = []
    seen_devices = set()
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        device, fstype = parts[0], parts[1]
        try:
            total, used, avail = (int(parts[i]) * multiplier for i in (2, 3, 4))
        except ValueError:
            continue
        mount = " ".join(parts[6:])
        if total <= 0 or (device, mount) in seen_devices:
            continue
        seen_devices.add((device, mount))
        # Same formula as df's Capacity column: used / (used + available)
        denom = used + avail
        disks.append(DiskPartition(
            device=device,
            mountpoint=mount,
            fstype=fstype,
            total_bytes=total,
            used_bytes=used,
            free_bytes=avail,
            percent=round(used * 100.0 / denom, 1) if denom else 0.0,
        ))
    disks.sort(key=lambda d: (d.mountpoint != "/", d.mountpoint))
    return disks


_PARTITION = re.compile(r"^((sd|vd|xvd|hd)[a-z]+\d+|(nvme\d+n\d+|mmcblk\d+)p\d+)$")
_VIRTUAL = re.compile(r"^(loop|ram|zram|dm-|sr|md|fd|nbd)")


def parse_diskstats(text: str) -> tuple[int, int]:
    """/proc/diskstats -> cumulative (read_bytes, written_bytes) over physical whole disks."""
    read = written = 0
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        name = parts[2]
        if _VIRTUAL.match(name) or _PARTITION.match(name):
            continue
        try:
            read += int(parts[5]) * 512
            written += int(parts[9]) * 512
        except ValueError:
            continue
    return read, written


# --- network ------------------------------------------------------------------------------------

_SKIP_NIC = re.compile(r"^(lo|docker\d*|veth|br-|virbr|cni|flannel|cali|kube-ipvs)")


def parse_net_dev(text: str) -> dict[str, tuple[int, int]]:
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        nic, stats = line.split(":", 1)
        nic = nic.strip()
        if _SKIP_NIC.match(nic):
            continue
        parts = stats.split()
        if len(parts) >= 9:
            try:
                out[nic] = (int(parts[0]), int(parts[8]))
            except ValueError:
                continue
    return out


# --- processes ----------------------------------------------------------------------------------

class ProcSample(NamedTuple):
    ticks: int
    rss_pages: int
    name: str


def parse_procstat(text: str) -> dict[int, ProcSample]:
    """`<pid> <utime+stime ticks> <rss pages> <comm>` lines -> {pid: ProcSample}"""
    out = {}
    for line in text.splitlines():
        parts = line.split(None, 3)
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        try:
            rss = int(parts[2])
        except ValueError:
            continue
        out[int(parts[0])] = ProcSample(int(parts[1]), max(rss, 0), parts[3].strip() if len(parts) > 3 else "?")
    return out


def parse_procusers(text: str) -> dict[int, str]:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit():
            out[int(parts[0])] = parts[1]
    return out


# --- ports without ss/netstat ---------------------------------------------------------------------

def _hex_ipv4(h: str) -> str:
    b = bytes.fromhex(h)
    return ".".join(str(x) for x in reversed(b))


def _hex_ipv6(h: str) -> str:
    # 4 little-endian 32-bit words
    raw = b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))
    groups = [raw[i:i + 2].hex() for i in range(0, 16, 2)]
    import ipaddress
    return str(ipaddress.IPv6Address(":".join(groups)))


def parse_socket_owners(text: str) -> dict[str, int]:
    """`find /proc/*/fd -lname 'socket:*'` lines -> {socket inode: pid}"""
    owners: dict[str, int] = {}
    for line in text.splitlines():
        m = re.match(r"/proc/(\d+)/fd socket:\[(\d+)\]", line.strip())
        if m:
            owners.setdefault(m.group(2), int(m.group(1)))
    return owners


def parse_proc_net(text: str, inode_owner: dict[str, int], names: dict[int, str]) -> list[ListeningPort]:
    """Listening sockets from /proc/net/{tcp,tcp6,udp,udp6} dumps (each preceded by `#<table>`)."""
    table = None
    unique: dict[tuple[str, str, int], ListeningPort] = {}
    for line in text.splitlines():
        if line.startswith("#"):
            table = line[1:].strip()
            continue
        parts = line.split()
        if table is None or len(parts) < 10 or ":" not in parts[1]:
            continue
        proto = table.rstrip("6")
        # TCP LISTEN = 0A; unconnected UDP = 07
        if (proto == "tcp" and parts[3] != "0A") or (proto == "udp" and parts[3] != "07"):
            continue
        addr_hex, port_hex = parts[1].split(":")
        try:
            ip = _hex_ipv6(addr_hex) if table.endswith("6") else _hex_ipv4(addr_hex)
            port = int(port_hex, 16)
        except ValueError:
            continue
        pid = inode_owner.get(parts[9])
        name = names.get(pid) if pid is not None else None
        unique[(proto, ip, port)] = ListeningPort(
            proto=proto, ip=ip, port=port, pid=pid, process_name=name,
            service_name=get_service_hint(port, name), exposure=classify_exposure(ip, port, name),
        )
    return sorted(unique.values(), key=lambda p: (p.port, p.proto, p.ip))


def apply_port_owners(ports: list[ListeningPort], owners: dict[tuple[str, str, int], tuple[int, str]]) -> list[ListeningPort]:
    """Fills pid/process (and the owner-dependent classification) from the slow tier's `ss -p`."""
    out = []
    for p in ports:
        owner = owners.get((p.proto, p.ip, p.port))
        if owner and not p.process_name:
            pid, name = owner
            p = p.model_copy(update={
                "pid": pid,
                "process_name": name,
                "service_name": get_service_hint(p.port, name),
                "exposure": classify_exposure(p.ip, p.port, name),
            })
        out.append(p)
    return out


# --- firewall -----------------------------------------------------------------------------------

def parse_firewall(text: str) -> FirewallStatus:
    blocks: dict[str, str] = {}
    current = None
    for line in text.splitlines():
        if line.startswith("BACKEND:"):
            current = line[len("BACKEND:"):].strip()
            blocks[current] = ""
        elif current:
            blocks[current] += line + "\n"

    if not blocks:
        return FirewallStatus(is_active=False, backend="Yok", summary="Güvenlik duvarı aracı bulunamadı", known=True)

    unknown_backends = []

    ufw = blocks.get("ufw")
    if ufw is not None:
        low = ufw.lower()
        if "status: active" in low:
            rules = len(re.findall(r"^\s*\[\s*\d+\]", ufw, re.M))
            return FirewallStatus(is_active=True, backend="UFW", summary=f"Aktif ({rules} kural)", rules_count=rules)
        if "status: inactive" in low:
            return FirewallStatus(is_active=False, backend="UFW", summary="DEVRE DIŞI! (Tüm portlar filtrelenmemiş)")
        unknown_backends.append("UFW")

    firewalld = blocks.get("firewalld")
    if firewalld is not None:
        low = firewalld.strip().lower()
        if low == "running":
            return FirewallStatus(is_active=True, backend="firewalld", summary="Aktif (firewalld çalışıyor)")
        if "not running" in low:
            pass  # firewalld installed but stopped; iptables/nftables may still filter
        else:
            unknown_backends.append("firewalld")

    iptables = blocks.get("iptables")
    if iptables is not None:
        if iptables.strip() == "UNKNOWN" or not iptables.strip():
            unknown_backends.append("iptables")
        else:
            rules = [line for line in iptables.splitlines() if line.startswith("-A INPUT")]
            policy_drop = bool(re.search(r"^-P INPUT (DROP|REJECT)", iptables, re.M))
            if rules or policy_drop:
                summary = f"Aktif ({len(rules)} INPUT kuralı" + (", varsayılan DROP)" if policy_drop else ")")
                return FirewallStatus(is_active=True, backend="iptables", summary=summary, rules_count=len(rules))
            if "nftables" not in blocks:
                return FirewallStatus(is_active=False, backend="iptables",
                                      summary="DEVRE DIŞI! (INPUT zinciri boş, politika ACCEPT)")

    nft = blocks.get("nftables")
    if nft is not None:
        m = re.search(r"rules=(\d+) policy_drop=(\d)", nft)
        if not m:
            unknown_backends.append("nftables")
        else:
            rules, policy_drop = int(m.group(1)), m.group(2) == "1"
            if rules or policy_drop:
                return FirewallStatus(is_active=True, backend="nftables",
                                      summary=f"Aktif ({rules} input kuralı)", rules_count=rules)
            if not unknown_backends:
                return FirewallStatus(is_active=False, backend="nftables/iptables",
                                      summary="DEVRE DIŞI! (Gelen trafik filtrelenmiyor)")

    if unknown_backends:
        return FirewallStatus(
            is_active=False,
            backend="/".join(unknown_backends),
            summary="Bilinmiyor (okumak için root gerekli)",
            known=False,
        )
    return FirewallStatus(is_active=False, backend="Yok", summary="DEVRE DIŞI! (Etkin kural bulunamadı)")


# --- backups ------------------------------------------------------------------------------------

def parse_backup_files(text: str) -> tuple[list[str], dict[str, int], dict[str, str]]:
    """BACKUP_FILES section -> (snapshot file names, their sizes, {deploy sha file name: first line})."""
    names: list[str] = []
    sizes: dict[str, int] = {}
    shas: dict[str, str] = {}
    current_sha = None
    for line in text.splitlines():
        if line.startswith("SNAP "):
            parts = line.split(" ", 2)
            if len(parts) == 3 and parts[1].isdigit():
                name = parts[2].rsplit("/", 1)[-1]
                names.append(name)
                sizes[name] = int(parts[1])
            current_sha = None
        elif line.startswith("FILE:"):
            current_sha = line[len("FILE:"):].strip().rsplit("/", 1)[-1]
        elif current_sha and line.strip():
            shas[current_sha] = line.strip()
            current_sha = None
    return names, sizes, shas
