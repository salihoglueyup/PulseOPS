"""Pure parsers for probe sections. No I/O, no state: everything stateful lives in ProbeCollector."""
import datetime
import json
import re
from typing import NamedTuple

from models.ports import ListeningPort
from models.docker import ContainerSecurity
from models.security import (AccessAudit, AuthActivity, CountedItem, Fail2banJail, Fail2banStatus, HardeningAudit,
                             HardeningCheck, LoginEvent, UpdateStatus)
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

# Pseudo/ephemeral filesystems (the -k fallback cannot exclude them with -x)
_DF_SKIP_FSTYPES = {"tmpfs", "devtmpfs", "squashfs", "efivarfs", "proc", "sysfs", "devpts", "cgroup", "cgroup2"}
# Container runtimes' own mounts (one overlay per running container on a Docker host)
_DF_SKIP_PREFIXES = ("/var/lib/docker/", "/var/lib/containers/", "/run/containerd/", "/run/docker/", "/snap/")
# Single files bind-mounted into containers / LXC guests; they repeat the host disk under a bogus name
_DF_BIND_FILES = {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}


def parse_df(text: str) -> list[DiskPartition]:
    """`df -P -T -B1` (or -k, detected from the header).

    An overlay root (containers, LXC guests, live systems) is kept: it is the machine's `/`.
    """
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
        if fstype in _DF_SKIP_FSTYPES or mount in _DF_BIND_FILES or mount.startswith(_DF_SKIP_PREFIXES):
            continue
        if fstype == "overlay" and mount != "/":
            continue
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


# --- SOC: fail2ban, authentication activity, privileged access ------------------------------------

def _jail_value(text: str, label: str) -> str:
    m = re.search(rf"{re.escape(label)}:\s*(.*)", text)
    return m.group(1).strip() if m else ""


def parse_fail2ban(text: str) -> Fail2banStatus:
    lines = text.splitlines()
    if "INSTALLED" not in (line.strip() for line in lines):
        return Fail2banStatus(installed=False)
    running = True if "RUNNING" in text.split() else (False if "STOPPED" in text.split() else None)
    if any(line.strip() == "UNKNOWN" for line in lines):
        # Status could not be read: not running, or no permission for the fail2ban socket
        return Fail2banStatus(installed=True, running=running, known=running is False)

    jails = []
    for block in re.split(r"^#JAIL ", text, flags=re.M)[1:]:
        name = block.splitlines()[0].strip()
        ips = _jail_value(block, "Banned IP list").split()
        jails.append(Fail2banJail(
            name=name,
            currently_failed=int(_jail_value(block, "Currently failed") or 0),
            currently_banned=int(_jail_value(block, "Currently banned") or 0),
            total_banned=int(_jail_value(block, "Total banned") or 0),
            banned_ips=ips[:50],
        ))
    return Fail2banStatus(installed=True, running=True if jails or running is None else running, known=True, jails=jails)


def _epoch_or_text(stamp: str) -> str:
    if re.fullmatch(r"\d+\.\d+", stamp):
        return datetime.datetime.fromtimestamp(float(stamp)).strftime("%Y-%m-%d %H:%M")
    return stamp.replace("_", " ") if stamp != "-" else ""


def parse_auth(text: str) -> AuthActivity:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines or "UNKNOWN" in lines:
        return AuthActivity(known=False)
    activity = AuthActivity(known=True)
    for line in lines:
        key, _, rest = line.partition(" ")
        if key == "SOURCE":
            activity.source = rest
            activity.window = "son 24 saat" if rest == "journal" else ("" if rest == "none" else "son 20.000 log satırı")
            if rest == "none":
                activity.known = False
        elif key in ("FAILED", "INVALID", "ACCEPTED", "ACCEPTED_PASSWORD") and rest.isdigit():
            setattr(activity, {"FAILED": "failed", "INVALID": "invalid_user", "ACCEPTED": "accepted",
                               "ACCEPTED_PASSWORD": "accepted_password"}[key], int(rest))
        elif key in ("FIP", "FUSER"):
            count, _, value = rest.partition(" ")
            if count.isdigit() and value:
                item = CountedItem(value=value, count=int(count))
                (activity.top_sources if key == "FIP" else activity.top_users).append(item)
        elif key == "ACC":
            parts = rest.split()
            if len(parts) >= 4:
                activity.recent_accepted.append(
                    LoginEvent(time=_epoch_or_text(parts[0]), method=parts[1], user=parts[2], source=parts[3]))
    activity.top_sources.sort(key=lambda c: -c.count)
    activity.top_users.sort(key=lambda c: -c.count)
    return activity


# Groups whose members are already listed from the group database (ADMINS block)
_ADMIN_GROUPS = {"%sudo", "%wheel", "%admin"}
_SUDOERS_SPEC = re.compile(r"^(\S+)\s+\S[^=]*=")


def sudo_rule_subjects(lines: list[str]) -> list[str]:
    """Who a set of (comment-free) sudoers lines grants rights to: `deploy ALL=(ALL) ALL` -> deploy.

    Defaults, aliases and includes are skipped, as are root and the sudo/wheel/admin groups.
    """
    subjects: list[str] = []
    for line in lines:
        # "ci, backup ALL=..." -> "ci,backup ALL=...": the user list is then the first token
        m = _SUDOERS_SPEC.match(re.sub(r"\s*,\s*", ",", line))
        if not m:
            continue
        head = m.group(1)
        if head.startswith(("Defaults", "@include", "#include")) or head.endswith("_Alias"):
            continue
        for subject in head.split(","):
            subject = subject.strip()
            if subject and subject not in ("root", "ALL") and subject not in _ADMIN_GROUPS and subject not in subjects:
                subjects.append(subject)
    return subjects


def _kernel_key(release: str) -> tuple:
    """'5.15.0-105-generic' -> (5, 15, 0, 105): numeric parts only, for ordering kernels."""
    return tuple(int(n) for n in re.findall(r"\d+", release.split("-generic")[0])[:6])


def parse_updates(text: str, now: float) -> UpdateStatus:
    st = UpdateStatus()
    kernels: list[str] = []
    reboot_pkgs: list[str] = []
    for line in text.splitlines():
        key, _, rest = line.strip().partition(" ")
        rest = rest.strip()
        if key == "MANAGER":
            st.manager = rest
        elif key == "TOTAL" and rest.isdigit():
            st.total, st.known = int(rest), True
        elif key == "SECURITY":
            st.security = int(rest) if rest.isdigit() else None
        elif key == "SECPKG" and rest and len(st.security_packages) < 30:
            st.security_packages.append(rest)
        elif key == "META":
            try:
                st.metadata_age_days = max(0.0, (now - float(rest)) / 86400)
            except ValueError:
                pass
        elif key == "KERNEL":
            st.running_kernel = rest
        elif key == "KERNELS":
            kernels = rest.split()
        elif key == "REBOOT" and rest in ("yes", "no"):
            st.reboot_required = rest == "yes"
        elif key == "REBOOT_PKG" and rest and rest not in reboot_pkgs:
            reboot_pkgs.append(rest)
    if st.reboot_required:
        st.reboot_reason = ("yeniden başlatma isteyen paketler: " + ", ".join(reboot_pkgs[:5])
                            if reboot_pkgs else "paket güncellemesi yeniden başlatma istiyor")
    if not st.known:
        st.security = None
    # A newer kernel installed than the one running also means a reboot is pending
    running = st.running_kernel
    if running and running in kernels:
        newest = max(kernels, key=_kernel_key)
        if _kernel_key(newest) > _kernel_key(running):
            st.reboot_required = True
            st.reboot_reason = f"yeni çekirdek kurulu: {newest} (çalışan {running})"
        elif st.reboot_required is None:
            st.reboot_required = False
    return st


# sysctl key -> (accepted values, severity, title)
SYSCTL_CHECKS = {
    "kernel/randomize_va_space": ({"2"}, "MEDIUM", "ASLR tam açık (randomize_va_space=2)"),
    "fs/protected_symlinks": ({"1"}, "MEDIUM", "Sembolik bağ saldırısı koruması (protected_symlinks=1)"),
    "fs/protected_hardlinks": ({"1"}, "MEDIUM", "Hard link saldırısı koruması (protected_hardlinks=1)"),
    "net/ipv4/tcp_syncookies": ({"1"}, "MEDIUM", "SYN flood koruması (tcp_syncookies=1)"),
    "net/ipv4/conf/all/accept_source_route": ({"0"}, "MEDIUM", "Kaynak yönlendirmeli paketler reddediliyor"),
    "kernel/kptr_restrict": ({"1", "2"}, "LOW", "Çekirdek adresleri gizli (kptr_restrict>=1)"),
    "kernel/dmesg_restrict": ({"1"}, "LOW", "dmesg yalnızca root'a açık (dmesg_restrict=1)"),
    "kernel/yama/ptrace_scope": ({"1", "2", "3"}, "LOW", "ptrace kısıtlı (yama.ptrace_scope>=1)"),
    "fs/suid_dumpable": ({"0"}, "LOW", "SUID süreçler core dump bırakmıyor (suid_dumpable=0)"),
    "net/ipv4/conf/all/accept_redirects": ({"0"}, "LOW", "ICMP yönlendirmeleri kabul edilmiyor"),
    "net/ipv4/conf/all/send_redirects": ({"0"}, "LOW", "ICMP yönlendirmesi gönderilmiyor"),
    "net/ipv4/conf/all/rp_filter": ({"1", "2"}, "LOW", "Sahte kaynak IP filtresi (rp_filter)"),
}
# file -> (bits that must not be set, title)
PERM_CHECKS = {
    "/etc/shadow": (0o004, "/etc/shadow herkes tarafından okunamıyor", "/etc/shadow herkes tarafından okunabiliyor"),
    "/etc/gshadow": (0o004, "/etc/gshadow herkes tarafından okunamıyor", "/etc/gshadow herkes tarafından okunabiliyor"),
    "/etc/passwd": (0o002, "/etc/passwd herkes tarafından yazılamıyor", "/etc/passwd herkes tarafından yazılabiliyor"),
    "/etc/group": (0o002, "/etc/group herkes tarafından yazılamıyor", "/etc/group herkes tarafından yazılabiliyor"),
    "/etc/sudoers": (0o022, "/etc/sudoers başkaları tarafından yazılamıyor", "/etc/sudoers başkaları tarafından yazılabiliyor"),
    "/etc/ssh/sshd_config": (0o022, "sshd_config başkaları tarafından yazılamıyor",
                             "sshd_config başkaları tarafından yazılabiliyor"),
}


def parse_hardening(text: str) -> HardeningAudit:
    blocks: dict[str, list[str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") and line[1:].replace("_", "").isupper():
            current = line[1:]
            blocks[current] = []
        elif line and current is not None:
            blocks[current].append(line)
    audit = HardeningAudit(known="SYSCTL" in blocks)
    if not audit.known:
        return audit
    add = audit.checks.append

    sysctl = dict(line.split(" ", 1) for line in blocks.get("SYSCTL", []) if " " in line)
    # The kernel applies max(all, <interface>) for rp_filter; distros usually set it via `default`
    rp = [sysctl[k].strip() for k in ("net/ipv4/conf/all/rp_filter", "net/ipv4/conf/default/rp_filter") if k in sysctl]
    if rp:
        sysctl["net/ipv4/conf/all/rp_filter"] = max(rp)
    for key, (ok, severity, title) in SYSCTL_CHECKS.items():
        if key in sysctl:
            add(HardeningCheck(id=f"sysctl:{key}", title=title, severity=severity,
                               passed=sysctl[key].strip() in ok, detail=f"{key.replace('/', '.')} = {sysctl[key]}"))
    if "net/ipv4/ip_forward" in sysctl:
        audit.ip_forward = sysctl["net/ipv4/ip_forward"].strip() == "1"

    mounts = {}
    for line in blocks.get("MOUNTS", []):
        mnt, _, opts = line.partition(" ")
        mounts[mnt] = set(opts.split(","))
    for mnt in ("/tmp", "/dev/shm"):
        if mnt in mounts:
            missing = [o for o in ("nosuid", "nodev") if o not in mounts[mnt]]
            add(HardeningCheck(id=f"mount:{mnt}", title=f"{mnt} nosuid,nodev ile bağlı", severity="LOW",
                               passed=not missing, detail="eksik: " + ",".join(missing) if missing else ""))

    for line in blocks.get("PERMS", []):
        parts = line.split(" ", 2)
        if len(parts) != 3 or parts[2] not in PERM_CHECKS:
            continue
        try:
            mode = int(parts[0], 8)
        except ValueError:
            continue
        forbidden, title, problem = PERM_CHECKS[parts[2]]
        add(HardeningCheck(id=f"perm:{parts[2]}", title=title, severity="HIGH", passed=not mode & forbidden,
                           detail=f"izin {parts[0]}, sahibi {parts[1]}", problem=problem))

    audit.suid_files = sorted(set(blocks.get("SUID", [])))
    suspect = blocks.get("SUID_SUSPECT", [])
    if suspect != ["UNKNOWN"]:
        audit.suspicious_suid = sorted(set(suspect))
        add(HardeningCheck(id="suid:suspicious", title="Geçici/kullanıcı dizinlerinde SUID/SGID dosya yok",
                           severity="HIGH", passed=not audit.suspicious_suid,
                           detail=", ".join(audit.suspicious_suid[:5]),
                           problem=f"Şüpheli konumda SUID/SGID dosya: {', '.join(audit.suspicious_suid[:3])}"))
    audit.world_writable = sorted(set(blocks.get("WORLD_WRITABLE", [])))
    add(HardeningCheck(id="files:world-writable", title="/etc ve bin dizinlerinde herkesin yazabildiği dosya yok",
                       severity="HIGH", passed=not audit.world_writable, detail=", ".join(audit.world_writable[:5]),
                       problem=f"Herkesin yazabildiği sistem dosyası: {', '.join(audit.world_writable[:3])}"))
    empty = blocks.get("EMPTY_PASSWORD", [])
    if empty != ["UNKNOWN"]:
        audit.empty_password_users = sorted(set(empty))
        add(HardeningCheck(id="accounts:empty-password", title="Boş parolalı hesap yok", severity="HIGH",
                           passed=not audit.empty_password_users, detail=", ".join(audit.empty_password_users),
                           problem=f"Boş parolalı hesap: {', '.join(audit.empty_password_users)}"))
    return audit


def parse_docker_security(text: str) -> dict[str, ContainerSecurity]:
    """`docker inspect` lines (see DOCKER_SEC) -> {container name: settings}."""
    result: dict[str, ContainerSecurity] = {}
    for line in text.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 10 or not parts[0]:
            continue
        name, user, privileged, net, pid, caps, restarts, health, mounts, ro = parts
        try:
            cap_list = json.loads(caps) or []
        except ValueError:
            cap_list = []
        mount_list = []
        for m in filter(None, mounts.split(";")):
            fields = m.split(">")
            if len(fields) == 3:
                mount_list.append((fields[0], fields[1], fields[2] == "true"))
        result[name.lstrip("/")] = ContainerSecurity(
            user=user, privileged=privileged == "true", network_mode=net, pid_mode=pid,
            cap_add=[str(c) for c in cap_list if isinstance(c, str)][:20],
            restart_count=int(restarts) if restarts.isdigit() else 0, health=health,
            mounts=mount_list[:50], read_only_root=ro == "true",
        )
    return result


def parse_access(text: str) -> AccessAudit:
    audit = AccessAudit()
    block = None
    sudoers_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("#") and line[1:].isupper():
            block = line[1:]
            continue
        if not line:
            continue
        if block == "UID0":
            audit.uid0_users.append(line)
        elif block == "ADMINS":
            members = line.split(":")[3] if line.count(":") >= 3 else ""
            for member in filter(None, (m.strip() for m in members.split(","))):
                if member not in audit.admin_users:
                    audit.admin_users.append(member)
        elif block == "LOGIN":
            audit.login_users.append(line)
        elif block == "SUDOERS":
            sudoers_lines.append(line)
        elif block == "AUTHKEYS":
            user, _, count = line.partition(" ")
            if count.isdigit():
                audit.authorized_keys[user] = int(count)
                audit.keys_known = True
            elif count == "?":
                audit.authorized_keys_unknown.append(user)
    if "UNKNOWN" in sudoers_lines:
        audit.sudoers_known = False
        sudoers_lines.remove("UNKNOWN")
    else:
        audit.sudoers_known = "SUDOERS" in text
    audit.nopasswd_rules = [line for line in sudoers_lines if "NOPASSWD" in line][:20]
    audit.sudo_rule_users = sudo_rule_subjects(sudoers_lines) if audit.sudoers_known else []
    return audit
