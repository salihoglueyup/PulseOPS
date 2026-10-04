import platform
import re

import pytest

from collectors import probe_parsers as pp
from collectors.nginx_parser import NginxParser
from collectors.port_collector import PortCollector
from collectors.probe import build_script, parse_sections
from collectors.probe_collector import ProbeCollector
from collectors.transport import LocalTransport, TransportError
from models.ports import PortExposure


# --- sections -------------------------------------------------------------------------------------

def test_sections_need_the_nonce():
    script, nonce = build_script(fast=True)
    assert nonce in script
    raw = (
        f"===PULSEOPS:{nonce}:HOST===\nweb01\n"
        "===PULSEOPS:deadbeef:PRIV===\n"  # forged marker inside command output stays data
        f"===PULSEOPS:{nonce}:LOGS===\nline\n===PULSEOPS:{nonce}:END===\n"
    )
    sections = parse_sections(raw, nonce)
    assert sections["HOST"] == "web01\n===PULSEOPS:deadbeef:PRIV==="
    assert sections["LOGS"] == "line"
    assert "PRIV" not in sections and "END" not in sections


def test_script_tiers():
    fast, _ = build_script(fast=True)
    slow, _ = build_script(fast=False, slow=True)
    assert ":CPUSTAT===" in fast and ":DOCKER===" not in fast
    assert ":DOCKER===" in slow and ":CPUSTAT===" not in slow
    assert "LC_ALL=C" in fast


# --- parsers --------------------------------------------------------------------------------------

def test_parse_host_load_sysconf():
    assert pp.parse_host('web01\n6.8.0-40-generic\nNAME="Ubuntu"\nPRETTY_NAME="Ubuntu 24.04.1 LTS"\n') == (
        "web01", "6.8.0-40-generic", "Ubuntu 24.04.1 LTS")
    assert pp.parse_loadavg("0.42 0.35 0.28 2/350 49201") == (0.42, 0.35, 0.28)
    assert pp.parse_uptime("86400.50 172800.00") == 86400.5
    assert pp.parse_sysconf("8\n100\n4096\n") == (8, 100, 4096)
    assert pp.parse_sysconf("") == (1, 100, 4096)


def test_cpu_percent_from_proc_stat():
    before = pp.parse_cpustat("cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 50 0 50 400 0 0 0 0 0 0")
    after = pp.parse_cpustat("cpu  250 0 150 900 100 0 0 0 0 0\ncpu0 150 0 50 400 0 0 0 0 0 0")
    # total: busy +200, total +400 (iowait counts as idle) -> 50%
    assert pp.cpu_percent(before["cpu"], after["cpu"]) == 50.0
    assert pp.cpu_percent(before["cpu0"], after["cpu0"]) == 100.0
    assert pp.cpu_percent(after["cpu"], after["cpu"]) == 0.0


def test_parse_meminfo():
    m = pp.parse_meminfo(
        "MemTotal:       16000000 kB\nMemFree:         1000000 kB\nMemAvailable:    8000000 kB\n"
        "SwapTotal:       4000000 kB\nSwapFree:        3000000 kB\n"
    )
    assert m.percent == 50.0
    assert m.used_bytes == 8000000 * 1024
    assert m.swap_percent == 25.0


def test_parse_df_posix_with_type_and_spaces():
    disks = pp.parse_df(
        "Filesystem     Type     1-blocks       Used   Available Capacity Mounted on\n"
        "/dev/sdb1      xfs   100000000000 60000000000 40000000000      60% /data\n"
        "/dev/sda1      ext4   50000000000 20000000000 30000000000      40% /\n"
        "/dev/sdc1      ext4   10000000000  1000000000  9000000000      10% /mnt/my disk\n"
    )
    assert [d.mountpoint for d in disks] == ["/", "/data", "/mnt/my disk"]  # root first
    assert disks[1].fstype == "xfs" and disks[1].percent == 60.0


def test_parse_df_kilobyte_fallback():
    disks = pp.parse_df("Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 100 50 50 50% /\n")
    assert disks[0].total_bytes == 100 * 1024


def test_parse_df_overlay_root_and_container_mounts():
    # LXC guest / container: `/` is overlay; the host disk shows up again on bind-mounted files
    guest = pp.parse_df(
        "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
        "overlay overlay 1000 400 600 40% /\n"
        "tmpfs tmpfs 64 0 64 0% /dev\n"
        "/dev/vda ext4 1000 400 600 40% /etc/hosts\n"
        "/dev/vda ext4 1000 400 600 40% /etc/resolv.conf\n"
    )
    assert [(d.mountpoint, d.fstype) for d in guest] == [("/", "overlay")]

    # Docker host: one overlay per container must not flood the disk list
    host = pp.parse_df(
        "Filesystem Type 1-blocks Used Available Capacity Mounted on\n"
        "/dev/sda1 ext4 1000 400 600 40% /\n"
        "overlay overlay 1000 400 600 40% /var/lib/docker/overlay2/abc/merged\n"
        "overlay overlay 1000 400 600 40% /mnt/union\n"
        "/dev/loop3 squashfs 100 100 0 100% /snap/core/1\n"
    )
    assert [d.mountpoint for d in host] == ["/"]


def test_parse_diskstats_counts_whole_disks_only():
    text = (
        "   8       0 sda 100 0 2000 0 50 0 4000 0 0 0 0\n"
        "   8       1 sda1 100 0 2000 0 50 0 4000 0 0 0 0\n"
        " 259       0 nvme0n1 10 0 100 0 5 0 200 0 0 0 0\n"
        " 259       1 nvme0n1p1 10 0 100 0 5 0 200 0 0 0 0\n"
        "   7       0 loop0 999 0 99999 0 0 0 0 0 0 0 0\n"
        " 253       0 dm-0 999 0 99999 0 999 0 99999 0 0 0 0\n"
    )
    assert pp.parse_diskstats(text) == ((2000 + 100) * 512, (4000 + 200) * 512)


def test_parse_net_dev_skips_virtual():
    text = (
        "Inter-|   Receive |  Transmit\n face |bytes ...\n"
        "    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n"
        "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
        "vethab12: 5 1 0 0 0 0 0 0 5 1 0 0 0 0 0 0\n"
    )
    assert pp.parse_net_dev(text) == {"eth0": (1000, 2000)}


def test_parse_procstat_and_users():
    procs = pp.parse_procstat("1 221 1213 systemd\n812 5 300 nginx: worker process\n9 0 0 x) y) z\nbad line\n")
    assert procs[812] == pp.ProcSample(5, 300, "nginx: worker process")
    assert procs[9].name == "x) y) z"
    assert pp.parse_procusers("    1 root\n  812 www-data\n") == {1: "root", 812: "www-data"}


def test_parse_proc_net_without_ss():
    text = (
        "#tcp\n"
        "   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1111 1\n"
        "   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2222 1\n"
        "   2: 0100007F:9C40 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 3333 1\n"
        "#tcp6\n"
        "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4444 1\n"
        "#sockets\n"
        "/proc/10/fd socket:[1111]\n/proc/20/fd socket:[2222]\n"
    )
    tables, sockets = text.split("#sockets\n")
    ports = pp.parse_proc_net(tables, pp.parse_socket_owners(sockets), {10: "nginx", 20: "postgres"})
    by_port = {(p.port, p.ip): p for p in ports}
    assert set(by_port) == {(80, "0.0.0.0"), (5432, "127.0.0.1"), (22, "::")}  # ESTABLISHED row ignored
    assert by_port[(80, "0.0.0.0")].process_name == "nginx"
    assert by_port[(5432, "127.0.0.1")].exposure == PortExposure.SAFE_INTERNAL
    assert by_port[(22, "::")].process_name is None


@pytest.mark.parametrize("text,active,known,backend", [
    ("BACKEND:ufw\nStatus: active\n\n     To  Action  From\n[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 80/tcp ALLOW IN Anywhere\n",
     True, True, "UFW"),
    ("BACKEND:ufw\nStatus: inactive\n", False, True, "UFW"),
    ("BACKEND:ufw\nUNKNOWN\nBACKEND:iptables\nUNKNOWN\n", False, False, "UFW/iptables"),
    ("BACKEND:firewalld\nrunning\n", True, True, "firewalld"),
    ("BACKEND:iptables\n-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n", True, True, "iptables"),
    ("BACKEND:iptables\n-P INPUT ACCEPT\nBACKEND:nftables\nrules=0 policy_drop=0\n", False, True, "nftables/iptables"),
    ("BACKEND:iptables\n-P INPUT ACCEPT\nBACKEND:nftables\nrules=3 policy_drop=1\n", True, True, "nftables"),
    ("BACKEND:nftables\nUNKNOWN\n", False, False, "nftables"),
    ("", False, True, "Yok"),
])
def test_parse_firewall(text, active, known, backend):
    fw = pp.parse_firewall(text)
    assert (fw.is_active, fw.known, fw.backend) == (active, known, backend)


def test_parse_firewall_counts_ufw_rules():
    fw = pp.parse_firewall("BACKEND:ufw\nStatus: active\n[ 1] 22/tcp ALLOW IN Anywhere\n[ 2] 443 ALLOW IN Anywhere\n")
    assert fw.rules_count == 2


def test_port_owners_from_slow_tier_reclassify():
    fast = PortCollector().parse_ss_text(
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port\n"
        "tcp   LISTEN 0      128          0.0.0.0:6379       0.0.0.0:*\n"
    )
    owned = pp.apply_port_owners(fast, {("tcp", "0.0.0.0", 6379): (77, "redis-server")})
    assert owned[0].pid == 77 and owned[0].process_name == "redis-server"
    assert owned[0].exposure == PortExposure.EXPOSED_RISK


def test_legacy_ss_and_netstat_parsing():
    ports = PortCollector().parse_ss_text(
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess\n"
        'tcp   LISTEN 0      128          0.0.0.0:3306       0.0.0.0:*    users:(("mysqld",pid=5600,fd=22))\n'
    )
    assert ports[0].exposure == PortExposure.EXPOSED_RISK
    ports = PortCollector().parse_ss_text(
        "Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\n"
        "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1120/postgres\n"
    )
    assert ports[0].process_name == "postgres" and ports[0].exposure == PortExposure.SAFE_INTERNAL


def test_nginx_upstream_resolution():
    routes = NginxParser().parse_config_text(
        "upstream app { server 127.0.0.1:3000; }\n"
        "server { listen 80; server_name myapp.com; location / { proxy_pass http://app; } }\n"
    )
    assert routes[0].domain == "myapp.com" and routes[0].target_port == 3000


# --- collector with a scripted fake host ------------------------------------------------------------

class FakeHost:
    """Answers probe scripts like a Linux host, with counters advancing between calls."""

    def __init__(self, sudo_works=False):
        self.calls = 0
        self.scripts = []
        self.sudo_works = sudo_works

    def section_values(self, step):
        # step 0 = baseline, 1 = first sample, 2 = second sample (each 2 seconds apart)
        uptime = 1000.0 + 2 * step
        busy = 1000 + 300 * step  # 300 of 400 jiffies busy per step -> 75 %
        total = 4000 + 400 * step
        return {
            "UPTIME": f"{uptime} 0",
            "CPUSTAT": f"cpu  {busy} 0 0 {total - busy} 0 0 0 0\ncpu0 {busy} 0 0 {total - busy} 0 0 0 0",
            "PROCSTAT": f"1 0 250 systemd\n42 {100 * step} 62500 node",  # 100 ticks / 2s at CLK 100 -> 50 %
            "NET": f"  eth0: {1000 * step} 0 0 0 0 0 0 0 {500 * step} 0 0 0 0 0 0 0",
            "DISKSTATS": f"   8 0 sda 0 0 {8 * step} 0 0 0 {4 * step} 0 0 0 0",
        }

    def run(self, script, timeout):
        self.calls += 1
        self.scripts.append(script)
        nonce = re.search(r"===PULSEOPS:([0-9a-f]+):", script).group(1)
        names = re.findall(r"===PULSEOPS:[0-9a-f]+:([A-Z_0-9]+)===", script)
        step = self.calls if "UPTIME0" not in names else 1
        values = self.section_values(step)
        base = self.section_values(0)
        out = []
        for name in names:
            out.append(f"===PULSEOPS:{nonce}:{name}===")
            if name.endswith("0") and name[:-1] in base:
                out.append(base[name[:-1]])
            elif name in values:
                out.append(values[name])
            elif name == "HOST":
                out.append('web01\n6.8.0\nPRETTY_NAME="Ubuntu 24.04 LTS"')
            elif name == "LOADAVG":
                out.append("0.5 0.4 0.3 1/100 1")
            elif name == "SYSCONF":
                out.append("1\n100\n4096")
            elif name == "PROCUSERS":
                out.append("    1 root\n   42 app")
            elif name == "MEM":
                out.append("MemTotal: 1000000 kB\nMemFree: 100 kB\nMemAvailable: 500000 kB")
            elif name == "FIREWALL":
                out.append("BACKEND:ufw\nStatus: active\n[ 1] 22/tcp ALLOW IN Anywhere")
            elif name == "PRIV":
                out.append("app\n1000\n" + ("sudo_ok\n" if self.sudo_works and "sudo -n true" in script else ""))
            elif name == "LOGS":
                out.append('1.2.3.4 - - "GET /[/] HTTP/1.1" 404\n-- No entries --')
        return "\n".join(out) + "\n"

    def close(self):
        pass


def test_probe_collector_rates_and_tiers():
    host = FakeHost()
    c = ProbeCollector(host)

    t1 = c.collect(include_slow=True, include_logs=True)
    assert ":UPTIME0===" in host.scripts[0] and ":DOCKER===" in host.scripts[0]
    assert t1.snapshot.hostname == "web01"
    assert t1.snapshot.cpu.total_percent == 75.0
    top = t1.snapshot.top_processes[0]
    assert (top.name, top.cpu_percent, top.memory_mb, top.username) == ("node", 50.0, 244.1, "app")
    assert t1.snapshot.memory.percent == 50.0
    assert t1.security.firewall_active and t1.snapshot.firewall.backend == "UFW"
    assert not t1.privileges.elevated
    assert t1.logs == ['1.2.3.4 - - "GET /[/] HTTP/1.1" 404']

    t2 = c.collect(include_slow=False, include_logs=False)
    fast_script = host.scripts[1]
    assert ":UPTIME0===" not in fast_script and ":DOCKER===" not in fast_script and ":LOGS===" not in fast_script
    assert t2.snapshot.cpu.total_percent == 75.0
    assert t2.snapshot.network[0].rx_bytes_sec == 500.0 and t2.snapshot.network[0].tx_bytes_sec == 250.0
    assert t2.snapshot.disk_io.read_bytes_sec == 8 * 512 / 2 and t2.snapshot.disk_io.write_bytes_sec == 4 * 512 / 2
    # slow tier and logs come from cache
    assert t2.security.firewall_active and t2.logs == t1.logs
    assert t2.slow_collected_at == t1.slow_collected_at


def test_probe_collector_rejects_truncated_output():
    class Truncated:
        def run(self, script, timeout):
            return "garbage"

        def close(self):
            pass

    with pytest.raises(TransportError):
        ProbeCollector(Truncated()).collect()


@pytest.mark.skipif(platform.system() != "Linux", reason="runs the real probe on this Linux machine")
def test_real_local_probe():
    c = ProbeCollector(LocalTransport())
    t = c.collect()
    assert t.snapshot.hostname
    assert t.snapshot.cpu.cores >= 1 and len(t.snapshot.cpu.per_core_percent) >= 1
    assert t.snapshot.memory.total_bytes > 0
    assert t.snapshot.disks and t.snapshot.disks[0].mountpoint == "/"
    assert t.snapshot.top_processes
    t2 = c.collect(include_slow=False, include_logs=False)
    assert t2.snapshot.uptime_seconds >= t.snapshot.uptime_seconds


def test_unknown_firewall_is_neither_alerted_nor_penalized():
    from collectors.base import DemoCollector
    from collectors.telemetry import collect_telemetry, summarize_alerts
    from collectors.audit_exporter import calculate_audit_score
    from models.system import FirewallStatus

    t = collect_telemetry(DemoCollector())
    base_score, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)

    t.snapshot.firewall = FirewallStatus(is_active=False, known=False, backend="iptables", summary="Bilinmiyor")
    t.security.firewall_active, t.security.firewall_known = False, False
    assert not any("Duvarı" in a for a in summarize_alerts(t))
    assert calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)[0] == base_score

    t.snapshot.firewall = FirewallStatus(is_active=False, known=True, backend="iptables", summary="Kapalı")
    t.security.firewall_known = True
    assert any("Duvarı KAPALI" in a for a in summarize_alerts(t))
    assert calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)[0] == base_score - 15


def test_sshd_config_semantics():
    from collectors.security_collector import SecurityCollector

    parse = SecurityCollector().parse_sshd_config_text
    # OpenSSH defaults when nothing is set
    audit = parse("")
    assert (audit.permit_root_login, audit.password_authentication, audit.pubkey_authentication) == (
        "prohibit-password", "yes", "yes")
    assert not audit.is_hardened  # password logins are allowed by default

    # First value wins: a drop-in (printed first) overrides the main file
    audit = parse("PasswordAuthentication no\nPermitRootLogin no\n# main file\nPasswordAuthentication yes\nPermitRootLogin yes\n")
    assert (audit.password_authentication, audit.permit_root_login, audit.is_hardened) == ("no", "no", True)

    # Match blocks are conditional and must not leak into the global settings
    audit = parse("PermitRootLogin no\nMatch Address 10.0.0.0/8\n    PasswordAuthentication yes\n")
    assert audit.password_authentication == "yes"  # default, not from the Match block
    audit = parse("Match User backup\n  PermitRootLogin yes\n")
    assert audit.permit_root_login == "prohibit-password"

    # `sshd -T` output: lowercase keys and the without-password alias
    audit = parse("#EFFECTIVE\nport 2222\npermitrootlogin without-password\npasswordauthentication no\npubkeyauthentication yes\n")
    assert (audit.port, audit.permit_root_login, audit.is_hardened) == (2222, "prohibit-password", True)


def test_sudo_is_detected_once_and_never_used_in_fast_tier():
    host = FakeHost(sudo_works=True)
    c = ProbeCollector(host)
    c.collect(include_slow=True)
    assert "sudo -n true" in host.scripts[0]
    c.collect(include_slow=False, include_logs=False)
    fast_body = host.scripts[1].split('S=""\n', 1)[1]
    assert "sudo" not in fast_body
    c.collect(include_slow=True)
    assert "sudo -n true" not in host.scripts[2] and 'S="sudo -n"' in host.scripts[2]


def test_sudo_can_be_disabled():
    host = FakeHost(sudo_works=True)
    c = ProbeCollector(host, use_sudo=False)
    c.collect(include_slow=True)
    assert "sudo -n" not in host.scripts[0].split('S=""')[1]


def test_parse_backup_files():
    names, sizes, shas = pp.parse_backup_files(
        "SNAP 120 ./backups/store-20261001-020000.json\n"
        "SNAP 7 /srv/app data/store-20261002-020000.json\n"
        "FILE:./last-successful-deploy.sha\na1b2c3d4e5f6\n"
        "FILE:/opt/x/previous-successful-deploy.sha\n\n0f9e8d\n"
    )
    assert names == ["store-20261001-020000.json", "store-20261002-020000.json"]
    assert sizes["store-20261002-020000.json"] == 7
    assert shas == {"last-successful-deploy.sha": "a1b2c3d4e5f6", "previous-successful-deploy.sha": "0f9e8d"}


def test_rare_sections_are_skipped_while_cached():
    from collectors.probe import RARE_SECTIONS

    script, _ = build_script(fast=False, slow=True, skip=frozenset(RARE_SECTIONS))
    assert ":UNIT_FILES===" not in script and ":DOCKER===" in script
    host = FakeHost()
    c = ProbeCollector(host)
    c.collect(include_slow=True)
    c.collect(include_slow=True)
    assert ":UNIT_FILES===" in host.scripts[0] and ":UNIT_FILES===" not in host.scripts[1]


# Commands/arguments that would change the host. The probe must never contain any of them.
WRITE_PATTERNS = [
    r"\brm\b", r"\bmv\b", r"\bcp\b", r"\btee\b", r"\bdd\b", r"\btruncate\b", r"\bchmod\b", r"\bchown\b",
    r"\bmkdir\b", r"\btouch\b", r"\bln\b", r"\bkill\b", r"\bpkill\b", r"\bkillall\b", r"(?<![|/-])\breboot\b(?![|-])", r"(?<!\|)\bshutdown\b(?!\|)",
    r"sed\s+-i", r"\bsystemctl\s+(start|stop|restart|reload|enable|disable|mask|kill)\b",
    r"\bdocker\s+(rm|rmi|stop|start|restart|kill|run|exec|prune|system\s+prune|builder\s+prune|volume\s+rm)\b",
    r"\bufw\s+(enable|disable|allow|deny|reject|limit|delete|reset|insert)\b",
    r"\biptables\s+-[ADIRFNXZP]\b", r"\bnft\s+(add|delete|flush|insert|replace|create)\b",
    r"\bfail2ban-client\s+(set|unban|ban|stop|start|reload|restart)\b", r"\bcrontab\s+-[re]\b",
    r"\bapt(-get)?\s+(install|remove|purge|upgrade|dist-upgrade|full-upgrade|update|autoremove|clean)\b",
    r"\b(dnf|yum)\s+(install|remove|erase|upgrade|update|makecache|clean|distro-sync)\b",
    r"\bapk\s+(add|del|upgrade|update|fix|cache)\b", r"\bneeds-restarting\s+-s\b",
    r"\bjournalctl\s+--(vacuum|rotate|flush)", r"\bfirewall-cmd\s+--(add|remove|reload|set)", r"\bnginx\s+-s\b",
]


def test_probe_is_read_only():
    script, _ = build_script(fast=True, slow=True, logs=True, baseline=True, sudo=True)
    body = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
    for pattern in WRITE_PATTERNS:
        assert not re.search(pattern, body), f"probe contains a modifying command: {pattern}"
    # Package managers: a modifying verb anywhere in the command needs simulate/cache-only flags
    for cmd in re.findall(r"\bapt(?:-get)?\s[^;|&]*", body):
        if re.search(r"\b(install|remove|purge|upgrade|dist-upgrade|full-upgrade|update|autoremove)\b", cmd):
            assert re.search(r"\s-s\b", cmd), f"apt runs for real: {cmd}"
    for cmd in re.findall(r"\$pm\s[^;|&]*|(?<!-v )\b(?:dnf|yum)\s[^;|&]*", body):
        assert re.search(r"\s-C\b", cmd), f"dnf may refresh metadata: {cmd}"
    # Shell output redirections may only discard (>/dev/null, 2>/dev/null, >&2-style dups)
    shell_only = re.sub(r"'[^']*'", "''", body)
    for target in re.findall(r"(?<![<>&|])(?:\d?>>?)\s*([^\s;|&)]+)", shell_only):
        assert target == "/dev/null" or target.startswith("&"), f"probe writes to {target}"
    # Quoted programs (awk) must not write files or run commands other than the sort|head pipe
    for program in re.findall(r"'([^']*)'", body):
        assert not re.search(r'print[^;}]*>\s*"', program), f"awk writes a file: {program[:80]}"
        assert "system(" not in program and "getline" not in program


def test_fast_tier_never_uses_sudo():
    for sudo in (None, True, False):
        script, _ = build_script(fast=True, baseline=True, sudo=sudo)
        body = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("#"))
        assert "sudo" not in body.split('S=""', 1)[1]
