"""The agentless probe: one POSIX shell script that prints every telemetry source in sections.

The same script runs locally (`sh -s` subprocess) and remotely (`sh -s` over SSH), so both modes
share one parsing path. It is split into tiers so cheap, fast-changing metrics can be refreshed
often while expensive ones run rarely:

  * FAST  - cpu, memory, disk I/O, network, listening ports, processes. Shell builtins plus at most
            three short-lived processes; never sudo.
  * SLOW  - host identity, disks, port owners, nginx, timers/cron, backups, docker, storage,
            firewall, services, sshd, privileges
  * LOGS  - recent web/system log lines (only fetched when needed)

Everything here is read-only. sudo is never used as root, never in the fast tier, and otherwise
only as `sudo -n` (non-interactive) once passwordless sudo is known to work: every sudo call is
written to the host's auth log, and a monitoring tool must not flood it.
"""
import secrets
from typing import Optional

PREAMBLE = r"""export LC_ALL=C LANG=C
exec 2>/dev/null
# show FILE: print a (small, /proc) file with shell builtins only, no fork
show() { while IFS= read -r l || [ -n "$l" ]; do printf '%s\n' "$l"; done < "$1"; }
# priv CMD...: run with passwordless sudo when enabled for this run, otherwise directly
priv() { if [ -n "$S" ]; then $S "$@" && return 0; fi; "$@"; }
S=""
"""

SUDO_DETECT = 'if [ "$(id -u)" != 0 ] && sudo -n true 2>/dev/null; then S="sudo -n"; fi\n'
SUDO_ON = 'if [ "$(id -u)" != 0 ]; then S="sudo -n"; fi\n'

# pid, cpu ticks (utime+stime), rss pages and comm for every process in a single awk pass.
# `cat` keeps going when a process exits mid-read (mawk would abort on a missing file), and the
# last ") " delimits comm because comm itself may contain ") ".
PROCSTAT_CMD = (
    "cat /proc/[0-9]*/stat | awk '{ s = $0; k = 0;"
    " while ((j = index(s, \") \")) > 0) { k += j + 1; s = substr(s, j + 2) }"
    " o = index($0, \"(\"); split(s, f, \" \");"
    " print $1, f[12] + f[13], f[22], substr($0, o + 1, k - o - 2) }'"
)

CPUSTAT_CMD = "while IFS= read -r l; do case $l in cpu*) printf '%s\\n' \"$l\";; *) break;; esac; done < /proc/stat"

# Each entry: (section name, shell snippet). Snippets must never prompt and must tolerate failure.
FAST_SECTIONS = [
    ("UPTIME", "show /proc/uptime"),
    ("LOADAVG", "show /proc/loadavg"),
    ("CPUSTAT", CPUSTAT_CMD),
    ("MEM", "show /proc/meminfo"),
    ("DISKSTATS", "show /proc/diskstats"),
    ("NET", "show /proc/net/dev"),
    (
        # Owners (-p) are resolved in the slow tier: that is the expensive part of ss/netstat
        "PORTS",
        "if command -v ss >/dev/null; then ss -lntu;"
        " elif command -v netstat >/dev/null; then netstat -lntu;"
        " else for t in tcp tcp6 udp udp6; do [ -r /proc/net/$t ] && { echo \"#$t\"; show /proc/net/$t; }; done; fi",
    ),
    ("PROCSTAT", PROCSTAT_CMD),
]

# Printed (followed by a short sleep) before FAST when there is no previous sample to diff against,
# so even a one-shot `pulseops status` reports real CPU usage.
BASELINE_SECTIONS = [
    ("UPTIME0", "show /proc/uptime"),
    ("CPUSTAT0", CPUSTAT_CMD),
    ("PROCSTAT0", PROCSTAT_CMD),
    ("BASELINE_SLEEP", "sleep 0.5"),
]

# Summarises sshd authentication events into counts and top-10 lists inside the host, so a server
# under a brute-force storm sends a few hundred bytes instead of megabytes of log lines.
AUTH_AWK = (
    "awk '"
    # timestamp: journal short-unix (epoch), RFC 3339, or classic syslog (\"Oct  3 19:00:00\")
    "function ts() { if ($1 ~ /^[0-9]+[.][0-9]+$/ || $1 ~ /^[0-9][0-9][0-9][0-9]-/) return $1;"
    " if ($1 ~ /^[A-Z][a-z][a-z]$/) return $1 \"_\" $2 \"_\" $3; return \"-\" }"
    " /Accepted [a-z/-]+ for / { for (i = 1; i <= NF; i++) if ($i == \"Accepted\") { m = $(i+1); u = $(i+3); ip = $(i+5) }"
    " acc++; if (m == \"password\" || m ~ /^keyboard-interactive/) accpw++;"
    " recent[acc % 10] = ts() \" \" m \" \" u \" \" ip; next }"
    # an invalid user is counted once, on its \"Invalid user\" line
    " /Failed [a-z/-]+ for invalid user / { next }"
    " /Failed [a-z/-]+ for / { ip = \"\"; u = \"\";"
    " for (i = 1; i <= NF; i++) { if ($i == \"from\") { ip = $(i+1); seen[ip \":\" $(i+3)] = 1 } if ($i == \"for\") u = $(i+1) }"
    " fail++; fip[ip]++; fuser[u]++; next }"
    # key-only servers: a rejected key shows up as a pre-auth disconnect of an authenticating user
    # (only when that connection logged no \"Failed\" line, which sshd also writes for passwords)
    " /(Connection closed by|Disconnected from) authenticating user / { ip = \"\"; u = \"\"; port = \"\";"
    " for (i = 1; i <= NF; i++) if ($i == \"authenticating\" && $(i+1) == \"user\") { u = $(i+2); ip = $(i+3); port = $(i+5) }"
    " if ((ip \":\" port) in seen) next; fail++; fip[ip]++; fuser[u]++; next }"
    " /Invalid user / { ip = \"\"; u = \"\";"
    " for (i = 1; i <= NF; i++) { if ($i == \"from\") ip = $(i+1); if ($i == \"user\" && $(i-1) == \"Invalid\") u = $(i+1) }"
    " inv++; fip[ip]++; fuser[u]++; next }"
    " END { print \"FAILED\", fail + 0; print \"INVALID\", inv + 0; print \"ACCEPTED\", acc + 0; print \"ACCEPTED_PASSWORD\", accpw + 0;"
    " for (k in fip) if (k != \"\") print \"FIP\", fip[k], k | \"sort -k2,2nr | head -n 10\"; close(\"sort -k2,2nr | head -n 10\");"
    " for (k in fuser) if (k != \"\") print \"FUSER\", fuser[k], k | \"sort -k2,2nr | head -n 10\"; close(\"sort -k2,2nr | head -n 10\");"
    " n = acc < 10 ? acc : 10; for (j = 0; j < n; j++) print \"ACC\", recent[(acc - n + j + 1) % 10] }'"
)

# One `priv sh -c` for everything that needs root here: a single sudo call (and auth-log entry)
ACCESS_PRIV_SCRIPT = (
    "echo '#SUDOERS'; cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^[[:space:]]*#'"
    " | grep NOPASSWD | head -n 20 || true; [ -r /etc/sudoers ] || echo UNKNOWN;"
    " echo '#AUTHKEYS';"
    " awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1, $6}' /etc/passwd | while read -r u h; do"
    " f=\"$h/.ssh/authorized_keys\"; [ -f \"$f\" ] || continue;"
    " if [ -r \"$f\" ]; then echo \"$u $(grep -cvE '^[[:space:]]*(#|$)' \"$f\")\"; else echo \"$u ?\"; fi; done"
)

SEARCH_ROOTS = "/var/backups /var/www /opt /srv /home /root ."

SLOW_SECTIONS = [
    ("HOST", "show /proc/sys/kernel/hostname; show /proc/sys/kernel/osrelease; show /etc/os-release"),
    ("SYSCONF", "nproc || grep -c ^processor /proc/cpuinfo; getconf CLK_TCK || echo 100; getconf PAGESIZE || echo 4096"),
    ("DISK", "df -P -T -B1 -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs || df -P -T -k"),
    (
        "PORT_OWNERS",
        "if command -v ss >/dev/null; then priv ss -lntup;"
        " elif command -v netstat >/dev/null; then priv netstat -lntup;"
        " else echo '#sockets'; priv find /proc/[0-9]*/fd -lname 'socket:*' -printf '%h %l\\n'; fi",
    ),
    ("PROCUSERS", "ps -eo pid=,user:32= || ps -eo pid=,user="),
    ("NGINX", "priv nginx -T || cat /etc/nginx/nginx.conf /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf"),
    ("NGINX_CONF", "head -n 120 /etc/nginx/nginx.conf"),
    ("TIMERS", "systemctl list-timers --all --no-pager"),
    ("CRONTAB", "crontab -l"),
    (
        # One directory walk for both backup snapshots and deploy SHA markers
        "BACKUP_FILES",
        f"find {SEARCH_ROOTS} -maxdepth 4 \\( -name 'store-*.json' -printf 'SNAP %s %p\\n' \\)"
        " -o \\( -name '*deploy.sha' -printf 'SHA %p\\n' \\) | head -n 200"
        " | while IFS= read -r line; do case $line in"
        " 'SNAP '*) printf '%s\\n' \"$line\";;"
        " 'SHA '*) f=${line#SHA }; printf 'FILE:%s\\n' \"$f\"; head -n 1 \"$f\";; esac; done",
    ),
    ("DOCKER", "command -v docker >/dev/null && priv docker ps -a --format '{{json .}}'"),
    ("DOCKER_DF", "command -v docker >/dev/null && priv docker system df --format '{{json .}}'"),
    (
        "CONTAINERD_SZ",
        # du walks every file of the image store; keep it low priority and bounded
        "for d in /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs /var/lib/docker/overlay2; do"
        " [ -d \"$d\" ] || continue; priv timeout 10 nice -n 19 du -sh \"$d\"; break; done",
    ),
    (
        "FIREWALL",
        # Only the INPUT path is inspected: docker adds FORWARD/nat rules that say nothing about the
        # host firewall. "UNKNOWN" means the tool exists but could not be read (needs root).
        "if command -v ufw >/dev/null; then echo 'BACKEND:ufw'; priv ufw status numbered || echo UNKNOWN; fi;"
        " if command -v firewall-cmd >/dev/null; then echo 'BACKEND:firewalld'; firewall-cmd --state 2>&1 || true; fi;"
        " if command -v iptables >/dev/null; then echo 'BACKEND:iptables'; priv iptables -S INPUT || echo UNKNOWN; fi;"
        " if command -v nft >/dev/null; then echo 'BACKEND:nftables';"
        " { priv nft list ruleset || echo UNKNOWN; }"
        " | awk '/UNKNOWN/{u=1} /hook input/{i=1; if ($0 ~ /policy (drop|reject)/) d=1; next}"
        " /^[[:space:]]*}/{i=0} i && /(accept|drop|reject)/{c++}"
        " END{if (u) print \"UNKNOWN\"; else print \"rules=\" c+0 \" policy_drop=\" d+0}'; fi",
    ),
    ("SERVICES", "systemctl list-units --type=service --all --no-pager"),
    ("UNIT_FILES", "systemctl list-unit-files --type=service --no-pager"),
    (
        "SSHD_CONF",
        # Prefer sshd's own effective configuration (needs root); otherwise the raw files with the
        # drop-ins first, matching where Debian/Ubuntu/Fedora put their `Include` line.
        "if [ -e /etc/ssh/sshd_config ]; then"
        " SSHD=$(command -v sshd || echo /usr/sbin/sshd); eff=$(priv \"$SSHD\" -T);"
        " if [ -n \"$eff\" ]; then echo '#EFFECTIVE'; printf '%s\\n' \"$eff\""
        " | grep -E '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|permitemptypasswords) ';"
        " else { priv sh -c 'cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config' || echo UNREADABLE; }"
        " | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' | head -n 200; fi; fi",
    ),
    (
        "FAIL2BAN",
        "if command -v fail2ban-client >/dev/null; then echo INSTALLED;"
        " if command -v pgrep >/dev/null; then pgrep -x fail2ban-server >/dev/null && echo RUNNING || echo STOPPED; fi;"
        " out=$(priv fail2ban-client status 2>&1);"
        " case $out in *'Jail list'*)"
        " printf '%s\\n' \"$out\";"
        " for j in $(printf '%s\\n' \"$out\" | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' ' '); do"
        " echo \"#JAIL $j\"; priv fail2ban-client status \"$j\"; done;;"
        " *) echo UNKNOWN;; esac; fi",
    ),
    (
        # journald when it runs (then sshd logs there); otherwise the classic auth log files.
        # Without root/sudo/journal group a user only sees their own journal entries: report UNKNOWN
        # instead of a misleading zero.
        "AUTH",
        "if [ -d /run/systemd/journal ]; then"
        " if [ \"$(id -u)\" = 0 ] || [ -n \"$S\" ] || id -Gn | grep -qwE 'systemd-journal|adm|wheel'; then"
        " echo 'SOURCE journal';"
        " priv journalctl _COMM=sshd _COMM=sshd-session --since '24 hours ago' --no-pager -o short-unix | " + AUTH_AWK + ";"
        " else echo UNKNOWN; fi;"
        " else found=; for f in /var/log/auth.log /var/log/secure; do [ -e \"$f\" ] || continue; found=1;"
        " if [ -r \"$f\" ] || [ -n \"$S\" ]; then echo \"SOURCE $f\"; priv tail -n 20000 \"$f\" | " + AUTH_AWK + ";"
        " else echo UNKNOWN; fi; break; done; [ -n \"$found\" ] || echo 'SOURCE none'; fi",
    ),
    (
        "ACCESS",
        "echo '#UID0'; awk -F: '$3 == 0 {print $1}' /etc/passwd;"
        " echo '#ADMINS'; for g in sudo wheel admin; do getent group \"$g\" 2>/dev/null || grep \"^$g:\" /etc/group; done;"
        " echo '#LOGIN'; awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd;"
        " priv sh -c \"" + ACCESS_PRIV_SCRIPT.replace('"', '\\"').replace("$", "\\$") + "\"",
    ),
    (
        "PRIV",
        "id -un; id -u;"
        " command -v docker >/dev/null && echo docker_installed;"
        " [ -w /var/run/docker.sock ] && echo docker_ok;"
        " [ -n \"$S\" ] && echo sudo_ok",
    ),
]

LOG_SECTIONS = [
    (
        "LOGS",
        "if [ -r /var/log/nginx/access.log ] && [ -s /var/log/nginx/access.log ]; then tail -n 40 /var/log/nginx/access.log;"
        " elif [ -n \"$S\" ] && $S test -s /var/log/nginx/access.log; then $S tail -n 40 /var/log/nginx/access.log;"
        " else journalctl -n 40 --no-pager -o short-iso || tail -n 40 /var/log/syslog /var/log/messages; fi",
    ),
]

SECTION_PREFIX = "===PULSEOPS"


# Slow sections whose content practically never changes; the collector refreshes them far less often
RARE_SECTIONS = {"UNIT_FILES", "SYSCONF"}


def build_script(
    *,
    fast: bool = True,
    slow: bool = False,
    logs: bool = False,
    baseline: bool = False,
    sudo: Optional[bool] = None,
    skip: frozenset = frozenset(),
) -> tuple[str, str]:
    """Returns (script, nonce). The nonce makes section markers unforgeable by command output.

    sudo: None = detect passwordless sudo in this run (one `sudo -n true`), True = use it,
    False = never. It only matters for the slow and log tiers.
    skip: section names to leave out (e.g. RARE_SECTIONS that are still cached).
    """
    nonce = secrets.token_hex(8)
    groups = []
    if baseline:
        groups += BASELINE_SECTIONS
    if fast:
        groups += FAST_SECTIONS
    if slow:
        groups += SLOW_SECTIONS
    if logs:
        groups += LOG_SECTIONS

    script = PREAMBLE
    if (slow or logs) and sudo is not False:
        script += SUDO_DETECT if sudo is None else SUDO_ON
    for name, snippet in groups:
        if name in skip:
            continue
        script += f"echo '{SECTION_PREFIX}:{nonce}:{name}==='\n"
        # stdin is the script itself (`sh -s`); no snippet may read from it
        script += f"{{ {snippet}; }} </dev/null\n"
    script += f"echo '{SECTION_PREFIX}:{nonce}:END==='\n"
    return script, nonce


def parse_sections(raw: str, nonce: str) -> dict[str, str]:
    """Splits probe output into {section: text}. Lines that only look like markers are kept as data."""
    marker = f"{SECTION_PREFIX}:{nonce}:"
    sections: dict[str, str] = {}
    current = None
    buf: list[str] = []
    for line in raw.splitlines():
        if line.startswith(marker) and line.endswith("==="):
            if current is not None:
                sections[current] = "\n".join(buf)
            current = line[len(marker):-3]
            buf = []
        elif current is not None:
            buf.append(line)
    if current is not None and current != "END":
        sections[current] = "\n".join(buf)
    sections.pop("END", None)
    sections.pop("BASELINE_SLEEP", None)
    return sections
