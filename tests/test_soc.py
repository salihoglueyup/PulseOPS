import shutil
import subprocess

import pytest

from pulseops.collectors import probe_parsers as pp
from pulseops.collectors.audit_exporter import calculate_audit_score
from pulseops.collectors.base import DemoCollector
from pulseops.collectors.probe import AUTH_AWK
from pulseops.collectors.security_collector import SecurityCollector
from pulseops.collectors.telemetry import collect_telemetry, summarize_alerts
from pulseops.models.security import AccessAudit, AuthActivity, CountedItem, Fail2banJail, Fail2banStatus, SSHSecurityAudit
from pulseops.models.system import FirewallStatus

# Real OpenSSH 9.6 output for: 2 wrong root passwords, invalid users admin + oracle, a wrong deploy
# password, then a password login and two key logins. sshd logs "Connection closed by authenticating
# user" after each failed password too; that must not be counted twice.
SSHD_LOG = """\
Failed password for root from 127.0.0.1 port 49300 ssh2
Connection closed by authenticating user root 127.0.0.1 port 49300 [preauth]
Failed password for root from 127.0.0.1 port 49302 ssh2
Invalid user admin from 127.0.0.1 port 49306
Connection closed by authenticating user root 127.0.0.1 port 49302 [preauth]
Failed password for invalid user admin from 127.0.0.1 port 49306 ssh2
Invalid user oracle from 127.0.0.1 port 49312
Failed password for invalid user oracle from 127.0.0.1 port 49312 ssh2
Failed password for deploy from 127.0.0.1 port 54498 ssh2
Connection closed by authenticating user deploy 127.0.0.1 port 54498 [preauth]
Accepted password for deploy from 127.0.0.1 port 54500 ssh2
Accepted publickey for root from 127.0.0.1 port 54514 ssh2: ED25519 SHA256:G9zi
Accepted publickey for deploy from 127.0.0.1 port 54530 ssh2: ED25519 SHA256:G9zi
"""

# journalctl -o short-unix; a key-only server where a rejected key leaves only a pre-auth disconnect
JOURNAL = """\
1791050000.123456 web sshd[100]: Invalid user oracle from 203.0.113.9 port 40832
1791050002.000000 web sshd[101]: Failed password for root from 203.0.113.9 port 40840 ssh2
1791050003.000000 web sshd[102]: Failed password for root from 198.51.100.7 port 40841 ssh2
1791050004.000000 web sshd-session[103]: Connection closed by authenticating user deploy 198.51.100.7 port 51234 [preauth]
1791050005.000000 web sshd[104]: Accepted publickey for deploy from 192.0.2.10 port 51300 ssh2: ED25519 SHA256:abc
"""


def run_auth_awk(text):
    return subprocess.run(["sh", "-c", AUTH_AWK], input=text, capture_output=True, text=True, check=True).stdout


pytestmark_awk = pytest.mark.skipif(shutil.which("awk") is None or shutil.which("sort") is None, reason="needs awk")


@pytestmark_awk
def test_auth_summary_of_real_sshd_log():
    a = pp.parse_auth("SOURCE /var/log/auth.log\n" + run_auth_awk(SSHD_LOG))
    assert (a.known, a.failed, a.invalid_user, a.accepted, a.accepted_password) == (True, 3, 2, 3, 1)
    assert a.failed_total == 5
    assert a.top_sources == [CountedItem(value="127.0.0.1", count=5)]
    assert {u.value: u.count for u in a.top_users} == {"root": 2, "admin": 1, "oracle": 1, "deploy": 1}
    assert [(e.method, e.user) for e in a.recent_accepted] == [("password", "deploy"), ("publickey", "root"), ("publickey", "deploy")]
    assert a.window == "son 20.000 log satırı"


@pytestmark_awk
def test_auth_summary_of_journal_counts_key_probes():
    a = pp.parse_auth("SOURCE journal\n" + run_auth_awk(JOURNAL))
    assert (a.failed, a.invalid_user, a.accepted) == (3, 1, 1)
    assert a.window == "son 24 saat"
    assert a.recent_accepted[0].time.startswith("2026-") and a.recent_accepted[0].source == "192.0.2.10"


@pytestmark_awk
def test_auth_summary_keeps_only_top_ten():
    log = "".join(f"Failed password for root from 10.0.{i // 250}.{i % 250} port {i} ssh2\n" for i in range(500))
    out = run_auth_awk(log)
    assert out.count("FIP ") == 10 and "FAILED 500" in out


def test_parse_auth_unknown_and_none():
    assert not pp.parse_auth("UNKNOWN").known
    assert not pp.parse_auth("SOURCE none\nFAILED 0").known
    assert not pp.parse_auth("").known


def test_parse_access():
    audit = pp.parse_access(
        "#UID0\nroot\ntoor\n#ADMINS\nsudo:x:27:ubuntu,deploy\nwheel:x:10:\n#LOGIN\nroot\nubuntu\ndeploy\n"
        "#SUDOERS\n%sudo ALL=(ALL) NOPASSWD: ALL\n#AUTHKEYS\nroot 1\ndeploy 3\nubuntu ?\n"
    )
    assert audit.extra_uid0 == ["toor"]
    assert audit.admin_users == ["ubuntu", "deploy"]
    assert audit.login_users == ["root", "ubuntu", "deploy"]
    assert audit.sudoers_known and audit.nopasswd_rules == ["%sudo ALL=(ALL) NOPASSWD: ALL"]
    assert audit.authorized_keys == {"root": 1, "deploy": 3}

    unknown = pp.parse_access("#UID0\nroot\n#SUDOERS\nUNKNOWN\n#AUTHKEYS\n")
    assert not unknown.sudoers_known and unknown.nopasswd_rules == [] and not unknown.keys_known
    assert unknown.sudo_rule_users == []


def test_sudoers_rules_outside_admin_groups():
    audit = pp.parse_access(
        "#SUDOERS\n"
        "Defaults env_reset\n"
        "Defaults:deploy !requiretty\n"
        "Cmnd_Alias RESTART = /bin/systemctl restart nginx\n"
        "User_Alias OPS = alice, bob\n"
        "root ALL=(ALL:ALL) ALL\n"
        "%sudo ALL=(ALL:ALL) ALL\n"
        "%wheel ALL=(ALL) NOPASSWD: ALL\n"
        "deploy ALL=(ALL) ALL\n"
        "ci, backup ALL=(root) NOPASSWD: RESTART\n"
        "%ops ALL=(ALL) ALL\n"
        "@includedir /etc/sudoers.d\n"
    )
    # A user with sudo rights but no sudo/wheel membership used to be invisible
    assert audit.sudo_rule_users == ["deploy", "ci", "backup", "%ops"]
    assert audit.nopasswd_rules == ["%wheel ALL=(ALL) NOPASSWD: ALL", "ci, backup ALL=(root) NOPASSWD: RESTART"]


def overview(**kw):
    defaults = dict(
        ssh_audit=SSHSecurityAudit(password_authentication="no"),
        firewall=FirewallStatus(is_active=True),
        ports=[],
    )
    defaults.update(kw)
    return SecurityCollector().build_overview(**defaults)


def test_brute_force_needs_fail2ban():
    attack = AuthActivity(known=True, source="journal", window="son 24 saat", failed=400, invalid_user=50,
                          top_sources=[CountedItem(value="203.0.113.9", count=300)])
    unprotected = overview(auth=attack)
    assert unprotected.overall_status == "DİKKAT GEREKTİRİYOR"
    assert any("[DIKKAT] SSH kaba kuvvet: 450" in r and "203.0.113.9 (300)" in r for r in unprotected.recommendations)

    jail = Fail2banStatus(installed=True, running=True, jails=[Fail2banJail(name="sshd", currently_banned=4)])
    protected = overview(auth=attack, fail2ban=jail)
    assert protected.overall_status == "GÜVENLİ"
    assert any(r.startswith("[BILGI] SSH: 450") and "4 IP" in r for r in protected.recommendations)


def test_extra_uid0_and_other_findings():
    sec = overview(
        ssh_audit=SSHSecurityAudit(password_authentication="yes"),
        access=AccessAudit(uid0_users=["root", "toor"], sudoers_known=True, nopasswd_rules=["x ALL=(ALL) NOPASSWD: ALL"]),
        auth=AuthActivity(known=True, window="son 24 saat", accepted=2, accepted_password=2),
        fail2ban=Fail2banStatus(installed=True, running=False),
    )
    text = "\n".join(sec.recommendations)
    assert sec.overall_status == "DİKKAT GEREKTİRİYOR"
    assert "UID 0 olan root disi hesap: 'toor'" in text
    assert "2 sifreyle basarili giris" in text
    assert "fail2ban kurulu ama calismiyor" in text
    assert "1 NOPASSWD kurali" in text


def test_unreadable_auth_is_reported_not_hidden():
    sec = overview(auth=AuthActivity(known=False))
    assert any("giris kayitlari okunamadi" in r for r in sec.recommendations)
    assert sec.overall_status == "GÜVENLİ"


def test_alerts_and_score_for_soc_findings():
    t = collect_telemetry(DemoCollector())
    base_score = calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)[0]
    assert not any("UID 0" in a or "kaba kuvvet" in a for a in summarize_alerts(t))  # demo: fail2ban protects ssh

    t.security.access.uid0_users = ["root", "toor"]
    t.security.fail2ban = Fail2banStatus(installed=False)
    alerts = summarize_alerts(t)
    assert "UID 0 hesap: toor" in alerts
    assert any(a.startswith("SSH kaba kuvvet: 512") for a in alerts)
    score = calculate_audit_score(t.snapshot, t.ports, t.routes, security=t.security, storage=t.storage)[0]
    assert score == max(15, base_score - 20 - 10)


def test_parse_fail2ban_permission_vs_stopped():
    assert pp.parse_fail2ban("INSTALLED\nRUNNING\nUNKNOWN\n").known is False      # running, socket not readable
    stopped = pp.parse_fail2ban("INSTALLED\nSTOPPED\nUNKNOWN\n")
    assert stopped.known and stopped.running is False


def test_parse_updates_apt_with_security_and_reboot():
    now = 1_800_000_000
    u = pp.parse_updates(
        "MANAGER apt\nMETA 1799913600\nSECPKG openssl\nSECPKG libc6\nTOTAL 12\nSECURITY 2\n"
        "KERNEL 6.8.0-40-generic\nKERNELS 6.8.0-40-generic 6.8.0-45-generic\n"
        "REBOOT yes\nREBOOT_PKG linux-image-6.8.0-45-generic\nREBOOT_PKG libc6\n", now)
    assert (u.manager, u.known, u.total, u.security) == ("apt", True, 12, 2)
    assert u.security_packages == ["openssl", "libc6"]
    assert round(u.metadata_age_days) == 1 and not u.metadata_stale
    assert u.reboot_required
    # A newer installed kernel is the more specific reason
    assert u.reboot_reason == "yeni çekirdek kurulu: 6.8.0-45-generic (çalışan 6.8.0-40-generic)"


def test_parse_updates_unknowns_are_not_zero():
    blind = pp.parse_updates("MANAGER dnf\nTOTAL UNKNOWN\nKERNEL 5.14.0-427.el9.x86_64\nKERNELS\n", 0)
    assert not blind.known and blind.security is None and blind.reboot_required is None
    assert blind.summary.startswith("okunamadı")
    apk = pp.parse_updates("MANAGER apk\nMETA 0\nTOTAL 3\nSECURITY UNKNOWN\n", 30 * 86400)
    assert apk.known and apk.security is None and apk.metadata_stale
    assert apk.summary == "3 bekliyor (güvenlik bilgisi yok), listeler 30 gün eski"
    # RHEL kernel versions order numerically, running == newest -> no reboot
    rhel = pp.parse_updates("MANAGER dnf\nTOTAL 0\nSECURITY 0\nKERNEL 5.14.0-427.el9.x86_64\n"
                            "KERNELS 5.14.0-70.el9.x86_64 5.14.0-427.el9.x86_64\n", 0)
    assert rhel.reboot_required is False
    assert pp.parse_updates("", 0).summary == "kontrol ediliyor"


def test_updates_raise_alerts_and_lower_the_score():
    from pulseops.collectors.audit_exporter import calculate_audit_score
    from pulseops.collectors.base import DemoCollector
    from pulseops.collectors.telemetry import collect_telemetry, summarize_alerts
    from pulseops.models.security import UpdateStatus

    t = collect_telemetry(DemoCollector())
    base, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage)
    t.security.updates = UpdateStatus(manager="apt", known=True, total=9, security=4, reboot_required=True,
                                      reboot_reason="x")
    alerts = summarize_alerts(t)
    assert "4 güvenlik güncellemesi bekliyor" in alerts and any("Yeniden başlatma" in a for a in alerts)
    assert calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage)[0] == base - 15


HARDEN_SAMPLE = """#SYSCTL
kernel/randomize_va_space 2
fs/protected_symlinks 0
net/ipv4/tcp_syncookies 1
net/ipv4/conf/all/rp_filter 0
net/ipv4/conf/default/rp_filter 2
net/ipv4/ip_forward 1
#MOUNTS
/tmp rw,nosuid,nodev,relatime
/dev/shm rw,relatime
#PERMS
644 root /etc/passwd
644 root /etc/shadow
440 root /etc/sudoers
#SUID
/usr/bin/sudo
/usr/bin/passwd
#SUID_SUSPECT
/tmp/.x/bash
#WORLD_WRITABLE
#EMPTY_PASSWORD
guest
"""


def test_parse_hardening():
    h = pp.parse_hardening(HARDEN_SAMPLE)
    by_id = {c.id: c for c in h.checks}
    assert h.known and h.ip_forward
    assert by_id["sysctl:kernel/randomize_va_space"].passed
    assert not by_id["sysctl:fs/protected_symlinks"].passed
    assert by_id["sysctl:net/ipv4/conf/all/rp_filter"].passed  # effective value is max(all, default)
    assert by_id["mount:/tmp"].passed and not by_id["mount:/dev/shm"].passed
    assert not by_id["perm:/etc/shadow"].passed and by_id["perm:/etc/passwd"].passed
    assert h.suspicious_suid == ["/tmp/.x/bash"] and h.empty_password_users == ["guest"]
    assert {c.problem for c in h.failed if c.severity == "HIGH"} == {
        "/etc/shadow herkes tarafından okunabiliyor",
        "Şüpheli konumda SUID/SGID dosya: /tmp/.x/bash",
        "Boş parolalı hesap: guest",
    }
    assert h.summary == f"{len(h.checks) - len(h.failed)}/{len(h.checks)} kontrol geçti, 3 kritik"


def test_parse_hardening_unknowns():
    h = pp.parse_hardening("#SYSCTL\n#SUID_SUSPECT\nUNKNOWN\n#WORLD_WRITABLE\n#EMPTY_PASSWORD\nUNKNOWN\n")
    assert h.known and h.suspicious_suid is None and h.empty_password_users is None
    assert {c.id for c in h.checks} == {"files:world-writable"}  # nothing unreadable is counted as passed
    assert not pp.parse_hardening("").known


def test_hardening_alerts_score_and_drift():
    from pulseops.collectors.audit_exporter import calculate_audit_score
    from pulseops.collectors.base import DemoCollector
    from pulseops.collectors.drift import HIGH, diff, fingerprint
    from pulseops.collectors.telemetry import collect_telemetry, summarize_alerts

    t = collect_telemetry(DemoCollector())
    base, _ = calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage)
    clean = t.model_copy(deep=True)
    clean.security.hardening = pp.parse_hardening(
        "#SYSCTL\nfs/protected_symlinks 1\n#SUID\n/usr/bin/sudo\n#SUID_SUSPECT\n#WORLD_WRITABLE\n#EMPTY_PASSWORD\n")
    t.security.hardening = pp.parse_hardening(HARDEN_SAMPLE)

    assert "Boş parolalı hesap: guest" in summarize_alerts(t)
    # 3 HIGH (-45) and 1 MEDIUM (-3)
    assert calculate_audit_score(t.snapshot, t.ports, t.routes, t.security, t.storage)[0] == max(15, base - 48)
    changes = {(c.severity, c.message) for c in diff(fingerprint(clean), fingerprint(t))}
    assert (HIGH, "Yeni SUID/SGID dosya: /usr/bin/passwd") in changes
    assert (HIGH, "Şüpheli konumda SUID/SGID dosya: /tmp/.x/bash") in changes
    assert (HIGH, "Parolası boşaltılan hesap: guest") in changes
    assert (HIGH, "Dosya izni bozuldu: /etc/shadow herkes tarafından okunabiliyor") in changes
