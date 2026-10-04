"""Security drift detection: what changed on the host since the previous observation.

A fingerprint maps each category to a sorted list of items, or None when that category could not be
read this time (e.g. sudoers without root). Categories are only compared when both sides were
readable, so a permission change never shows up as "everything was removed".
"""
from typing import Optional

from pydantic import BaseModel

from pulseops.models.ports import PortExposure
from pulseops.models.services import ServiceState
from pulseops.models.telemetry import Telemetry

# Loopback services in the kernel's ephemeral range are usually short-lived helper sockets
EPHEMERAL_PORTS = range(32768, 61000)

HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"


class Change(BaseModel):
    category: str
    severity: str
    message: str


Fingerprint = dict[str, Optional[list[str]]]


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "localhost")


def fingerprint(t: Telemetry) -> Fingerprint:
    sec = t.security
    access = sec.access
    fp: Fingerprint = {}

    # Ports are compared on proto/ip/port only: the owning process name depends on the observer's
    # privileges and changes on restarts. The name is kept after a tab, for messages.
    public, local = {}, {}
    for p in t.ports:
        if p.exposure == PortExposure.SYSTEM_RPC:
            continue
        key = f"{p.proto} {p.ip}:{p.port}"
        bucket = local if _is_loopback(p.ip) else public
        if bucket is local and p.port in EPHEMERAL_PORTS:
            continue
        if p.process_name or key not in bucket:
            bucket[key] = f"{key}\t{p.process_name or '?'}"
    fp["ports_public"] = sorted(public.values())
    fp["ports_local"] = sorted(local.values())

    fp["login_users"] = sorted(access.login_users) if access.login_users else None
    fp["uid0_users"] = sorted(access.uid0_users) if access.uid0_users else None
    fp["admin_users"] = sorted(access.admin_users) if access.login_users else None
    fp["nopasswd_rules"] = sorted(access.nopasswd_rules) if access.sudoers_known else None
    fp["sudo_rule_users"] = sorted(access.sudo_rule_users) if access.sudoers_known else None
    # Only when docker itself was readable: otherwise "no risky container" just means "could not look"
    fp["container_risks"] = sorted(
        f"{c.name}: {r.text}" for c in t.containers if c.security for r in c.security.risks if r.severity == "HIGH"
    ) if t.privileges.docker_access else None
    hard = sec.hardening
    fp["suid_files"] = sorted(hard.suid_files) if hard.known else None
    fp["suspicious_suid"] = sorted(hard.suspicious_suid) if hard.suspicious_suid is not None else None
    fp["empty_password_users"] = (sorted(hard.empty_password_users)
                                  if hard.empty_password_users is not None else None)
    fp["world_writable"] = sorted(hard.world_writable) if hard.known else None
    fp["permission_problems"] = (sorted(c.problem for c in hard.failed if c.id.startswith("perm:"))
                                 if hard.known else None)
    fp["authorized_keys"] = (
        sorted([f"{user}={count}" for user, count in access.authorized_keys.items()]
               + [f"{user}=?" for user in access.authorized_keys_unknown])
        if access.keys_known else None
    )
    fp["firewall"] = [("active" if sec.firewall_active else "inactive")] if sec.firewall_known else None
    if sec.ssh.permit_root_login in ("?", "KAPALI"):
        fp["sshd"] = None
    else:
        fp["sshd"] = [f"PermitRootLogin={sec.ssh.permit_root_login}",
                      f"PasswordAuthentication={sec.ssh.password_authentication}"]
    fp["failed_services"] = sorted(s.name for s in t.services if s.state == ServiceState.FAILED)
    fp["fail2ban"] = (
        None if not sec.fail2ban.installed or not sec.fail2ban.known
        else [("running" if sec.fail2ban.running is not False else "stopped")]
    )
    fp["containers"] = sorted(f"{c.name} ({c.image})" for c in t.containers)
    return fp


def _added_removed(old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    return sorted(set(new) - set(old)), sorted(set(old) - set(new))


def diff(old: Fingerprint, new: Fingerprint) -> list[Change]:
    changes: list[Change] = []

    def both(key: str) -> bool:
        return old.get(key) is not None and new.get(key) is not None

    def add(category: str, severity: str, message: str) -> None:
        changes.append(Change(category=category, severity=severity, message=message))

    for key, label_new, label_closed in (("ports_public", "Yeni dışa açık port", "Dışa açık port kapandı"),
                                         ("ports_local", "Yeni yerel port", None)):
        if not both(key):
            continue
        before = dict(item.split("\t", 1) if "\t" in item else (item.rsplit(" (", 1)[0], "?") for item in old[key])
        after = dict(item.split("\t", 1) if "\t" in item else (item.rsplit(" (", 1)[0], "?") for item in new[key])
        severity = HIGH if key == "ports_public" else INFO
        for port in sorted(set(after) - set(before)):
            add("port", severity, f"{label_new}: {port} ({after[port]})")
        if label_closed:
            for port in sorted(set(before) - set(after)):
                add("port", INFO, f"{label_closed}: {port} ({before[port]})")

    if both("uid0_users"):
        added, _ = _added_removed(old["uid0_users"], new["uid0_users"])
        for user in added:
            add("account", HIGH, f"Yeni UID 0 (root yetkili) hesap: {user}")
    if both("login_users"):
        added, removed = _added_removed(old["login_users"], new["login_users"])
        for user in added:
            add("account", MEDIUM, f"Yeni giriş yapabilen hesap: {user}")
        for user in removed:
            add("account", INFO, f"Hesap kaldırıldı / girişi kapatıldı: {user}")
    if both("admin_users"):
        added, removed = _added_removed(old["admin_users"], new["admin_users"])
        for user in added:
            add("account", HIGH, f"sudo/wheel grubuna eklendi: {user}")
        for user in removed:
            add("account", INFO, f"sudo/wheel grubundan çıkarıldı: {user}")
    if both("nopasswd_rules"):
        added, removed = _added_removed(old["nopasswd_rules"], new["nopasswd_rules"])
        for rule in added:
            add("sudo", HIGH, f"Yeni NOPASSWD sudo kuralı: {rule}")
        for rule in removed:
            add("sudo", INFO, f"NOPASSWD sudo kuralı kaldırıldı: {rule}")
    if both("sudo_rule_users"):
        added, removed = _added_removed(old["sudo_rule_users"], new["sudo_rule_users"])
        for subject in added:
            add("sudo", HIGH, f"sudoers ile yetki verildi: {subject}")
        for subject in removed:
            add("sudo", INFO, f"sudoers yetkisi kaldırıldı: {subject}")
    if both("container_risks"):
        added, removed = _added_removed(old["container_risks"], new["container_risks"])
        for risk in added:
            add("container", HIGH, f"Riskli konteyner: {risk}")
        for risk in removed:
            add("container", INFO, f"Konteyner riski kalktı: {risk}")
    if both("suid_files"):
        added, removed = _added_removed(old["suid_files"], new["suid_files"])
        for path in added:
            add("hardening", HIGH, f"Yeni SUID/SGID dosya: {path}")
        for path in removed:
            add("hardening", INFO, f"SUID/SGID dosya kaldırıldı: {path}")
    if both("suspicious_suid"):
        for path in _added_removed(old["suspicious_suid"], new["suspicious_suid"])[0]:
            add("hardening", HIGH, f"Şüpheli konumda SUID/SGID dosya: {path}")
    if both("empty_password_users"):
        for user in _added_removed(old["empty_password_users"], new["empty_password_users"])[0]:
            add("account", HIGH, f"Parolası boşaltılan hesap: {user}")
    if both("world_writable"):
        for path in _added_removed(old["world_writable"], new["world_writable"])[0]:
            add("hardening", HIGH, f"Herkesin yazabildiği sistem dosyası: {path}")
    if both("permission_problems"):
        added, removed = _added_removed(old["permission_problems"], new["permission_problems"])
        for problem in added:
            add("hardening", HIGH, f"Dosya izni bozuldu: {problem}")
        for problem in removed:
            add("hardening", INFO, f"Dosya izni düzeltildi: {problem}")
    if both("authorized_keys"):
        before = dict(item.split("=", 1) for item in old["authorized_keys"])
        after = dict(item.split("=", 1) for item in new["authorized_keys"])
        for user in sorted(set(before) | set(after)):
            if before.get(user) == "?" or after.get(user) == "?":
                continue  # one of the observers could not read this user's keys
            b, a = int(before.get(user, 0)), int(after.get(user, 0))
            if a > b:
                add("ssh_key", HIGH, f"{user} hesabına {a - b} yeni SSH anahtarı eklendi ({b} → {a})")
            elif a < b:
                add("ssh_key", INFO, f"{user} hesabından {b - a} SSH anahtarı kaldırıldı ({b} → {a})")

    if both("firewall") and old["firewall"] != new["firewall"]:
        if new["firewall"] == ["inactive"]:
            add("firewall", HIGH, "Güvenlik duvarı KAPATILDI")
        else:
            add("firewall", INFO, "Güvenlik duvarı açıldı")
    if both("sshd"):
        for before, after in zip(old["sshd"], new["sshd"]):
            if before != after:
                weaker = after.endswith("=yes")
                add("sshd", HIGH if weaker else INFO, f"sshd ayarı değişti: {before} → {after.split('=', 1)[1]}")
    if both("fail2ban") and old["fail2ban"] != new["fail2ban"]:
        add("fail2ban", HIGH if new["fail2ban"] == ["stopped"] else INFO,
            "fail2ban DURDU" if new["fail2ban"] == ["stopped"] else "fail2ban yeniden çalışıyor")
    if both("failed_services"):
        added, removed = _added_removed(old["failed_services"], new["failed_services"])
        for name in added:
            add("service", MEDIUM, f"Servis çöktü: {name}")
        for name in removed:
            add("service", INFO, f"Servis düzeldi: {name}")
    if both("containers"):
        added, removed = _added_removed(old["containers"], new["containers"])
        for item in added:
            add("container", INFO, f"Yeni konteyner: {item}")
        for item in removed:
            add("container", INFO, f"Konteyner kaldırıldı: {item}")

    order = {HIGH: 0, MEDIUM: 1, INFO: 2}
    return sorted(changes, key=lambda c: order[c.severity])
