"""SSH host key verification, following OpenSSH's StrictHostKeyChecking semantics.

Known keys come from ~/.ssh/known_hosts and /etc/ssh/ssh_known_hosts (hashed entries included).
A key that differs from the known one is always refused (paramiko raises BadHostKeyException).
For an unknown host:
  * "ask"        - show the fingerprint and ask (only possible on an interactive terminal)
  * "accept-new" - trust and remember it (trust on first use)
  * "yes"        - refuse
"""
import base64
import hashlib
import os
from pathlib import Path
from typing import Callable, Optional

import paramiko

MODES = ("ask", "accept-new", "yes")

ConfirmFn = Callable[[str, str, str], bool]  # (host entry, key type, fingerprint) -> accept?


class UnknownHostKeyError(paramiko.SSHException):
    def __init__(self, host_entry: str, key_type: str, fingerprint: str):
        self.host_entry = host_entry
        self.key_type = key_type
        self.fingerprint = fingerprint
        super().__init__(
            f"{host_entry} sunucusunun anahtarı tanınmıyor ({key_type} {fingerprint}). "
            "Bir kez etkileşimli terminalden bağlanıp parmak izini onaylayın "
            "veya `ssh` ile bağlanarak known_hosts dosyasına ekleyin."
        )


def user_known_hosts() -> Path:
    return Path.home() / ".ssh" / "known_hosts"


SYSTEM_KNOWN_HOSTS = Path("/etc/ssh/ssh_known_hosts")


def fingerprint(key: paramiko.PKey) -> str:
    """OpenSSH style: SHA256:<unpadded base64>"""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def append_known_host(path: Path, host_entry: str, key: paramiko.PKey) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(f"{host_entry} {key.get_name()} {key.get_base64()}\n")


def load_known_hosts(client: paramiko.SSHClient, user_file: Optional[Path] = None) -> None:
    for path in (SYSTEM_KNOWN_HOSTS, user_file or user_known_hosts()):
        if path.is_file():
            try:
                client.load_system_host_keys(str(path))
            except (OSError, paramiko.SSHException):
                continue


class VerifyingHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Called by paramiko only for hosts that are not in any loaded known_hosts file."""

    def __init__(self, mode: str = "ask", confirm: Optional[ConfirmFn] = None, user_file: Optional[Path] = None):
        if mode not in MODES:
            raise ValueError(f"bilinmeyen host key modu: {mode}")
        self.mode = mode
        self.confirm = confirm
        self.user_file = user_file or user_known_hosts()

    def missing_host_key(self, client, hostname, key):
        fp = fingerprint(key)
        accepted = self.mode == "accept-new" or (
            self.mode == "ask" and self.confirm is not None and self.confirm(hostname, key.get_name(), fp)
        )
        if not accepted:
            raise UnknownHostKeyError(hostname, key.get_name(), fp)
        append_known_host(self.user_file, hostname, key)
        client.get_host_keys().add(hostname, key.get_name(), key)


def describe_bad_host_key(error: paramiko.BadHostKeyException) -> str:
    return (
        f"UYARI: {error.hostname} SUNUCUSUNUN KİMLİĞİ DEĞİŞMİŞ! Biri araya giriyor olabilir (MITM).\n"
        f"   Beklenen: {error.expected_key.get_name()} {fingerprint(error.expected_key)}\n"
        f"   Gelen:    {error.key.get_name()} {fingerprint(error.key)}\n"
        "   Anahtar gerçekten değiştiyse eski kaydı silin: ssh-keygen -R <sunucu>"
    )
