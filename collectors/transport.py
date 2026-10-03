"""Where the probe script runs: this machine or a remote host over SSH.

Both feed the script to `sh -s` on stdin, which works whatever the login shell is (bash, zsh, fish).
"""
import subprocess
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import paramiko

from collectors.hostkeys import (
    ConfirmFn,
    UnknownHostKeyError,
    VerifyingHostKeyPolicy,
    describe_bad_host_key,
    load_known_hosts,
)


class TransportError(RuntimeError):
    pass


class LocalTransport:
    name = "local"

    def run(self, script: str, timeout: float) -> str:
        try:
            result = subprocess.run(["sh", "-s"], input=script, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            raise TransportError(f"Yerel probe {timeout:.0f} sn içinde bitmedi") from e
        except OSError as e:
            raise TransportError(f"Yerel probe çalıştırılamadı: {e}") from e
        return result.stdout

    def close(self) -> None:
        pass


@dataclass
class SSHTarget:
    """Where and how to connect, after merging command line flags with ~/.ssh/config."""

    alias: str
    hostname: str
    port: int = 22
    username: str = "root"
    key_filenames: list[str] = field(default_factory=list)
    proxy_jump: Optional[str] = None
    proxy_command: Optional[str] = None

    @property
    def label(self) -> str:
        return f"{self.username}@{self.hostname}:{self.port}"


def _ssh_config(path: Optional[Path] = None) -> Optional[paramiko.SSHConfig]:
    path = path or Path.home() / ".ssh" / "config"
    try:
        return paramiko.SSHConfig.from_path(str(path)) if path.is_file() else None
    except (OSError, paramiko.SSHException, ValueError):
        return None


def parse_destination(spec: str) -> tuple[Optional[str], str, Optional[int]]:
    """'user@host:port' / 'host' / 'user@[::1]:22' -> (user, host, port)"""
    user = None
    if "@" in spec:
        user, spec = spec.rsplit("@", 1)
    port = None
    if spec.startswith("["):
        host, _, rest = spec[1:].partition("]")
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif spec.count(":") == 1:
        host, _, port_str = spec.partition(":")
        if port_str.isdigit():
            port = int(port_str)
        else:
            host = spec
    else:
        host = spec
    return user or None, host, port


def resolve_target(
    destination: str,
    username: Optional[str] = None,
    port: Optional[int] = None,
    key_filename: Optional[str] = None,
    proxy_jump: Optional[str] = None,
    ssh_config_path: Optional[Path] = None,
) -> SSHTarget:
    """Command line values win over ~/.ssh/config, which wins over defaults (like OpenSSH)."""
    dest_user, alias, dest_port = parse_destination(destination)
    cfg = _ssh_config(ssh_config_path)
    entry = cfg.lookup(alias) if cfg else {"hostname": alias}

    keys = [str(Path(key_filename).expanduser())] if key_filename else list(entry.get("identityfile", []))
    cfg_port = entry.get("port")
    jump = proxy_jump if proxy_jump is not None else entry.get("proxyjump")
    if jump and jump.lower() == "none":
        jump = None
    proxy_command = entry.get("proxycommand")
    if proxy_command and proxy_command.lower() == "none":
        proxy_command = None
    return SSHTarget(
        alias=alias,
        hostname=entry.get("hostname", alias),
        port=port or dest_port or (int(cfg_port) if cfg_port and str(cfg_port).isdigit() else 22),
        username=username or dest_user or entry.get("user") or "root",
        key_filenames=keys,
        proxy_jump=jump,
        proxy_command=proxy_command,
    )


class SSHTransport:
    name = "ssh"

    def __init__(
        self,
        target: SSHTarget,
        password: Optional[str] = None,
        passphrase: Optional[str] = None,
        connect_timeout: float = 8.0,
        host_key_mode: str = "ask",
        confirm_host_key: Optional[ConfirmFn] = None,
        ssh_config_path: Optional[Path] = None,
    ):
        self.target = target
        self.password = password
        self.passphrase = passphrase
        self.connect_timeout = connect_timeout
        self.host_key_mode = host_key_mode
        self.confirm_host_key = confirm_host_key
        self.ssh_config_path = ssh_config_path
        self._client: Optional[paramiko.SSHClient] = None
        self._jump: Optional["SSHTransport"] = None
        self._lock = threading.Lock()

    # Backwards compatible attribute names
    @property
    def host(self) -> str:
        return self.target.hostname

    def disable_prompts(self) -> None:
        """After startup no prompt may block a background thread; unknown keys are then refused."""
        self.confirm_host_key = None
        if self._jump is not None:
            self._jump.disable_prompts()

    def _sock(self):
        if self.target.proxy_jump:
            hops = [h.strip() for h in self.target.proxy_jump.split(",") if h.strip()]
            jump_target = resolve_target(
                hops[-1], proxy_jump=",".join(hops[:-1]) or None, ssh_config_path=self.ssh_config_path,
            )
            if self._jump is None:
                self._jump = SSHTransport(
                    jump_target,
                    connect_timeout=self.connect_timeout,
                    host_key_mode=self.host_key_mode,
                    confirm_host_key=self.confirm_host_key,
                    ssh_config_path=self.ssh_config_path,
                )
            jump_client = self._jump._connect()
            return jump_client.get_transport().open_channel(
                "direct-tcpip", (self.target.hostname, self.target.port), ("127.0.0.1", 0), timeout=self.connect_timeout,
            )
        if self.target.proxy_command:
            command = (self.target.proxy_command.replace("%h", self.target.hostname)
                       .replace("%p", str(self.target.port)).replace("%r", self.target.username))
            return paramiko.ProxyCommand(command)
        return None

    def _connect(self) -> paramiko.SSHClient:
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self._close_client()

        client = paramiko.SSHClient()
        load_known_hosts(client)
        client.set_missing_host_key_policy(VerifyingHostKeyPolicy(self.host_key_mode, self.confirm_host_key))
        kwargs = {
            "hostname": self.target.hostname,
            "port": self.target.port,
            "username": self.target.username,
            "timeout": self.connect_timeout,
            "banner_timeout": self.connect_timeout,
            "auth_timeout": self.connect_timeout,
            "sock": self._sock(),
            # ssh-agent and ~/.ssh/id_* are tried automatically (allow_agent / look_for_keys)
        }
        if self.target.key_filenames:
            kwargs["key_filename"] = self.target.key_filenames
        if self.password:
            kwargs["password"] = self.password
        if self.passphrase:
            kwargs["passphrase"] = self.passphrase
        try:
            client.connect(**kwargs)
        except Exception:
            client.close()
            raise
        transport = client.get_transport()
        if transport is not None:
            transport.set_keepalive(15)
        self._client = client
        return client

    def _exec(self, script: str, timeout: float) -> str:
        client = self._connect()
        stdin, stdout, _ = client.exec_command("sh -s", timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        return stdout.read().decode("utf-8", errors="replace")

    def run(self, script: str, timeout: float) -> str:
        with self._lock:
            try:
                return self._exec(script, timeout)
            except (paramiko.BadHostKeyException, UnknownHostKeyError, paramiko.AuthenticationException) as e:
                # Never retry these: a changed host key or rejected credentials will not fix themselves
                self._close_client()
                raise TransportError(_describe(e, self.target)) from e
            except Exception:
                # One transparent reconnect: idle SSH sessions are often dropped by NAT/firewalls
                self._close_client()
                try:
                    return self._exec(script, timeout)
                except Exception as e:
                    self._close_client()
                    raise TransportError(_describe(e, self.target)) from e

    def test_connection(self) -> None:
        """Connects (raising paramiko's own exceptions, so the caller can prompt) and runs a no-op."""
        with self._lock:
            out = self._exec("echo PULSEOPS_OK\n", timeout=min(self.connect_timeout, 5.0))
        if "PULSEOPS_OK" not in out:
            raise TransportError(f"Uzak sunucu beklenen yanıtı vermedi: {out.strip()[:200]!r}")

    def _close_client(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None

    def close(self) -> None:
        self._close_client()
        if self._jump is not None:
            self._jump.close()
            self._jump = None


def _describe(error: Exception, target: SSHTarget) -> str:
    if isinstance(error, paramiko.BadHostKeyException):
        return describe_bad_host_key(error)
    if isinstance(error, paramiko.AuthenticationException):
        return f"SSH kimlik doğrulaması reddedildi ({target.label})"
    return f"SSH {target.label}: {error}"
