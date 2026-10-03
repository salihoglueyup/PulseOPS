"""Where the probe script runs: this machine or a remote host over SSH.

Both feed the script to `sh -s` on stdin, which works whatever the login shell is (bash, zsh, fish).
"""
import subprocess
import threading
from typing import Optional

import paramiko


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


class SSHTransport:
    name = "ssh"

    def __init__(
        self,
        host: str,
        username: str = "root",
        port: int = 22,
        key_filename: Optional[str] = None,
        password: Optional[str] = None,
        connect_timeout: float = 8.0,
    ):
        self.host = host
        self.username = username
        self.port = port
        self.key_filename = key_filename
        self.password = password
        self.connect_timeout = connect_timeout
        self._client: Optional[paramiko.SSHClient] = None
        self._lock = threading.Lock()

    def _connect(self) -> paramiko.SSHClient:
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self.close()

        client = paramiko.SSHClient()
        # TODO(phase 3): verify host keys against known_hosts instead of trusting on first use
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": self.connect_timeout,
            "banner_timeout": self.connect_timeout,
            "auth_timeout": self.connect_timeout,
        }
        if self.key_filename:
            kwargs["key_filename"] = self.key_filename
        if self.password:
            kwargs["password"] = self.password
        client.connect(**kwargs)
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
            except Exception:
                # One transparent reconnect: idle SSH sessions are often dropped by NAT/firewalls
                self.close()
                try:
                    return self._exec(script, timeout)
                except Exception as e:
                    self.close()
                    raise TransportError(f"SSH {self.username}@{self.host}:{self.port}: {e}") from e

    def test_connection(self) -> None:
        with self._lock:
            out = self._exec("echo PULSEOPS_OK\n", timeout=min(self.connect_timeout, 5.0))
        if "PULSEOPS_OK" not in out:
            raise TransportError(f"Uzak sunucu beklenen yanıtı vermedi: {out.strip()[:200]!r}")

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
        self._client = None
