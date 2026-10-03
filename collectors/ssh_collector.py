"""Agentless remote collector: runs the shared probe on a Linux host over SSH."""
from typing import Optional

from collectors.probe_collector import ProbeCollector
from collectors.transport import SSHTransport


class SSHCollector(ProbeCollector):
    def __init__(
        self,
        host: str,
        username: str = "root",
        port: int = 22,
        key_filename: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 8.0,
        use_sudo: bool = True,
    ):
        super().__init__(
            SSHTransport(host, username, port, key_filename, password, connect_timeout=timeout),
            use_sudo=use_sudo,
        )
        self.host = host
        self.username = username
        self.port = port

    def test_connection(self) -> None:
        self.transport.test_connection()
