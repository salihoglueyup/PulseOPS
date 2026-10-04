"""Agentless remote collector: runs the shared probe on a Linux host over SSH."""
from pulseops.collectors.probe_collector import ProbeCollector
from pulseops.collectors.transport import SSHTransport


class SSHCollector(ProbeCollector):
    def __init__(self, transport: SSHTransport, use_sudo: bool = True):
        super().__init__(transport, use_sudo=use_sudo)
        self.host = transport.target.hostname
        self.username = transport.target.username
        self.port = transport.target.port

    def test_connection(self) -> None:
        self.transport.test_connection()
