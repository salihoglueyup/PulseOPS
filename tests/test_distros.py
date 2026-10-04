"""Runs the real probe inside real Linux distributions (Docker containers) and checks the parsed result.

The containers are bare images: no ss, ps, systemd or sudo on most of them, busybox on Alpine. This is
exactly what catches parser assumptions about tool output formats.

Enabled with PULSEOPS_TEST_DISTROS="ubuntu:24.04 debian:12 alpine:3.20 ..." (docker must be usable).
With PULSEOPS_TEST_DISTRO_PROVISION=1 the containers are first turned into small servers
(tests/distro_provision.sh: ss, ps, sudo, sshd on :22, a `deploy` user with passwordless sudo) and
the parsed ports, sshd configuration and sudo detection are checked as well.
"""
import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

from collectors.probe_collector import ProbeCollector
from collectors.transport import TransportError

IMAGES = os.environ.get("PULSEOPS_TEST_DISTROS", "").split()
PROVISION = os.environ.get("PULSEOPS_TEST_DISTRO_PROVISION") == "1"
PROVISION_SCRIPT = Path(__file__).with_name("distro_provision.sh")

pytestmark = pytest.mark.skipif(not IMAGES or not shutil.which("docker"), reason="PULSEOPS_TEST_DISTROS not set")


class DockerExecTransport:
    """Runs the probe with `docker exec -i <container> sh -s`, like LocalTransport does on the host."""

    name = "docker"

    def __init__(self, container: str, user: str = "0"):
        self.container, self.user = container, user

    def run(self, script: str, timeout: float) -> str:
        try:
            result = subprocess.run(
                ["docker", "exec", "-i", "-u", self.user, self.container, "sh", "-s"],
                input=script, capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            raise TransportError(f"probe timed out in {self.container}") from e
        return result.stdout

    def close(self) -> None:
        pass


@pytest.fixture(params=IMAGES or ["none"])
def container(request):
    name = f"pulseops-distro-{uuid.uuid4().hex[:8]}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name, "--hostname", "pulseops-distro", request.param,
         "sleep", "600"],
        check=True, capture_output=True,
    )
    if PROVISION:
        result = subprocess.run(["docker", "exec", "-i", name, "sh", "-s"], input=PROVISION_SCRIPT.read_text(),
                                capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True)
            pytest.fail(f"provisioning {request.param} failed:\n{result.stdout}\n{result.stderr}")
    yield request.param, name
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def collect_twice(collector):
    first = collector.collect(include_slow=True, include_logs=True)
    second = collector.collect(include_slow=False, include_logs=False)
    return first, second


USERS = {"root": "0", "nobody": "65534"} | ({"deploy": "deploy"} if PROVISION else {})


@pytest.mark.parametrize("user", list(USERS))
def test_probe_on_distro(container, user):
    image, name = container
    collector = ProbeCollector(DockerExecTransport(name, USERS[user]), fast_timeout=30, slow_timeout=90)
    first, t = collect_twice(collector)
    s = t.snapshot

    assert s.hostname == "pulseops-distro", image
    assert s.cpu.cores >= 1
    assert 0.0 <= s.cpu.total_percent <= 100.0
    assert s.memory.total_bytes > 0 and 0.0 <= s.memory.percent <= 100.0
    assert s.uptime_seconds > 0
    assert any(d.mountpoint == "/" and d.total_bytes > 0 for d in s.disks), (image, s.disks)
    assert any("sleep" in p.name for p in s.top_processes), (image, [p.name for p in s.top_processes])

    priv = t.privileges
    assert priv.user == user, (image, priv)
    assert priv.is_root == (user == "root")
    # No firewall tooling in a bare container: state must be unknown or inactive, never "active"
    assert not s.firewall.is_active
    # Unreadable / absent data must not turn into confident claims
    assert t.security.auth.failed_total == 0
    assert first.machine_id == t.machine_id
    # Package manager detected; a bare image has no package index, which must read as unknown, not "0"
    family = {"alpine": "apk", "ubuntu": "apt", "debian": "apt", "almalinux": "dnf"}[image.split(":")[0]]
    assert first.security.updates.manager == family, (image, first.security.updates)
    if not PROVISION:
        assert not first.security.updates.known, (image, first.security.updates)
    elif family == "apt" or (family == "dnf" and user != "nobody"):
        assert first.security.updates.known, (image, user, first.security.updates)

    if not PROVISION:
        return
    # Root and the sudo user see every socket owner; nobody still sees the port itself
    ssh_ports = [p for p in t.ports if p.port == 22 and p.proto == "tcp"]
    assert ssh_ports, (image, user, t.ports)
    if user != "nobody":
        assert priv.elevated, (image, priv)
        assert any(p.process_name and "sshd" in p.process_name for p in ssh_ports), (image, user, ssh_ports)
        # Distros ship different defaults (RHEL: root login allowed); what matters is that we report
        # exactly what sshd itself says its effective configuration is
        effective = dict(
            line.split(" ", 1) for line in subprocess.run(
                ["docker", "exec", name, "/usr/sbin/sshd", "-T"], capture_output=True, text=True,
            ).stdout.splitlines() if " " in line
        )
        ssh = t.security.ssh
        assert ssh.port == 22, (image, ssh)
        assert (ssh.permit_root_login, ssh.password_authentication, ssh.pubkey_authentication) == (
            # `sshd -T` prints the legacy alias of prohibit-password
            effective["permitrootlogin"].replace("without-password", "prohibit-password"),
            effective["passwordauthentication"], effective["pubkeyauthentication"],
        ), (image, ssh, effective)
        assert t.security.access.sudoers_known and "deploy" in t.security.access.sudo_rule_users, (image, t.security.access)
        assert any("deploy" in rule for rule in t.security.access.nopasswd_rules), (image, t.security.access)
    else:
        assert not priv.elevated
