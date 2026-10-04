"""End-to-end tests against a real sshd. Enabled when these are set (CI starts a throwaway sshd):

  PULSEOPS_TEST_SSH_HOST  (default 127.0.0.1)
  PULSEOPS_TEST_SSH_PORT
  PULSEOPS_TEST_SSH_USER
  PULSEOPS_TEST_SSH_KEY   private key accepted for that user
"""
import json
import os
import subprocess
import sys

import pytest

PORT = os.environ.get("PULSEOPS_TEST_SSH_PORT")
pytestmark = pytest.mark.skipif(not PORT, reason="no test sshd configured (PULSEOPS_TEST_SSH_PORT)")

HOST = os.environ.get("PULSEOPS_TEST_SSH_HOST", "127.0.0.1")
USER = os.environ.get("PULSEOPS_TEST_SSH_USER", "")
KEY = os.environ.get("PULSEOPS_TEST_SSH_KEY", "")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = ["-m", "pulseops"]


@pytest.fixture
def home(tmp_path):
    env = {k: v for k, v in os.environ.items() if k not in ("SSH_AUTH_SOCK", "PULSEOPS_SSH_PASSWORD")}
    env.update(HOME=str(tmp_path), XDG_CONFIG_HOME=str(tmp_path / "config"), XDG_CACHE_HOME=str(tmp_path / "cache"))
    return tmp_path, env


def pulseops(env, *args):
    r = subprocess.run([sys.executable, *CLI, *args], env=env, cwd=REPO, capture_output=True, text=True,
                       stdin=subprocess.DEVNULL, timeout=120)
    return r.returncode, r.stdout, r.stderr


def accept_new(home_dir):
    cfg = home_dir / "config" / "pulseops"
    cfg.mkdir(parents=True, exist_ok=True)
    (cfg / "config.toml").write_text('[ssh]\nhost_key_checking = "accept-new"\n')


def test_unknown_host_is_refused_then_accepted_then_pinned(home):
    home_dir, env = home
    target = [f"{USER}@{HOST}", "-p", PORT, "-k", KEY]

    code, _, err = pulseops(env, "check", *target)
    assert code == 3 and "tanınmıyor" in err

    accept_new(home_dir)
    code, out, err = pulseops(env, "status", "--json", *target)
    assert code == 0, err
    data = json.loads(out)
    assert data["snapshot"]["hostname"] and data["snapshot"]["cpu"]["cores"] >= 1
    assert data["snapshot"]["top_processes"]
    known = (home_dir / ".ssh" / "known_hosts").read_text()
    entry = HOST if PORT == "22" else f"[{HOST}]:{PORT}"
    assert known.startswith(f"{entry} ")

    # Simulate a changed server key: the stored key no longer matches -> hard refusal
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(home_dir / "other")], check=True)
    kind, b64 = (home_dir / "other.pub").read_text().split()[:2]
    (home_dir / ".ssh" / "known_hosts").write_text(f"{entry} {kind} {b64}\n")
    code, _, err = pulseops(env, "check", *target)
    assert code == 3 and "KİMLİĞİ DEĞİŞMİŞ" in err


def test_ssh_config_alias_and_proxy_jump(home):
    home_dir, env = home
    accept_new(home_dir)
    (home_dir / ".ssh").mkdir(exist_ok=True)
    (home_dir / ".ssh" / "config").write_text(
        f"Host bastion\n  HostName {HOST}\n  Port {PORT}\n  User {USER}\n  IdentityFile {KEY}\n"
        f"Host target\n  HostName {HOST}\n  Port {PORT}\n  User {USER}\n  IdentityFile {KEY}\n  ProxyJump bastion\n"
    )
    code, out, err = pulseops(env, "status", "--json", "target")
    assert code == 0, err
    assert json.loads(out)["snapshot"]["hostname"]


def test_remote_probe_matches_privileges(home):
    home_dir, env = home
    accept_new(home_dir)
    code, out, err = pulseops(env, "status", "--json", f"{USER}@{HOST}", "-p", PORT, "-k", KEY)
    assert code == 0, err
    priv = json.loads(out)["privileges"]
    assert priv["user"] == USER
    assert priv["is_root"] == (USER == "root")


def _collector(home_dir, monkeypatch):
    from pulseops.collectors.probe_collector import ProbeCollector
    from pulseops.collectors.transport import SSHTarget, SSHTransport

    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)
    target = SSHTarget(alias=HOST, hostname=HOST, port=int(PORT), username=USER, key_filenames=[KEY])
    transport = SSHTransport(target, host_key_mode="accept-new", connect_timeout=5)
    return transport, ProbeCollector(transport, fast_timeout=10, slow_timeout=30)


def test_reconnects_after_the_connection_dies(home, monkeypatch):
    """Idle sessions get dropped by NAT/firewalls and sshd restarts; polling must recover by itself."""
    home_dir, _ = home
    transport, collector = _collector(home_dir, monkeypatch)
    try:
        first = collector.collect()
        old_client = transport._client

        # 1) The server side goes away: kill this connection's sshd session process
        try:
            old_client.exec_command("kill -9 $PPID", timeout=5)[1].read()
        except Exception:
            pass
        t = collector.collect(include_slow=False)
        assert transport._client is not old_client
        assert t.snapshot.hostname == first.snapshot.hostname

        # 2) The socket dies under us without any SSH-level goodbye
        transport._client.get_transport().sock.close()
        t = collector.collect(include_slow=False)
        assert 0.0 <= t.snapshot.cpu.total_percent <= 100.0
    finally:
        collector.close()


def test_unreachable_host_fails_fast_and_recovers(home, monkeypatch):
    """While the host is down every poll fails quickly with a TransportError; afterwards it works again."""
    import time

    from pulseops.collectors.transport import TransportError

    home_dir, _ = home
    transport, collector = _collector(home_dir, monkeypatch)
    try:
        collector.collect()
        real_port = transport.target.port
        transport.target.port = 1  # nothing listens there: connection refused
        transport._close_client()
        started = time.monotonic()
        with pytest.raises(TransportError):
            collector.collect(include_slow=False)
        assert time.monotonic() - started < 15
        transport.target.port = real_port
        assert collector.collect(include_slow=False).snapshot.hostname
    finally:
        collector.close()
