import shutil
import stat
import subprocess

import paramiko
import pytest

import cli
from collectors.hostkeys import UnknownHostKeyError, VerifyingHostKeyPolicy, fingerprint, load_known_hosts
from collectors.transport import parse_destination, resolve_target


@pytest.mark.parametrize("spec,expected", [
    ("host", (None, "host", None)),
    ("deploy@host", ("deploy", "host", None)),
    ("deploy@host:2222", ("deploy", "host", 2222)),
    ("10.0.0.5:22", (None, "10.0.0.5", 22)),
    ("root@[::1]:2200", ("root", "::1", 2200)),
    ("fe80::1", (None, "fe80::1", None)),
])
def test_parse_destination(spec, expected):
    assert parse_destination(spec) == expected


def test_resolve_target_merges_ssh_config_with_cli_precedence(tmp_path):
    cfg = tmp_path / "config"
    cfg.write_text(
        "Host web\n  HostName 10.0.0.5\n  User deploy\n  Port 2200\n  IdentityFile ~/.ssh/id_web\n  ProxyJump bastion\n"
        "Host *\n  User fallback\n"
    )
    t = resolve_target("web", ssh_config_path=cfg)
    assert (t.hostname, t.port, t.username, t.proxy_jump) == ("10.0.0.5", 2200, "deploy", "bastion")
    assert t.key_filenames and t.key_filenames[0].endswith("/.ssh/id_web")

    t = resolve_target("admin@web:2300", key_filename="/k", proxy_jump="none", ssh_config_path=cfg)
    assert (t.username, t.port, t.key_filenames, t.proxy_jump) == ("admin", 2300, ["/k"], None)

    t = resolve_target("other", username="ops", ssh_config_path=cfg)
    assert (t.hostname, t.username, t.port) == ("other", "ops", 22)


def test_resolve_target_defaults_without_config(tmp_path):
    t = resolve_target("1.2.3.4", ssh_config_path=tmp_path / "missing")
    assert (t.hostname, t.port, t.username, t.key_filenames, t.proxy_jump) == ("1.2.3.4", 22, "root", [], None)


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs OpenSSH's ssh-keygen")
def test_fingerprint_matches_openssh(tmp_path):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp_path / "k")], check=True)
    openssh = subprocess.run(["ssh-keygen", "-lf", str(tmp_path / "k.pub")], capture_output=True, text=True).stdout.split()[1]
    key = paramiko.Ed25519Key.from_private_key_file(str(tmp_path / "k"))
    assert fingerprint(key) == openssh


@pytest.fixture
def host_key():
    return paramiko.Ed25519Key.generate() if hasattr(paramiko.Ed25519Key, "generate") else paramiko.RSAKey.generate(1024)


def test_policy_refuses_unknown_keys_without_confirmation(tmp_path, host_key):
    known = tmp_path / "ssh" / "known_hosts"
    for mode, confirm in (("yes", lambda *a: True), ("ask", None), ("ask", lambda *a: False)):
        policy = VerifyingHostKeyPolicy(mode, confirm, user_file=known)
        with pytest.raises(UnknownHostKeyError) as exc:
            policy.missing_host_key(paramiko.SSHClient(), "[web]:2222", host_key)
        assert exc.value.fingerprint == fingerprint(host_key)
    assert not known.exists()


@pytest.mark.parametrize("mode,confirm", [("ask", lambda host, kind, fp: True), ("accept-new", None)])
def test_policy_records_accepted_keys(tmp_path, host_key, mode, confirm):
    known = tmp_path / "ssh" / "known_hosts"
    seen = []
    client = paramiko.SSHClient()
    policy = VerifyingHostKeyPolicy(mode, (lambda *a: seen.append(a) or True) if confirm else None, user_file=known)
    policy.missing_host_key(client, "[web]:2222", host_key)

    assert known.read_text() == f"[web]:2222 {host_key.get_name()} {host_key.get_base64()}\n"
    assert stat.S_IMODE(known.stat().st_mode) == 0o600
    assert stat.S_IMODE(known.parent.stat().st_mode) == 0o700
    if confirm:
        assert seen == [("[web]:2222", host_key.get_name(), fingerprint(host_key))]

    # The recorded line is readable by paramiko (and OpenSSH) on the next connection
    fresh = paramiko.SSHClient()
    load_known_hosts(fresh, user_file=known)
    assert fresh.get_host_keys().lookup("[web]:2222") is None  # loaded as system keys, not user keys
    assert fresh._system_host_keys.lookup("[web]:2222")[host_key.get_name()] == host_key


def test_password_flag_is_rejected_with_explanation(capsys):
    for argv in (["status", "web", "-P", "secret"], ["web", "--password=secret"]):
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        assert exc.value.code == 2
        assert "kaldırıldı" in capsys.readouterr().err


def test_unknown_host_key_is_unknown_for_monitoring(tmp_path, monkeypatch, capsys):
    """`pulseops check` (cron, no tty) must not hang on a prompt nor trust an unknown key."""
    import commands
    from collectors import transport as tr

    def refuse(self):
        raise UnknownHostKeyError("[web]:22", "ssh-ed25519", "SHA256:abc")

    monkeypatch.setattr(tr.SSHTransport, "test_connection", refuse)
    with pytest.raises(SystemExit) as exc:
        cli.main(["check", "root@web"])
    assert exc.value.code == commands.EXIT_UNKNOWN
    assert "tanınmıyor" in capsys.readouterr().err
