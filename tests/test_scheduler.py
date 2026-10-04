import os
import stat

import pytest

from pulseops import cli
from pulseops import scheduler


def run(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    out = capsys.readouterr()
    return exc.value.code, out.out, out.err


@pytest.fixture
def fake_systemctl(tmp_path, monkeypatch):
    """A systemctl that only records its arguments; the units go to a temp XDG_CONFIG_HOME."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    log = tmp_path / "systemctl.log"
    script = bindir / "systemctl"
    script.write_text(f'#!/bin/sh\necho "$@" >> "{log}"\n')
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    exe = bindir / "pulseops"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ['PATH']}")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    return log, tmp_path / "config" / "systemd" / "user"


def test_parse_interval():
    assert scheduler.parse_interval("5m") == 300 and scheduler.parse_interval("2h") == 7200
    assert scheduler.parse_interval("90") == 90
    for bad in ("30s", "5x", "", "-5m"):
        with pytest.raises(ValueError):
            scheduler.parse_interval(bad)


def test_units_escape_specifiers_and_variables():
    service, timer = scheduler.render_units("/usr/bin/pulseops", ["check", "-o", "/x/a 50%$HOME.prom"], 300, True)
    assert "ExecStart=/usr/bin/pulseops check -o '/x/a 50%%$$HOME.prom'" in service
    assert "SuccessExitStatus=0 1 2 3" in service and "ProtectSystem=full" in service
    assert "OnUnitActiveSec=300s" in timer and "WantedBy=timers.target" in timer
    user_service, _ = scheduler.render_units("/usr/bin/pulseops", ["check"], 300, False)
    assert "ProtectSystem" not in user_service  # user units cannot use it and sudo needs privileges


def test_install_status_remove_user_timer(fake_systemctl, monkeypatch, capsys):
    log, unit_dir = fake_systemctl
    code, out, _ = run(["schedule", "install", "--user", "--every", "10m", "--args", "check --all -f json"], capsys)
    assert code == 0 and "600 sn" in out
    service = (unit_dir / "pulseops-check.service").read_text()
    assert "check --all -f json" in service and "OnUnitActiveSec=600s" in (unit_dir / "pulseops-check.timer").read_text()
    assert log.read_text().splitlines() == ["--user daemon-reload", "--user enable --now pulseops-check.timer"]

    assert run(["schedule", "status", "--user"], capsys)[0] == 0
    code, out, _ = run(["schedule", "remove", "--user"], capsys)
    assert code == 0 and not unit_dir.joinpath("pulseops-check.timer").exists()
    assert "--user disable --now pulseops-check.timer" in log.read_text()
    assert run(["schedule", "status", "--user"], capsys)[0] == 1


def test_install_rejects_non_check_commands(fake_systemctl, capsys):
    code, _, err = run(["schedule", "install", "--user", "--args", "uninstall --yes"], capsys)
    assert code == 2 and "check" in err
    assert run(["schedule", "install", "--user", "--every", "10s"], capsys)[0] == 2
