import json

import pytest
from rich.cells import cell_len

from pulseops import cli
from pulseops.commands import evaluate_check, EXIT_OK, EXIT_WARNING, EXIT_CRITICAL, EXIT_UNKNOWN
from pulseops.collectors.base import DemoCollector
from pulseops.collectors.telemetry import collect_telemetry, summarize_alerts
from pulseops.installer import parse_version, verify_checksum, find_links, detect_install_mode, sha256_file
from pulseops.ui.ascii_filter import to_ascii, to_ascii_text


def run_cli(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    out = capsys.readouterr()
    return exc.value.code, out.out, out.err


def test_collect_telemetry_demo():
    t = collect_telemetry(DemoCollector())
    assert t.snapshot.hostname == "prod-web-node01"
    assert t.services and t.databases
    alerts = summarize_alerts(t)
    assert any("27017" in a for a in alerts)
    assert any("502" in a for a in alerts)


@pytest.mark.parametrize(
    "score,expected",
    [(100, EXIT_OK), (80, EXIT_OK), (79, EXIT_WARNING), (50, EXIT_WARNING), (49, EXIT_CRITICAL)],
)
def test_evaluate_check(score, expected):
    assert evaluate_check(score, warn=80, crit=50) == expected


def test_check_command_demo_is_warning(capsys):
    code, out, _ = run_cli(["check", "--demo"], capsys)
    assert code == EXIT_WARNING
    assert out.startswith("PULSEOPS WARNING - prod-web-node01 skor 65/100")
    assert "| score=65;80;50;0;100 alerts=3" in out


def test_check_command_custom_thresholds(capsys):
    assert run_cli(["check", "--demo", "--warn", "60", "--crit", "40"], capsys)[0] == EXIT_OK
    assert run_cli(["check", "--demo", "--warn", "90", "--crit", "70"], capsys)[0] == EXIT_CRITICAL
    assert run_cli(["check", "--demo", "--warn", "40", "--crit", "60"], capsys)[0] == EXIT_UNKNOWN


def test_status_json(capsys):
    code, out, _ = run_cli(["status", "--demo", "--json"], capsys)
    assert code == EXIT_OK
    data = json.loads(out)
    assert data["score"] == 65
    assert data["snapshot"]["hostname"] == "prod-web-node01"
    assert len(data["alerts"]) == 3


def test_status_text(capsys):
    code, out, _ = run_cli(["status", "--demo"], capsys)
    assert code == EXIT_OK
    assert "65/100" in out and "Uyarılar (3)" in out


def test_report_writes_markdown(tmp_path, capsys):
    code, out, _ = run_cli(["report", "--demo", "-o", str(tmp_path)], capsys)
    assert code == EXIT_OK
    files = list(tmp_path.glob("pulseops-audit-prod-web-node01-*.md"))
    assert len(files) == 1 and out.strip() == str(files[0])
    assert "65 / 100" in files[0].read_text(encoding="utf-8")


def test_report_json_stdout(capsys):
    code, out, _ = run_cli(["report", "--demo", "-f", "json", "-o", "-"], capsys)
    assert code == EXIT_OK
    assert json.loads(out)["grade"].startswith("C")


def test_version_flag(capsys):
    code, out, _ = run_cli(["--version"], capsys)
    assert code == 0 and out.startswith("pulseops ")


def test_parse_version():
    assert parse_version("v1.2.10") == (1, 2, 10)
    assert parse_version("1.1.0") < parse_version("v1.10.0")
    assert parse_version("v2.0.0-rc1") == (2, 0, 0)


def test_verify_checksum(tmp_path):
    f = tmp_path / "bin"
    f.write_bytes(b"pulseops")
    digest = sha256_file(f)
    assert verify_checksum(f, digest)
    assert verify_checksum(f, f"{digest}  pulseops-linux-amd64\n")
    assert not verify_checksum(f, "0" * 64)
    assert not verify_checksum(f, "")


def test_find_links_only_matches_our_target(tmp_path):
    install = tmp_path / "share" / "pulseops"
    (install / "venv" / "bin").mkdir(parents=True)
    exe = install / "venv" / "bin" / "pulseops"
    exe.write_text("")
    other = tmp_path / "other-pulseops"
    other.write_text("")
    links = tmp_path / "bin"
    links.mkdir()
    (links / "pulseops").symlink_to(exe)
    (links / "pulsetui").symlink_to(other)

    assert find_links(install, link_dirs=[links]) == [links / "pulseops"]


def test_detect_install_mode(tmp_path):
    venv_dir = tmp_path / "pulseops"
    assert detect_install_mode(frozen=True) == "binary"
    assert detect_install_mode(frozen=False, prefix=str(venv_dir / "venv"), venv_dir=venv_dir) == "venv"
    assert detect_install_mode(frozen=False, prefix=str(tmp_path / "pipx" / "venvs" / "pulseops"), venv_dir=venv_dir) == "pipx"
    assert detect_install_mode(frozen=False, prefix=str(tmp_path / ".venv"), venv_dir=venv_dir) == "source"


@pytest.mark.parametrize("char", ["⚡", "🌐", "✓", "─", "│", "┼", "█", "⣿", "ş", "İ", "ğ", "•", "🛡"])
def test_ascii_replacement_preserves_width(char):
    replaced = to_ascii(char)
    assert replaced.isascii()
    assert cell_len(replaced) == cell_len(char)


def test_ascii_text_turkish():
    assert to_ascii_text("Güvenlik Duvarı KAPALI ⚠") == "Guvenlik Duvari KAPALI !"


class FakeRelease:
    def __init__(self, tag, payload, checksum=None):
        import hashlib
        self.tag = tag
        self.payload = payload
        self.checksum = checksum or f"{hashlib.sha256(payload).hexdigest()}  pulseops-linux-amd64\n"

    def install(self, monkeypatch):
        from pulseops import installer
        monkeypatch.setattr(installer, "latest_release_tag", lambda: self.tag)

        def fake_get(url, timeout=15.0):
            assert f"/releases/download/{self.tag}/" in url
            return self.checksum.encode() if url.endswith(".sha256") else self.payload

        monkeypatch.setattr(installer, "_http_get", fake_get)


def test_update_binary_replaces_executable(tmp_path, monkeypatch):
    from pulseops import installer
    exe = tmp_path / "pulseops"
    exe.write_bytes(b"old")
    FakeRelease("v99.0.0", b"new-binary").install(monkeypatch)
    assert installer._update_binary(exe, force=False) == 0
    assert exe.read_bytes() == b"new-binary"
    assert exe.stat().st_mode & 0o111
    assert [p.name for p in tmp_path.iterdir()] == ["pulseops"]  # no temp files left behind


def test_update_binary_rejects_bad_checksum(tmp_path, monkeypatch):
    from pulseops import installer
    exe = tmp_path / "pulseops"
    exe.write_bytes(b"old")
    FakeRelease("v99.0.0", b"tampered", checksum="0" * 64).install(monkeypatch)
    assert installer._update_binary(exe, force=False) == 1
    assert exe.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["pulseops"]


def test_update_binary_already_latest(tmp_path, monkeypatch, capsys):
    from pulseops import installer
    exe = tmp_path / "pulseops"
    exe.write_bytes(b"old")
    FakeRelease(f"v{installer.__version__}", b"same").install(monkeypatch)
    assert installer._update_binary(exe, force=False) == 0
    assert exe.read_bytes() == b"old"
    assert "Zaten güncel" in capsys.readouterr().out


def test_package_install_is_left_to_the_package_manager(monkeypatch, capsys):
    from pulseops import installer

    assert installer.detect_install_mode(frozen=True, executable="/usr/bin/pulseops") == "package"
    assert installer.detect_install_mode(frozen=True, executable="/usr/local/bin/pulseops") == "binary"
    monkeypatch.setattr(installer, "detect_install_mode", lambda: "package")
    assert installer.cmd_update(None) == 1 and "apt install ./pulseops_" in capsys.readouterr().err
    assert installer.cmd_uninstall(None) == 1 and "sudo apt remove pulseops" in capsys.readouterr().err
