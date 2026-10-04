import json

import pytest

import cli
from commands import EXIT_UNKNOWN, EXIT_WARNING


def run(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    return exc.value.code, capsys.readouterr().out


def write_fleet(tmp_path, monkeypatch):
    cfg = tmp_path / "config" / "pulseops"
    cfg.mkdir(parents=True)
    (cfg / "config.toml").write_text('[fleet]\nhosts = ["demo", "nobody@127.0.0.1:1"]\n[ssh]\nhost_key_checking = "yes"\n')
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))


def test_check_json_single_host(capsys):
    code, out = run(["check", "--demo", "-f", "json"], capsys)
    data = json.loads(out)
    assert code == EXIT_WARNING and data["state"] == "WARNING" and data["exit_code"] == EXIT_WARNING
    assert data["score"] == 65 and len(data["alerts"]) == 3 and data["hostname"] == "prod-web-node01"
    assert data["security"]["pending_updates"] == 7 and data["security"]["hardening_failed"] is None


def test_check_fleet_json_counts_and_unreachable(tmp_path, monkeypatch, capsys):
    write_fleet(tmp_path, monkeypatch)
    code, out = run(["check", "--all", "-f", "json"], capsys)
    data = json.loads(out)
    assert code == EXIT_UNKNOWN and data["state"] == "UNKNOWN"
    assert data["counts"]["WARNING"] == 1 and data["counts"]["UNKNOWN"] == 1
    down = next(h for h in data["hosts"] if h["target"] == "nobody@127.0.0.1:1")
    assert down["score"] is None and down["error"]


def test_check_prometheus_textfile(tmp_path, monkeypatch, capsys):
    parser = pytest.importorskip("prometheus_client.parser")
    write_fleet(tmp_path, monkeypatch)
    target = tmp_path / "textfile" / "pulseops.prom"
    code, out = run(["check", "--all", "-f", "prometheus", "-o", str(target)], capsys)
    assert code == EXIT_UNKNOWN and out == ""  # file only, exit code still for cron/monitoring
    text = target.read_text()
    assert oct(target.stat().st_mode & 0o777) == "0o644"
    assert [p.name for p in target.parent.iterdir()] == ["pulseops.prom"]  # no temp file left
    families = {f.name: f for f in parser.text_string_to_metric_families(text)}
    up = {s.labels["target"]: s.value for s in families["pulseops_up"].samples}
    assert up == {"demo": 1, "nobody@127.0.0.1:1": 0}
    assert [s.value for s in families["pulseops_score"].samples] == [65]
    # Unknown values are absent rather than 0: the demo host has no hardening data
    assert "pulseops_hardening_failed_checks" not in families


def test_prometheus_label_escaping():
    parser = pytest.importorskip("prometheus_client.parser")
    from collectors.base import DemoCollector
    from collectors.telemetry import collect_telemetry
    from commands import CheckResult
    from exporters import prometheus_text

    t = collect_telemetry(DemoCollector())
    t.snapshot.hostname = 'evil"host\\\nname{x="1"}'
    text = prometheus_text([CheckResult(target='a"b', code=1, line="", telemetry=t, score=65)])
    up = next(f for f in parser.text_string_to_metric_families(text) if f.name == "pulseops_up")
    assert up.samples[0].labels == {"target": 'a"b', "hostname": 'evil"host\\\nname{x="1"}'}
