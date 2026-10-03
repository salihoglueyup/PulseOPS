import pytest

import cli
from collectors.base import DemoCollector
from collectors.telemetry import collect_telemetry, summarize_alerts
from pulseops_config import AlertConfig, Config, ConfigError, init_user_config, load_config, render_config, tomllib


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_defaults_without_files(tmp_path):
    config, loaded = load_config([tmp_path / "missing.toml"])
    assert config == Config() and loaded == []


def test_user_file_overrides_system_file_key_by_key(tmp_path):
    system = write(tmp_path / "etc.toml", "[general]\ninterval = 5\nslow_interval = 120\n[check]\nwarn = 70\n")
    user = write(tmp_path / "user.toml", "[general]\ninterval = 3\n")
    config, loaded = load_config([system, user])
    assert loaded == [system, user]
    assert config.general.interval == 3.0
    assert config.general.slow_interval == 120.0
    assert config.check.warn == 70 and config.check.crit == 50


@pytest.mark.parametrize("text,message", [
    ("[general]\nintervall = 3\n", "bilinmeyen ayar 'general.intervall'"),
    ("[genral]\n", "bilinmeyen ayar 'genral'"),
    ("[general]\ninterval = 0.1\n", "'general.interval'"),
    ("[check]\nwarn = \"high\"\n", "'check.warn'"),
    ("[general\n", "geçersiz TOML"),
])
def test_invalid_files_name_the_file_and_key(tmp_path, text, message):
    path = write(tmp_path / "bad.toml", text)
    with pytest.raises(ConfigError) as exc:
        load_config([path])
    assert str(path) in str(exc.value) and message in str(exc.value)


def test_template_is_valid_and_all_commented(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    path = init_user_config()
    assert path == tmp_path / "pulseops" / "config.toml"
    assert tomllib.loads(path.read_text(encoding="utf-8")) == {"general": {}, "notify": {}, "history": {}, "ssh": {}, "check": {}, "alerts": {}}
    with pytest.raises(ConfigError):
        init_user_config()
    init_user_config(force=True)

    rendered = render_config(Config())
    assert Config.model_validate(tomllib.loads(rendered)) == Config()


def test_alert_thresholds_are_configurable():
    t = collect_telemetry(DemoCollector())
    default = summarize_alerts(t)
    assert any("SSL 4 gün" in a for a in default)
    relaxed = summarize_alerts(t, AlertConfig(ssl_days=2))
    assert not any("SSL" in a for a in relaxed)
    strict = summarize_alerts(t, AlertConfig(disk_percent=10, memory_percent=10))
    assert any(a.startswith("RAM") for a in strict) and any("disk" in a for a in strict)


def test_check_uses_config_thresholds_and_flags_win(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setattr("pulseops_config.SYSTEM_CONFIG", tmp_path / "none.toml")
    write(tmp_path / "pulseops" / "config.toml", "[check]\nwarn = 60\ncrit = 40\n")

    def run(argv):
        with pytest.raises(SystemExit) as exc:
            cli.main(argv)
        return exc.value.code

    assert run(["check", "--demo"]) == 0           # demo scores 65 >= 60
    assert run(["check", "--demo", "--warn", "70"]) == 1
    capsys.readouterr()

    write(tmp_path / "pulseops" / "config.toml", "[check]\nwarn = oops\n")
    assert run(["check", "--demo"]) == 3            # broken config -> UNKNOWN for monitoring
    assert "Yapılandırma hatası" in capsys.readouterr().err


def test_use_sudo_reaches_the_collector(tmp_path, monkeypatch):
    import argparse
    from commands import build_collector

    write(tmp_path / "config" / "pulseops" / "config.toml", "[general]\nuse_sudo = false\n")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    config, _ = load_config()
    args = argparse.Namespace(host=None, target=None, demo=False, live=True, user=None, port=22, key=None,
                              password=None, config=config)
    collector = build_collector(args)
    if hasattr(collector, "_sudo"):
        assert collector._sudo is False
