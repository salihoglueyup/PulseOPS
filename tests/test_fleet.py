import pytest

import cli
from collectors.base import DemoCollector
from commands import CollectorError, fleet_targets
from conftest import settle
from history import HistoryStore
from pulseops_config import Config
from ui.fleet_app import FleetApp, state_for


def config(**fleet):
    return Config.model_validate({"fleet": fleet})


def test_fleet_targets_dedup_and_groups():
    cfg = config(hosts=["local", "web01"], groups={"web": ["web01", "web02"], "db": ["db01"]})
    assert fleet_targets(cfg) == ["local", "web01", "web02", "db01"]
    assert fleet_targets(cfg, "web") == ["web01", "web02"]
    with pytest.raises(CollectorError, match="tanımlı gruplar: db, web"):
        fleet_targets(cfg, "nope")


def test_state_for_thresholds_and_drift():
    cfg = Config()
    assert state_for(95, cfg, False) == "OK"
    assert state_for(70, cfg, False) == "WARNING"
    assert state_for(40, cfg, False) == "CRITICAL"
    assert state_for(95, cfg, True) == "WARNING"  # a new HIGH change raises an OK host
    assert state_for(95, Config.model_validate({"history": {"drift_exit": "none"}}), True) == "OK"


def fake_connect(target):
    if target == "down":
        raise CollectorError("down: bağlanılamadı (connection refused)")
    return DemoCollector()


@pytest.mark.asyncio
async def test_fleet_app_rows_errors_and_open(tmp_path):
    store = HistoryStore(tmp_path / "h.db")
    app = FleetApp(["web01", "down", "web02"], fake_connect, Config(), history=store, interval=3600)
    async with app.run_test(size=(180, 30)) as pilot:
        await settle(pilot)
        await settle(pilot)
        web01, down, web02 = app.entries
        assert (web01.state, web01.score, len(web01.alerts)) == ("WARNING", 65, 3)
        assert web01.telemetry.snapshot.hostname == "prod-web-node01"
        assert down.state == "HATA" and "connection refused" in down.error
        assert web02.state == "WARNING"
        table = app.query_one("DataTable")
        assert table.row_count == 3
        assert "connection refused" in table.get_cell("down", "Hostname").plain
        assert len(store.samples(store.hosts()[0][0], since=0)) >= 1  # history is recorded per host

        await pilot.press("down")
        await pilot.press("enter")
        await pilot.pause()
    assert app.return_value == "down"


@pytest.mark.asyncio
async def test_fleet_poll_failure_keeps_last_data():
    class Flaky(DemoCollector):
        fail = False

        def collect(self, include_slow=True, include_logs=True):
            if Flaky.fail:
                raise ConnectionError("ssh: connection reset")
            return super().collect(include_slow, include_logs)

    app = FleetApp(["web01"], lambda t: Flaky(), Config(), interval=3600)
    async with app.run_test(size=(180, 30)) as pilot:
        await settle(pilot)
        entry = app.entries[0]
        assert entry.telemetry is not None
        Flaky.fail = True
        app.poll_all()
        await settle(pilot)
        assert entry.state == "HATA" and entry.telemetry is not None  # last data kept, marked stale
        assert "⚠" in app.query_one("DataTable").get_cell("web01", "Güncelleme").plain


def test_fleet_command_without_hosts(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["fleet"])
    assert exc.value.code == 3 and "[fleet]" in capsys.readouterr().err
