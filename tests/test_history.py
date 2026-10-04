import stat
import time

import pytest

from pulseops import cli
from pulseops.collectors.base import DemoCollector
from pulseops.collectors.drift import HIGH, INFO, MEDIUM, diff, fingerprint
from pulseops.collectors.telemetry import collect_telemetry
from conftest import settle
from pulseops.history import HistoryStore, host_key
from pulseops.models.ports import ListeningPort, PortExposure
from pulseops.models.services import ServiceState, ServiceUnit
from pulseops.models.security import AccessAudit
from pulseops.ui.app import ServerTUIApp


@pytest.fixture
def base():
    t = collect_telemetry(DemoCollector())
    t.security.access = AccessAudit(uid0_users=["root"], admin_users=["deploy"], login_users=["root", "deploy"],
                                    sudoers_known=True, nopasswd_rules=[], keys_known=True,
                                    authorized_keys={"root": 0, "deploy": 2})
    return t


def changed(t, **edits):
    t2 = t.model_copy(deep=True)
    for path, value in edits.items():
        obj = t2
        *parents, attr = path.split("__")
        for p in parents:
            obj = getattr(obj, p)
        setattr(obj, attr, value)
    return t2


def messages(changes):
    return [(c.severity, c.message) for c in changes]


def test_no_changes_against_itself(base):
    assert diff(fingerprint(base), fingerprint(base)) == []


def test_new_public_port_is_high_and_ephemeral_loopback_ignored(base):
    t2 = base.model_copy(deep=True)
    t2.ports += [
        ListeningPort(proto="tcp", ip="0.0.0.0", port=4444, process_name="nc", exposure=PortExposure.EXPOSED_GENERAL),
        ListeningPort(proto="tcp", ip="127.0.0.1", port=41234, process_name="helper"),  # ephemeral loopback
        ListeningPort(proto="tcp", ip="127.0.0.1", port=9000, process_name="php-fpm"),
        ListeningPort(proto="tcp", ip="0.0.0.0", port=50001, process_name="rpc", exposure=PortExposure.SYSTEM_RPC),
    ]
    assert messages(diff(fingerprint(base), fingerprint(t2))) == [
        (HIGH, "Yeni dışa açık port: tcp 0.0.0.0:4444 (nc)"),
        (INFO, "Yeni yerel port: tcp 127.0.0.1:9000 (php-fpm)"),
    ]


def test_account_and_key_changes(base):
    t2 = changed(base,
                 security__access__uid0_users=["root", "toor"],
                 security__access__admin_users=["deploy", "mallory"],
                 security__access__login_users=["root", "deploy", "mallory"],
                 security__access__authorized_keys={"root": 1, "deploy": 1},
                 security__access__nopasswd_rules=["mallory ALL=(ALL) NOPASSWD: ALL"],
                 security__access__sudo_rule_users=["mallory"])
    got = messages(diff(fingerprint(base), fingerprint(t2)))
    assert (HIGH, "sudoers ile yetki verildi: mallory") in got
    assert (HIGH, "Yeni UID 0 (root yetkili) hesap: toor") in got
    assert (HIGH, "sudo/wheel grubuna eklendi: mallory") in got
    assert (MEDIUM, "Yeni giriş yapabilen hesap: mallory") in got
    assert (HIGH, "root hesabına 1 yeni SSH anahtarı eklendi (0 → 1)") in got
    assert (INFO, "deploy hesabından 1 SSH anahtarı kaldırıldı (2 → 1)") in got
    assert (HIGH, "Yeni NOPASSWD sudo kuralı: mallory ALL=(ALL) NOPASSWD: ALL") in got
    assert [s for s, _ in got] == sorted((s for s, _ in got), key=[HIGH, MEDIUM, INFO].index)


def test_firewall_sshd_fail2ban_service_changes(base):
    t2 = changed(base, security__firewall_active=False, security__ssh__password_authentication="yes")
    t2.security.fail2ban.running = False
    t2.services = list(t2.services) + [ServiceUnit(name="nginx.service", display_name="Nginx", state=ServiceState.FAILED)]
    got = messages(diff(fingerprint(base), fingerprint(t2)))
    assert (HIGH, "Güvenlik duvarı KAPATILDI") in got
    assert (HIGH, "sshd ayarı değişti: PasswordAuthentication=no → yes") in got
    assert (HIGH, "fail2ban DURDU") in got
    assert (MEDIUM, "Servis çöktü: nginx.service") in got


def test_unreadable_categories_never_produce_changes(base):
    """Running once as root and once as a normal user must not look like keys/sudoers vanished."""
    t2 = changed(base, security__access__sudoers_known=False, security__access__nopasswd_rules=[],
                 security__access__keys_known=False, security__access__authorized_keys={},
                 security__firewall_known=False)
    assert diff(fingerprint(base), fingerprint(t2)) == []
    assert diff(fingerprint(t2), fingerprint(base)) == []


def test_store_baseline_changes_and_permissions(tmp_path, base):
    store = HistoryStore(tmp_path / "data" / "history.db")
    assert store.detect_changes(base, ts=1000.0) == []  # first sight: baseline only
    t2 = changed(base, security__access__admin_users=["deploy", "mallory"])
    assert messages(store.detect_changes(t2, ts=2000.0)) == [(HIGH, "sudo/wheel grubuna eklendi: mallory")]
    assert store.detect_changes(t2, ts=3000.0) == []  # reported once

    # a run that cannot read a category keeps the last readable baseline for it
    blind = changed(t2, security__access__sudoers_known=False, security__access__keys_known=False,
                    security__access__authorized_keys={})
    assert store.detect_changes(blind, ts=4000.0) == []
    t3 = changed(t2, security__access__authorized_keys={"root": 1, "deploy": 2})
    assert messages(store.detect_changes(t3, ts=5000.0)) == [(HIGH, "root hesabına 1 yeni SSH anahtarı eklendi (0 → 1)")]

    stored = store.changes(host_key(base))
    assert [c.ts for c in stored] == [5000.0, 2000.0]
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700


def test_take_unreported_per_consumer(tmp_path, base):
    store = HistoryStore(tmp_path / "h.db")
    key = host_key(base)
    store.detect_changes(base, ts=100.0)
    assert store.take_unreported(key, "check", now=150.0) == []  # first call marks the start
    store.detect_changes(changed(base, security__access__admin_users=["deploy", "x"]), ts=200.0)
    assert [c.message for c in store.take_unreported(key, "check", now=250.0)] == ["sudo/wheel grubuna eklendi: x"]
    assert store.take_unreported(key, "check", now=300.0) == []
    assert store.take_unreported(key, "tui", now=300.0) == []  # another consumer has its own cursor


def test_samples_and_retention(tmp_path, base):
    store = HistoryStore(tmp_path / "h.db")
    now = time.time()
    store.record_sample(base, 65, 3, ts=now - 40 * 86400)
    store.record_sample(base, 70, 2, ts=now)
    samples = store.samples(host_key(base), since=0)
    assert [s.score for s in samples] == [70]  # 30-day retention pruned the old one
    assert samples[0].cpu == base.snapshot.cpu.total_percent


def test_check_reports_drift_once_and_escalates(tmp_path, monkeypatch, capsys, base):
    from pulseops import commands
    from pulseops.collectors import base as base_mod

    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    states = [base, base, changed(base, security__access__admin_users=["deploy", "mallory"]), base]

    class Scripted(base_mod.BaseCollector):
        def collect(self, include_slow=True, include_logs=True):
            return states.pop(0).model_copy(deep=True)

    monkeypatch.setattr(commands, "create_local_collector", lambda **kw: Scripted())

    def run():
        with pytest.raises(SystemExit) as exc:
            cli.main(["check", "--warn", "10", "--crit", "5"])
        return exc.value.code, capsys.readouterr().out

    assert run()[0] == 0                     # baseline
    assert run()[0] == 0                     # nothing new
    code, out = run()
    assert code == 1 and "DEĞİŞİKLİK: sudo/wheel grubuna eklendi: mallory" in out and "changes=1" in out
    code, out = run()                        # mallory removed: INFO only, not reported by check
    assert code == 0 and "changes=0" in out


def test_history_command_without_connecting(tmp_path, monkeypatch, capsys, base):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    store = HistoryStore()
    store.record_sample(base, 65, 3)
    store.detect_changes(base)
    store.detect_changes(changed(base, security__access__admin_users=["deploy", "eve"]))
    with pytest.raises(SystemExit) as exc:
        cli.main(["history", base.snapshot.hostname, "--since", "7d"])
    out = capsys.readouterr().out
    assert exc.value.code == 0
    assert "sudo/wheel grubuna eklendi: eve" in out
    assert "Skor" in out and "CPU %" in out


@pytest.mark.asyncio
async def test_tui_records_history_and_shows_modal(tmp_path, base):
    store = HistoryStore(tmp_path / "h.db")
    store.detect_changes(base, ts=time.time() - 3600)          # an earlier session saw the baseline
    store.take_unreported(host_key(base), "tui", now=time.time() - 3500)
    store.detect_changes(changed(base, security__access__admin_users=["deploy", "eve"]), ts=time.time() - 60)  # cron saw this

    class Fixed(DemoCollector):
        def collect(self, include_slow=True, include_logs=True):
            t = super().collect(include_slow, include_logs)
            t.security.access = base.security.access.model_copy(update={"admin_users": ["deploy", "eve"]})
            return t

    app = ServerTUIApp(collector=Fixed(), poll_interval=3600, history=store)
    async with app.run_test(size=(160, 50)) as pilot:
        await settle(pilot)
        titles = [n.title for n in app._notifications]
        assert "Son açılıştan beri 1 güvenlik değişikliği" in titles
        assert len(store.samples(host_key(base), since=0)) == 1
        await pilot.press("h")
        await pilot.pause()
        assert type(app.screen).__name__ == "HistoryModal"
        await pilot.press("escape")
        await pilot.pause()
        assert type(app.screen).__name__ != "HistoryModal"


def test_observer_privileges_do_not_create_drift(base):
    """The same machine seen as root and as a normal user (local + SSH, fleet) must look unchanged."""
    root_view = base.model_copy(deep=True)
    root_view.ports = [ListeningPort(proto="tcp", ip="0.0.0.0", port=22, process_name="sshd", pid=1,
                                     exposure=PortExposure.ADMIN_SSH)]
    root_view.security.access.authorized_keys = {"root": 1, "deploy": 2}
    user_view = base.model_copy(deep=True)
    user_view.ports = [ListeningPort(proto="tcp", ip="0.0.0.0", port=22, exposure=PortExposure.ADMIN_SSH)]
    user_view.security.access.authorized_keys = {"deploy": 2}
    user_view.security.access.authorized_keys_unknown = ["root"]

    assert diff(fingerprint(root_view), fingerprint(user_view)) == []
    assert diff(fingerprint(user_view), fingerprint(root_view)) == []
    # a restart under another process name is not a new port either
    renamed = root_view.model_copy(deep=True)
    renamed.ports[0] = renamed.ports[0].model_copy(update={"process_name": "sshd-session"})
    assert diff(fingerprint(root_view), fingerprint(renamed)) == []


def test_old_baseline_port_format_still_compares(base):
    old = fingerprint(base)
    old["ports_public"] = ["tcp 0.0.0.0:22 (sshd)"]
    new = fingerprint(base)
    new["ports_public"] = ["tcp 0.0.0.0:22\tsshd", "tcp 0.0.0.0:8080\tnode"]
    assert messages(diff(old, new)) == [(HIGH, "Yeni dışa açık port: tcp 0.0.0.0:8080 (node)")]


def test_parse_access_unknown_homes():
    from pulseops.collectors import probe_parsers as pp

    audit = pp.parse_access("#UID0\nroot\n#AUTHKEYS\nroot ?\ndeploy 2\n")
    assert audit.authorized_keys == {"deploy": 2} and audit.authorized_keys_unknown == ["root"]
