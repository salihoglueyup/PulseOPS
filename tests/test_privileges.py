import pytest

from collectors.base import DemoCollector
from collectors.privilege_collector import parse_privileges_section, collect_local_privileges
from models.privileges import PrivilegeInfo
from ui.app import ServerTUIApp


def test_parse_root():
    info = parse_privileges_section("root\n0\ndocker_installed\ndocker_ok\n")
    assert info.is_root and info.elevated and info.docker_access
    assert info.limitations == [] and info.hint == ""


def test_parse_unprivileged_user():
    info = parse_privileges_section("deploy\n1000\ndocker_installed\n")
    assert not info.is_root and not info.elevated
    assert not info.docker_access
    assert len(info.limitations) == 4
    assert "sudo pulseops" in info.hint


def test_parse_passwordless_sudo_counts_as_elevated():
    info = parse_privileges_section("deploy\n1000\ndocker_installed\nsudo_ok\n")
    assert info.elevated and info.docker_access
    assert info.limitations == []


def test_parse_docker_group_only():
    info = parse_privileges_section("deploy\n1000\ndocker_installed\ndocker_ok\n")
    assert info.docker_access and not info.elevated
    assert not any("Docker" in item for item in info.limitations)


def test_parse_docker_not_installed_no_docker_warning():
    info = parse_privileges_section("root\n0\n")
    assert not info.docker_installed
    assert info.limitations == []


def test_parse_missing_section_assumes_full_access():
    assert parse_privileges_section("") == PrivilegeInfo()


def test_collect_local_privileges_runs():
    info = collect_local_privileges()
    assert info.user
    assert info.elevated == info.is_root


class RestrictedDemoCollector(DemoCollector):
    def poll_privileges(self):
        return PrivilegeInfo(user="deploy", is_root=False, elevated=False, docker_installed=True, docker_access=False)


@pytest.mark.asyncio
async def test_header_and_notification_for_restricted_user():
    app = ServerTUIApp(collector=RestrictedDemoCollector(), poll_interval=60)
    async with app.run_test() as pilot:
        await pilot.pause()
        rendered = app.header_bar.render().plain
        assert "deploy (kısıtlı)" in rendered
        titles = [n.title for n in app._notifications]
        assert titles.count("Kısıtlı erişim: deploy") == 1
        # A second poll must not repeat the warning
        app.poll_data()
        await pilot.pause()
        assert [n.title for n in app._notifications].count("Kısıtlı erişim: deploy") == 1


@pytest.mark.asyncio
async def test_no_privilege_warning_for_full_access():
    app = ServerTUIApp(collector=DemoCollector(), poll_interval=60)
    async with app.run_test() as pilot:
        await pilot.pause()
        assert "kısıtlı" not in app.header_bar.render().plain
        assert not any((n.title or "").startswith("Kısıtlı") for n in app._notifications)


def test_collect_local_privileges_without_posix_uid(monkeypatch):
    import collectors.privilege_collector as pc
    monkeypatch.delattr(pc.os, "geteuid")
    assert collect_local_privileges() == PrivilegeInfo()
