import pytest


@pytest.fixture(autouse=True)
def isolated_user_dirs(tmp_path_factory, monkeypatch):
    """Tests never read the developer's real config or write logs into their home directory."""
    root = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root / "config"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(root / "cache"))
    monkeypatch.setattr("pulseops.config.SYSTEM_CONFIG", root / "etc" / "config.toml")


async def settle(pilot):
    """Waits for the app's background poll worker(s) and the UI updates they post."""
    await pilot.app.workers.wait_for_complete()
    await pilot.pause()
