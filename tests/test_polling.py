import threading

import pytest

from collectors.base import DemoCollector
from conftest import settle
from ui.app import ServerTUIApp


class RecordingCollector(DemoCollector):
    def __init__(self):
        super().__init__()
        self.calls = []
        self.fail = False
        self.gate = None

    def collect(self, include_slow=True, include_logs=True):
        self.calls.append((include_slow, include_logs))
        if self.gate is not None:
            self.gate.wait(5)
        if self.fail:
            raise ConnectionError("ssh: connection reset by peer")
        return super().collect(include_slow=include_slow, include_logs=include_logs)


@pytest.mark.asyncio
async def test_failure_shows_banner_once_and_recovers():
    c = RecordingCollector()
    app = ServerTUIApp(collector=c, poll_interval=3600)
    async with app.run_test() as pilot:
        await settle(pilot)
        assert app.telemetry is not None and app.header_bar.error_message == ""
        good = app.telemetry

        c.fail = True
        for _ in range(3):
            app.request_poll()
            await settle(pilot)
        assert "connection reset" in app.header_bar.error_message
        assert "BAĞLANTI HATASI" in app.header_bar.render().plain
        assert [n.title for n in app._notifications].count("Veri toplanamadı") == 1
        assert app.telemetry is good  # last good data stays on screen

        c.fail = False
        app.request_poll()
        await settle(pilot)
        assert app.header_bar.error_message == ""
        assert app.telemetry is not good
        assert "Veri akışı yeniden sağlandı." in [n.message for n in app._notifications]


@pytest.mark.asyncio
async def test_polls_never_overlap():
    c = RecordingCollector()
    app = ServerTUIApp(collector=c, poll_interval=3600)
    async with app.run_test() as pilot:
        await settle(pilot)
        c.gate = threading.Event()
        app.request_poll()
        app.request_poll()
        app.request_poll()
        c.gate.set()
        await settle(pilot)
        assert len(c.calls) == 2  # initial + one, the other two were skipped while in flight


@pytest.mark.asyncio
async def test_slow_tier_and_logs_only_when_needed():
    c = RecordingCollector()
    app = ServerTUIApp(collector=c, poll_interval=3600, slow_interval=3600)
    async with app.run_test() as pilot:
        await settle(pilot)
        assert c.calls[0] == (True, True)  # first poll fetches everything

        app.request_poll()
        await settle(pilot)
        assert c.calls[-1] == (False, False)  # fast tier only, logs tab not visible

        app.query_one("#main-tabs").active = "tab-logs"
        await pilot.pause()
        app.request_poll()
        await settle(pilot)
        assert c.calls[-1] == (False, True)

        await pilot.press("r")  # manual refresh forces the slow tier
        await settle(pilot)
        assert c.calls[-1][0] is True
