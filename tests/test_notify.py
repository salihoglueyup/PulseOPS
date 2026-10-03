import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import cli
from collectors import base as base_mod
from collectors.base import DemoCollector
from collectors.telemetry import collect_telemetry
from notify import (
    EmailChannel,
    Notification,
    NotifyConfig,
    build_check_notification,
    discord_block,
    dispatch,
    resolve_secret,
    slack_escape,
)


@pytest.fixture
def receiver():
    """A local HTTP endpoint that records every POST (path + JSON body)."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, json.loads(body)))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}", received
    server.shutdown()


HOSTILE = "nc <http://evil.example|tıkla> [x](http://evil.example) @everyone ```"


def notification():
    return Notification(host="web01", state="WARNING", previous_state="OK", score=70,
                        alerts=["Port :4444 (nc) dışa açık!"],
                        changes=[{"severity": "HIGH", "message": f"Yeni dışa açık port: tcp 0.0.0.0:4444 ({HOSTILE})", "ts": 1.0}])


def test_all_http_channels_deliver_and_escape(receiver, monkeypatch):
    url, received = receiver
    monkeypatch.setenv("TG_TOKEN", "123:abc")
    config = NotifyConfig.model_validate({"channels": [
        {"type": "webhook", "url": f"{url}/hook"},
        {"type": "slack", "url": f"{url}/slack"},
        {"type": "discord", "url": f"{url}/discord"},
        {"type": "telegram", "bot_token": "env:TG_TOKEN", "chat_id": "42", "api_base": url},
    ]})
    assert dispatch(config, notification()) == []
    by_path = dict(received)

    hook = by_path["/hook"]
    assert hook["title"] == "PulseOps web01: OK → WARNING" and hook["score"] == 70
    assert hook["changes"][0]["severity"] == "HIGH"

    slack = by_path["/slack"]["text"]
    assert "<http://evil.example|" not in slack and "&lt;http://evil.example|tıkla&gt;" in slack

    discord = by_path["/discord"]
    assert discord["allowed_mentions"] == {"parse": []}
    body = discord["content"]
    assert body.count("```") == 2  # the hostile ``` could not close the code block early
    assert "[x](http://evil.example)" in body.split("```")[1]  # inside the code block: shown literally

    tg = by_path["/bot123:abc/sendMessage"]
    assert tg["chat_id"] == "42" and "parse_mode" not in tg and "OK → WARNING" in tg["text"]


def test_failures_are_reported_not_raised(monkeypatch):
    config = NotifyConfig.model_validate({"channels": [
        {"type": "webhook", "name": "kapali", "url": "http://127.0.0.1:9/x"},
        {"type": "telegram", "bot_token": "env:NOT_SET_ANYWHERE", "chat_id": "1"},
    ]})
    errors = dispatch(config, notification())
    assert len(errors) == 2 and errors[0].startswith("kapali:") and "NOT_SET_ANYWHERE" in errors[1]


def test_email_channel(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["server"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            sent["tls"] = True

        def login(self, user, password):
            sent["login"] = (user, password)

        def send_message(self, msg):
            sent["msg"] = msg

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    monkeypatch.setenv("SMTP_PASS", "s3cret")
    channel = EmailChannel(type="email", smtp_host="smtp.example", sender="a@example", to=["ops@example"],
                           username="a@example", password="env:SMTP_PASS")
    assert dispatch(NotifyConfig(channels=[channel]), notification()) == []
    assert sent["server"] == ("smtp.example", 587) and sent["tls"] and sent["login"] == ("a@example", "s3cret")
    assert sent["msg"]["Subject"] == "PulseOps web01: OK → WARNING"
    assert "Yeni dışa açık port" in sent["msg"].get_content()


def test_escaping_helpers():
    assert slack_escape("<a&b>") == "&lt;a&amp;b&gt;"
    assert discord_block("x ``` y").count("```") == 2
    assert resolve_secret("plain") == "plain"


def test_only_transitions_and_relevant_changes_notify():
    from history import StoredChange

    cfg = NotifyConfig()
    info = StoredChange(ts=1, severity="INFO", category="port", message="kapandı")
    high = StoredChange(ts=1, severity="HIGH", category="port", message="yeni port")
    assert build_check_notification(cfg, "h", "WARNING", "WARNING", 70, [], []) is None   # repeat: silent
    assert build_check_notification(cfg, "h", "WARNING", None, 70, [], []) is None        # first ever run
    assert build_check_notification(cfg, "h", "WARNING", "WARNING", 70, [], [info]) is None
    n = build_check_notification(cfg, "h", "WARNING", "WARNING", 70, [], [info, high])
    assert [c["message"] for c in n.changes] == ["yeni port"]
    assert build_check_notification(cfg, "h", "OK", "WARNING", 90, [], []).title == "PulseOps h: WARNING → OK"
    assert build_check_notification(NotifyConfig(on_state_change=False), "h", "OK", "WARNING", 90, [], []) is None


def test_check_sends_on_transition_and_recovery_only(receiver, tmp_path, monkeypatch, capsys):
    import commands

    url, received = receiver
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    cfg_dir = tmp_path / "config" / "pulseops"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "config.toml").write_text(f'[[notify.channels]]\ntype = "webhook"\nurl = "{url}/hook"\n')
    (cfg_dir / "config.toml").chmod(0o600)

    base = collect_telemetry(DemoCollector())  # scores 65
    healthy = base.model_copy(deep=True)
    healthy.ports = [p for p in healthy.ports if p.port != 27017]
    healthy.routes = []
    states = [base, base, healthy, healthy]

    class Scripted(base_mod.BaseCollector):
        def collect(self, include_slow=True, include_logs=True):
            return states.pop(0).model_copy(deep=True)

    monkeypatch.setattr(commands, "create_local_collector", lambda **kw: Scripted())

    def run():
        with pytest.raises(SystemExit) as exc:
            cli.main(["check"])
        capsys.readouterr()
        return exc.value.code

    assert run() == 1 and received == []                       # first run: no previous state
    assert run() == 1 and received == []                       # WARNING again: silent
    assert run() == 0 and [b["title"] for _, b in received] == ["PulseOps prod-web-node01: WARNING → OK"]
    assert run() == 0 and len(received) == 1                   # OK again: silent


def test_plaintext_secret_in_readable_config_warns(tmp_path, monkeypatch, capsys, receiver):
    url, _ = receiver
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    cfg = tmp_path / "config" / "pulseops" / "config.toml"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(f'[[notify.channels]]\ntype = "slack"\nurl = "{url}/slack"\n')
    cfg.chmod(0o644)
    with pytest.raises(SystemExit) as exc:
        cli.main(["notify", "--test"])
    out = capsys.readouterr()
    assert exc.value.code == 0 and "✅ slack" in out.out
    assert "chmod 600" in out.err
