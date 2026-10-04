"""Notifications for `pulseops check`: state transitions and new security changes.

Channels use only the standard library. Text that comes from the observed host (process names,
user names...) is escaped for each channel so it cannot turn into links or formatting there.
"""
import json
import os
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage
from typing import Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

from pulseops.logging_setup import get_logger

log = get_logger("notify")


class _Channel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = ""


class WebhookChannel(_Channel):
    type: Literal["webhook"]
    url: str


class SlackChannel(_Channel):
    type: Literal["slack"]
    url: str


class DiscordChannel(_Channel):
    type: Literal["discord"]
    url: str


class TelegramChannel(_Channel):
    type: Literal["telegram"]
    bot_token: str
    chat_id: str
    api_base: str = "https://api.telegram.org"


class EmailChannel(_Channel):
    type: Literal["email"]
    smtp_host: str
    smtp_port: int = 587
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: str = ""
    password: str = ""
    sender: str
    to: list[str]


Channel = Union[WebhookChannel, SlackChannel, DiscordChannel, TelegramChannel, EmailChannel]


class NotifyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_severity: Literal["HIGH", "MEDIUM", "INFO"] = Field(
        "MEDIUM", description="Bu önemin altındaki güvenlik değişiklikleri bildirilmez")
    on_state_change: bool = Field(True, description="check durumu değişince bildir (OK → WARNING, düzelince → OK)")
    channels: list[Channel] = Field(default_factory=list)


class Notification(BaseModel):
    host: str
    state: str                       # OK / WARNING / CRITICAL / UNKNOWN
    previous_state: Optional[str] = None
    score: Optional[int] = None
    summary: str = ""
    alerts: list[str] = Field(default_factory=list)
    changes: list[dict] = Field(default_factory=list)  # {"severity", "message", "ts"}
    test: bool = False

    @property
    def title(self) -> str:
        if self.test:
            return f"PulseOps test bildirimi · {self.host}"
        if self.previous_state and self.previous_state != self.state:
            return f"PulseOps {self.host}: {self.previous_state} → {self.state}"
        return f"PulseOps {self.host}: {self.state}"

    def lines(self) -> list[str]:
        out = []
        if self.score is not None:
            out.append(f"Sağlık skoru: {self.score}/100")
        if self.changes:
            out.append("Güvenlik değişiklikleri:")
            out += [f"  [{c['severity']}] {c['message']}" for c in self.changes]
        if self.alerts:
            out.append("Aktif uyarılar:")
            out += [f"  • {a}" for a in self.alerts]
        if self.test:
            out.append("Bu kanal PulseOps bildirimlerini alabiliyor.")
        return out

    def text(self) -> str:
        return "\n".join([self.title, *self.lines()])


SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}


def resolve_secret(value: str) -> str:
    """`env:NAME` reads the value from the environment so secrets can stay out of the config file."""
    if value.startswith("env:"):
        name = value[4:]
        resolved = os.environ.get(name)
        if not resolved:
            raise ValueError(f"ortam değişkeni tanımlı değil: {name}")
        return resolved
    return value


# --- per-channel escaping of host-controlled text --------------------------------------------------

def slack_escape(text: str) -> str:
    # https://api.slack.com/reference/surfaces/formatting#escaping
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def discord_block(text: str) -> str:
    """A code block renders everything literally (no masked links, mentions or markdown)."""
    return "```\n" + text.replace("```", "`​``") + "\n```"


# --- senders ----------------------------------------------------------------------------------------

def _post_json(url: str, payload: dict, timeout: float = 10.0) -> None:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": "pulseops"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()


def send(channel: Channel, n: Notification) -> None:
    if isinstance(channel, WebhookChannel):
        _post_json(resolve_secret(channel.url), {"title": n.title, **n.model_dump()})
    elif isinstance(channel, SlackChannel):
        body = "\n".join(slack_escape(line) for line in n.lines())
        _post_json(resolve_secret(channel.url), {"text": f"*{slack_escape(n.title)}*\n```{body}```" if body else slack_escape(n.title)})
    elif isinstance(channel, DiscordChannel):
        content = f"**{n.title.replace('*', '')}**\n" + discord_block("\n".join(n.lines()) or "-")
        _post_json(resolve_secret(channel.url), {"content": content[:1990], "allowed_mentions": {"parse": []}})
    elif isinstance(channel, TelegramChannel):
        token = resolve_secret(channel.bot_token)
        # No parse_mode: Telegram shows the text literally
        _post_json(f"{channel.api_base.rstrip('/')}/bot{token}/sendMessage",
                   {"chat_id": resolve_secret(channel.chat_id), "text": n.text()[:4000], "disable_web_page_preview": True})
    elif isinstance(channel, EmailChannel):
        msg = EmailMessage()
        msg["Subject"] = n.title
        msg["From"] = channel.sender
        msg["To"] = ", ".join(channel.to)
        msg.set_content(n.text())
        context = ssl.create_default_context()
        if channel.security == "ssl":
            server = smtplib.SMTP_SSL(channel.smtp_host, channel.smtp_port, timeout=15, context=context)
        else:
            server = smtplib.SMTP(channel.smtp_host, channel.smtp_port, timeout=15)
        with server:
            if channel.security == "starttls":
                server.starttls(context=context)
            if channel.username:
                server.login(resolve_secret(channel.username), resolve_secret(channel.password))
            server.send_message(msg)
    else:  # pragma: no cover - guarded by the config model
        raise ValueError(f"bilinmeyen kanal: {channel}")


def _label(channel: Channel) -> str:
    return channel.name or channel.type


def dispatch(config: NotifyConfig, n: Notification) -> list[str]:
    """Sends to every channel; returns error descriptions (never raises)."""
    errors = []
    for channel in config.channels:
        try:
            send(channel, n)
            log.info("Bildirim gönderildi: %s (%s)", _label(channel), n.title)
        except Exception as e:  # network, auth, missing env var...
            log.warning("Bildirim gönderilemedi: %s: %s", _label(channel), e)
            errors.append(f"{_label(channel)}: {e}")
    return errors


def build_check_notification(
    config: NotifyConfig,
    host: str,
    state: str,
    previous_state: Optional[str],
    score: Optional[int],
    alerts: list[str],
    changes: list,
) -> Optional[Notification]:
    """What `check` should send, or None. State repeats are silent; new changes always count."""
    threshold = SEVERITY_ORDER[config.min_severity]
    relevant = [c for c in changes if SEVERITY_ORDER.get(c.severity, 2) <= threshold]
    state_changed = config.on_state_change and previous_state is not None and previous_state != state
    if not relevant and not state_changed:
        return None
    return Notification(
        host=host,
        state=state,
        previous_state=previous_state,
        score=score,
        alerts=alerts,
        changes=[{"severity": c.severity, "message": c.message, "ts": c.ts} for c in relevant],
    )
