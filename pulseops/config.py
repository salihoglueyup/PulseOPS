"""Configuration files: /etc/pulseops/config.toml (system) then ~/.config/pulseops/config.toml (user).

Later files override earlier ones key by key; command line flags override both.
Unknown keys are errors, so a typo never silently changes nothing.
"""
import os
import sys
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from pulseops.notify import NotifyConfig

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised on Python 3.10 in CI
    import tomli as tomllib

SYSTEM_CONFIG = Path("/etc/pulseops/config.toml")


def user_config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "pulseops" / "config.toml"


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GeneralConfig(_Section):
    interval: float = Field(2.0, ge=0.5, le=3600, description="Hızlı metrik yenileme aralığı (sn): CPU, RAM, port, süreç")
    slow_interval: float = Field(30.0, ge=5, le=86400, description="Ağır kontrollerin aralığı (sn): servis, docker, nginx, yedek")
    ascii: bool = Field(False, description="Yalnızca ASCII karakter kullan")
    no_color: bool = Field(False, description="Renksiz (gri tonlamalı) çıktı")
    mouse: bool = Field(True, description="Fare desteği")
    use_sudo: bool = Field(True, description="Root değilken yavaş kontrollerde parolasız `sudo -n` kullan (her çağrı auth log'a yazılır)")


class CheckConfig(_Section):
    warn: int = Field(80, ge=0, le=100, description="`pulseops check`: bu skorun altı WARNING")
    crit: int = Field(50, ge=0, le=100, description="`pulseops check`: bu skorun altı CRITICAL")


class AlertConfig(_Section):
    disk_percent: float = Field(80.0, ge=1, le=100, description="Disk doluluk uyarı eşiği (%)")
    memory_percent: float = Field(85.0, ge=1, le=100, description="RAM kullanım uyarı eşiği (%)")
    ssl_days: int = Field(7, ge=0, le=365, description="SSL bitişine kalan gün uyarı eşiği")
    ssh_failed_logins: int = Field(100, ge=1, description="Bu sayının üzerinde başarısız SSH denemesi ve fail2ban koruması yoksa uyar")


class SSHConfig(_Section):
    host_key_checking: Literal["ask", "accept-new", "yes"] = Field(
        "ask",
        description="Bilinmeyen sunucu anahtarı: ask = parmak izini sor, accept-new = ilk bağlantıda kabul et, yes = reddet",
    )


class HistoryConfig(_Section):
    enabled: bool = Field(True, description="Metrik geçmişi ve güvenlik değişikliği tespiti (~/.local/share/pulseops/history.db)")
    drift_exit: Literal["none", "warning", "critical"] = Field(
        "warning", description="`pulseops check`: yüksek önemli yeni değişiklikte en az bu çıkış kodu",
    )


class FleetConfig(_Section):
    hosts: list[str] = Field(
        default_factory=list,
        description='Filo: `pulseops fleet` ve `check --all` için sunucular (ör. "web01", "deploy@10.0.0.5:2222", "local")',
    )
    groups: dict[str, list[str]] = Field(
        default_factory=dict, description='Gruplar (--group ile seçilir), ör. { web = ["web01", "web02"] }',
    )
    parallel: int = Field(8, ge=1, le=64, description="Aynı anda sorgulanacak en fazla sunucu")


class AIConfig(_Section):
    url: str = Field("http://127.0.0.1:11434", description="Ollama adresi")
    model: str = Field("qwen2.5:7b", description="Kullanılacak model (`ollama pull <model>`)")
    timeout: float = Field(180.0, ge=5, le=3600, description="Bir yanıtın toplam süre sınırı (sn); aşılırsa yanıt kesilir")
    max_tokens: int = Field(1200, ge=64, le=16384, description="Yanıt başına en fazla token (döngüye giren modeli durdurur)")
    num_ctx: int = Field(8192, ge=2048, le=131072, description="Model bağlam penceresi (token)")
    allow_remote: bool = Field(False, description="localhost dışındaki bir Ollama'ya telemetri gönderilmesine izin ver")
    redact: bool = Field(False, description="IP adreslerini ve hostname'i modele göndermeden önce maskele")
    include_logs: bool = Field(False, description="Son log satırlarını da gönder (komut enjeksiyonu riski taşıyan ham metin)")


class Config(_Section):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    fleet: FleetConfig = Field(default_factory=FleetConfig)
    notify: NotifyConfig = Field(default_factory=NotifyConfig)
    history: HistoryConfig = Field(default_factory=HistoryConfig)
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    check: CheckConfig = Field(default_factory=CheckConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)
    ai: AIConfig = Field(default_factory=AIConfig)


class ConfigError(Exception):
    pass


def _merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(paths: Optional[list[Path]] = None) -> tuple[Config, list[Path]]:
    """Returns (config, files that were loaded). Raises ConfigError with the offending file."""
    paths = [SYSTEM_CONFIG, user_config_path()] if paths is None else paths
    data: dict = {}
    loaded: list[Path] = []
    for path in paths:
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            continue
        except OSError as e:
            raise ConfigError(f"{path}: okunamadı ({e.strerror})") from e
        try:
            file_data = tomllib.loads(raw.decode("utf-8"))
            Config.model_validate(file_data)  # report errors against the file that has them
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
            raise ConfigError(f"{path}: geçersiz TOML: {e}") from e
        except ValidationError as e:
            raise ConfigError(f"{path}: {_describe(e)}") from e
        data = _merge(data, file_data)
        loaded.append(path)
    return Config.model_validate(data), loaded


def _describe(error: ValidationError) -> str:
    parts = []
    for err in error.errors():
        location = ".".join(str(x) for x in err["loc"])
        if err["type"] == "extra_forbidden":
            parts.append(f"bilinmeyen ayar '{location}'")
        else:
            parts.append(f"'{location}': {err['msg']}")
    return "; ".join(parts)


def _toml_value(value) -> str:
    import json

    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{json.dumps(k)} = {_toml_value(v)}" for k, v in value.items()) + " }"
    return json.dumps(str(value), ensure_ascii=False)


def render_config(config: Config, commented: bool = False) -> str:
    """TOML text for a config. With commented=True every setting is commented out (a template)."""
    lines = []
    for section_name, section in config:
        lines.append(f"[{section_name}]")
        for key, field in type(section).model_fields.items():
            value = getattr(section, key)
            if isinstance(value, list) and key == "channels":
                lines.extend(_channel_lines(value, commented))
                continue
            if field.description:
                lines.append(f"# {field.description}")
            line = f"{key} = {_toml_value(value)}"
            lines.append(f"# {line}" if commented else line)
        lines.append("")
    return "\n".join(lines)


CHANNEL_EXAMPLES = """# Bildirim kanalları (yalnızca `pulseops check` gönderir; durum değişince ve yeni güvenlik değişikliğinde).
# Gizli değerler için "env:DEGISKEN" yazabilirsiniz; deneme: pulseops notify --test
#
# [[notify.channels]]
# type = "telegram"
# bot_token = "env:PULSEOPS_TELEGRAM_TOKEN"
# chat_id = "123456789"
#
# [[notify.channels]]
# type = "slack"            # veya "discord", "webhook" (JSON POST)
# url = "env:PULSEOPS_SLACK_WEBHOOK"
#
# [[notify.channels]]
# type = "email"
# smtp_host = "smtp.ornek.com"
# smtp_port = 587
# security = "starttls"     # starttls | ssl | none
# username = "alarm@ornek.com"
# password = "env:PULSEOPS_SMTP_PASSWORD"
# sender = "alarm@ornek.com"
# to = ["ops@ornek.com"]"""


def _channel_lines(channels: list, commented: bool) -> list[str]:
    if commented or not channels:
        return CHANNEL_EXAMPLES.splitlines()
    out = [f"# {len(channels)} kanal tanımlı:"]
    for ch in channels:
        out.append(f"#   {ch.type}" + (f" ({ch.name})" if ch.name else ""))
    return out


TEMPLATE_HEADER = """# PulseOps yapılandırması
# Sistem geneli: /etc/pulseops/config.toml   Kullanıcı: ~/.config/pulseops/config.toml
# Komut satırı bayrakları bu dosyadaki değerleri ezer. Değiştirmek istediğiniz satırın başındaki '#' işaretini kaldırın.

"""


def init_user_config(force: bool = False) -> Path:
    path = user_config_path()
    if path.exists() and not force:
        raise ConfigError(f"{path} zaten var (üzerine yazmak için --force)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(TEMPLATE_HEADER + render_config(Config(), commented=True), encoding="utf-8")
    return path
