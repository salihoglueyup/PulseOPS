"""Configuration files: /etc/pulseops/config.toml (system) then ~/.config/pulseops/config.toml (user).

Later files override earlier ones key by key; command line flags override both.
Unknown keys are errors, so a typo never silently changes nothing.
"""
import os
import sys
from pathlib import Path
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

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


class Config(_Section):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    check: CheckConfig = Field(default_factory=CheckConfig)
    alerts: AlertConfig = Field(default_factory=AlertConfig)


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
    if isinstance(value, bool):
        return "true" if value else "false"
    return repr(value) if isinstance(value, (int, float)) else f'"{value}"'


def render_config(config: Config, commented: bool = False) -> str:
    """TOML text for a config. With commented=True every setting is commented out (a template)."""
    lines = []
    for section_name, section in config:
        lines.append(f"[{section_name}]")
        for key, field in type(section).model_fields.items():
            if field.description:
                lines.append(f"# {field.description}")
            line = f"{key} = {_toml_value(getattr(section, key))}"
            lines.append(f"# {line}" if commented else line)
        lines.append("")
    return "\n".join(lines)


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
