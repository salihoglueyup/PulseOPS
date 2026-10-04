"""Regenerates the configuration reference in docs/configuration.md and packaging/config.example.toml.

Run after adding or changing a setting:  python scripts/update_config_docs.py
(tests/test_config.py fails when either file is out of date.)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pulseops.config import TEMPLATE_HEADER, Config, render_config  # noqa: E402

EXAMPLE_HEADER = TEMPLATE_HEADER.replace(
    "# PulseOps yapılandırması\n",
    "# PulseOps yapılandırması\n"
    "# Kopyalayın: /etc/pulseops/config.toml (sistem geneli) veya ~/.config/pulseops/config.toml\n", 1)


def main() -> None:
    doc = ROOT / "docs" / "configuration.md"
    text = doc.read_text(encoding="utf-8")
    text = re.sub(r"```toml\n.*?```", lambda _: "```toml\n" + render_config(Config()).rstrip("\n") + "\n```",
                  text, count=1, flags=re.S)
    doc.write_text(text, encoding="utf-8")
    example = ROOT / "packaging" / "config.example.toml"
    example.write_text(EXAMPLE_HEADER + render_config(Config(), commented=True), encoding="utf-8")
    print(f"updated {doc.relative_to(ROOT)} and {example.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
