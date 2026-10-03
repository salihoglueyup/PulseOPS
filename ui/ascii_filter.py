"""Output filter that makes the TUI usable on terminals without Unicode/emoji support.

Every non-ASCII character is replaced by an ASCII string of the *same cell width*, so the
layout computed by Textual stays aligned.
"""
import unicodedata
from functools import lru_cache

from rich.cells import cell_len
from rich.segment import Segment
from textual.filter import LineFilter

SYMBOLS = {
    "✓": "+", "✔": "+", "✗": "x", "✘": "x", "⚠": "!", "➔": ">", "→": ">", "←": "<",
    "↑": "^", "↓": "v", "▲": "^", "▼": "v", "▶": ">", "◀": "<", "●": "*", "•": "*",
    "○": "o", "◆": "*", "◇": "o", "…": ".", "·": ".", "°": "o", "×": "x", "≥": ">", "≤": "<",
    "⚡": "*", "🌐": "@", "🔍": "?", "🎨": "#",
    "ı": "i", "İ": "I",
}


@lru_cache(4096)
def to_ascii(char: str) -> str:
    """Width-preserving ASCII replacement for a single character."""
    if char.isascii():
        return char
    width = cell_len(char)
    if width == 0:
        return ""
    if char in SYMBOLS:
        out = SYMBOLS[char]
    else:
        code = ord(char)
        name = unicodedata.name(char, "")
        if 0x2500 <= code <= 0x257F:  # box drawing
            horizontal, vertical = "HORIZONTAL" in name, "VERTICAL" in name
            out = "-" if horizontal and not vertical else "|" if vertical and not horizontal else "+"
        elif 0x2580 <= code <= 0x259F:  # block elements (bars)
            out = " " if "LIGHT SHADE" in name else "#"
        elif 0x2800 <= code <= 0x28FF:  # braille (sparklines)
            out = " " if code == 0x2800 else "."
        else:
            decomposed = unicodedata.normalize("NFKD", char)
            out = "".join(c for c in decomposed if c.isascii()) or "?"
    return out[:width].ljust(width)


def to_ascii_text(text: str) -> str:
    return "".join(to_ascii(c) for c in text)


class AsciiFilter(LineFilter):
    def apply(self, segments: list[Segment], background) -> list[Segment]:
        return [
            seg if seg.control or seg.text.isascii() else Segment(to_ascii_text(seg.text), seg.style, seg.control)
            for seg in segments
        ]
