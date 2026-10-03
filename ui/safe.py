"""Helpers for rendering untrusted telemetry.

Process names, log lines, container names, domains, file contents... can all be influenced by
someone other than the operator. Rich parses plain `str` as markup, so such text could crash the
UI (`[/]`) or plant terminal hyperlinks (`[link=...]`). Untrusted text must reach Rich as `Text`
or be escaped.
"""
from rich.markup import escape
from rich.table import Table
from rich.text import Text

__all__ = ["PlainTable", "escape"]


class PlainTable(Table):
    """A Rich Table whose plain-string cells are shown literally instead of parsed as markup.

    Styling still works through `Text` cells and column/row styles.
    """

    def add_row(self, *renderables, **kwargs):
        cells = [Text(cell) if isinstance(cell, str) else cell for cell in renderables]
        return super().add_row(*cells, **kwargs)
