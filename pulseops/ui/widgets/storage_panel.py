from rich.panel import Panel
from rich.text import Text
from textual.reactive import reactive
from textual.widget import Widget

from pulseops.models.storage import StorageOverview, human_bytes
from pulseops.models.system import DiskPartition
from pulseops.ui.safe import PlainTable as Table

DIM = "#8b949e"
FAINT = "#6e7681"
TEXT = "#f0f6fc"
GOOD = "bold #3fb950"
WARN = "bold #d29922"
BAD = "bold #f85149"
INFO = "bold #58a6ff"


def _pct_style(pct: float, warn: float = 80, bad: float = 90) -> str:
    return BAD if pct >= bad else WARN if pct >= warn else GOOD


def _short(path: str, width: int = 48) -> str:
    """Middle-ellipsis for long paths: keeps the start (where) and the file name (what)."""
    if len(path) <= width:
        return path
    keep = width - 1
    return path[: keep // 2] + "…" + path[-(keep - keep // 2):]


def _bar(fraction: float, width: int = 18, style: str = "#58a6ff") -> Text:
    filled = max(0, min(width, round(fraction * width)))
    return Text("█" * filled, style=style) + Text("░" * (width - filled), style="#30363d")


class StoragePanel(Widget):
    """Filesystems, fill forecast, largest directories, log bloat, deleted-but-open files, Docker storage."""

    storage: reactive[StorageOverview] = reactive(StorageOverview)
    disks: reactive[list[DiskPartition]] = reactive(list)

    def render(self) -> Panel:
        st = self.storage
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=1)
        grid.add_row(Panel(self._cards(st), border_style="#30363d", padding=(0, 1)))
        grid.add_row(self._filesystems(st))

        split = Table.grid(expand=True)
        split.add_column(ratio=1)
        split.add_column(ratio=1)
        split.add_row(self._top_dirs(st), self._space_holders(st))
        grid.add_row(split)
        grid.add_row(self._docker(st))

        recs = Table(expand=True, box=None, padding=(0, 1))
        recs.add_column("DEPOLAMA TAVSİYELERİ")
        for r in st.recommendations or ["Depolama verisi bekleniyor..."]:
            style = (GOOD if "[GUVENLI]" in r else BAD if "[DIKKAT]" in r else WARN if "[UYARI]" in r
                     else INFO if "[FIRSAT]" in r else DIM)
            recs.add_row(Text(r, style=style))
        grid.add_row(Panel(recs, border_style="#30363d", padding=(0, 1)))
        return Panel(grid, title=f"[bold {TEXT}]DEPOLAMA ANALİZİ[/bold {TEXT}]", border_style="#30363d", padding=(0, 0))

    # --- sections ------------------------------------------------------------------------------

    def _cards(self, st: StorageOverview) -> Table:
        cards = Table(expand=True, box=None, padding=(0, 2))
        for title in ("KÖK DİSK", "DOLMA TAHMİNİ", "GERİ KAZANILABİLİR", "LOGLAR"):
            cards.add_column(title, style=f"bold {TEXT}", ratio=1)

        root = Text()
        root.append(f"{st.root_used_gb:.1f} / {st.root_total_gb:.1f} GB\n", style=TEXT)
        root.append(f"%{st.root_percent:.1f} dolu", style=_pct_style(st.root_percent))
        inode = st.inode_percent.get("/")
        if inode is not None:
            root.append(f"  · inode %{inode:.0f}", style=_pct_style(inode))

        forecast = Text()
        if st.forecast_days is not None:
            style = BAD if st.forecast_days <= 7 else WARN if st.forecast_days <= 30 else GOOD
            forecast.append(f"~{st.forecast_days:.0f} gün\n", style=style)
            forecast.append(f"+%{st.growth_percent_per_day:.2f} / gün", style=DIM)
        elif st.growth_percent_per_day is not None:
            forecast.append("Büyümüyor ✓\n", style=GOOD)
            forecast.append(f"%{st.growth_percent_per_day:+.2f} / gün (7 gün)", style=DIM)
        else:
            forecast.append("Veri birikiyor\n", style=DIM)
            forecast.append("geçmişte ≥6 saatlik örnek gerekir", style=FAINT)

        reclaim = Text()
        total = st.docker_reclaimable_bytes + st.deleted_open_bytes
        reclaim.append(f"{human_bytes(total)}\n", style=INFO if total else FAINT)
        parts = []
        if st.docker_reclaimable_bytes:
            parts.append(f"docker {human_bytes(st.docker_reclaimable_bytes)}")
        if st.deleted_open_bytes:
            parts.append(f"açık-silinmiş {human_bytes(st.deleted_open_bytes)}")
        reclaim.append(", ".join(parts) or "temizlenecek bir şey yok", style=DIM)

        logs = Text()
        if st.var_log_bytes is None and st.journal_bytes is None:
            logs.append("bekleniyor", style=FAINT)
        else:
            logs.append(f"/var/log {human_bytes(st.var_log_bytes)}\n", style=TEXT)
            logs.append(f"journal {human_bytes(st.journal_bytes)}", style=DIM)
            if st.docker_log_bytes:
                logs.append(f"  · docker {human_bytes(st.docker_log_bytes)}", style=WARN)
        cards.add_row(root, forecast, reclaim, logs)
        return cards

    def _filesystems(self, st: StorageOverview) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("BAĞLAMA NOKTASI", ratio=3)
        table.add_column("TÜR", ratio=1)
        table.add_column("BOYUT", justify="right", ratio=1)
        table.add_column("DOLULUK", ratio=3)
        table.add_column("INODE", justify="right", ratio=1)
        table.add_column("DURUM", ratio=2)
        if not self.disks:
            table.add_row(Text("Disk verisi bekleniyor...", style=FAINT), "", "", "", "", "")
        for d in self.disks:
            inode = st.inode_percent.get(d.mountpoint)
            read_only = d.mountpoint in st.read_only_mounts
            critical_ro = d.mountpoint in st.critical_read_only
            # A read-only image (squashfs-like) mount is full by design: not a warning
            fill_style = DIM if read_only and not critical_ro else _pct_style(d.percent)
            usage = _bar(d.percent / 100, 14, fill_style.split()[-1]) + Text(f" %{d.percent:.0f}", style=fill_style)
            state = (Text("SALT-OKUNUR ⚠", style=BAD) if critical_ro else Text("salt-okunur", style=DIM) if read_only
                     else Text("✓", style=GOOD))
            table.add_row(Text(d.mountpoint, style=TEXT), Text(d.fstype, style=DIM), human_bytes(d.total_bytes),
                          usage, Text("-" if inode is None else f"%{inode:.0f}",
                                      style=DIM if inode is None else _pct_style(inode)), state)
        return Panel(table, title=f"[bold {TEXT}]DOSYA SİSTEMLERİ[/bold {TEXT}]", border_style="#30363d", padding=(0, 0))

    def _top_dirs(self, st: StorageOverview) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("DİZİN", ratio=2)
        table.add_column("BOYUT", justify="right", ratio=1)
        table.add_column("", ratio=2)
        if not st.top_dirs:
            note = "bekleniyor (10 dakikada bir, düşük öncelikle ölçülür)" if not st.known else "okunamadı"
            table.add_row(Text(note, style=FAINT), "", "")
        biggest = st.top_dirs[0].bytes if st.top_dirs else 1
        for d in st.top_dirs[:10]:
            table.add_row(Text(d.path, style=TEXT), human_bytes(d.bytes), _bar(d.bytes / biggest, 16))
        title = "EN BÜYÜK DİZİNLER (KÖK DOSYA SİSTEMİ)" + (" · KISMİ" if st.top_dirs_partial else "")
        return Panel(table, title=f"[bold {TEXT}]{title}[/bold {TEXT}]", border_style="#30363d", padding=(0, 0))

    def _space_holders(self, st: StorageOverview) -> Panel:
        text = Text()
        if st.deleted_open:
            text.append("Silinmiş ama açık dosyalar (süreç yeniden başlayınca boşalır)\n", style=WARN)
            for f in st.deleted_open[:5]:
                text.append(f"  {human_bytes(f.bytes):>9}  {f.process} (pid {f.pid})  ", style=TEXT)
                text.append(f"{_short(f.path, 40)}\n", style=DIM)
        if st.docker_logs:
            text.append("Büyük konteyner logları\n", style=WARN)
            for f in st.docker_logs[:5]:
                text.append(f"  {human_bytes(f.bytes):>9}  {_short(f.path)}\n", style=TEXT)
        if st.big_logs:
            text.append("Büyük log dosyaları\n", style=INFO)
            for f in st.big_logs[:5]:
                text.append(f"  {human_bytes(f.bytes):>9}  {_short(f.path)}\n", style=TEXT)
        if not text.plain:
            if not st.known:
                text.append("Bekleniyor (10 dakikada bir ölçülür)", style=FAINT)
            elif not st.complete:
                text.append("Root gerekli: diğer kullanıcıların dosyaları ve süreçleri görünmüyor (sudo pulseops)", style=DIM)
            else:
                text.append("Silinmiş-açık dosya veya büyük log yok ✓", style=GOOD)
        return Panel(text, title=f"[bold {TEXT}]ALAN TUTANLAR[/bold {TEXT}]", border_style="#30363d", padding=(0, 1))

    def _docker(self, st: StorageOverview) -> Panel:
        table = Table(expand=True, box=None, padding=(0, 1))
        table.add_column("DOCKER", ratio=2)
        table.add_column("BOYUT", justify="right", ratio=1)
        table.add_column("GERİ KAZANILABİLİR", justify="right", ratio=2)
        table.add_column("AKTİF / TOPLAM", ratio=1)
        if not st.items:
            table.add_row(Text("Docker yok veya okunamadı (docker grubu / root gerekli)", style=FAINT), "", "", "")
        for item in st.items:
            reclaim = Text(f"{item.reclaimable_human}" + (f" (%{item.reclaimable_percent:.0f})" if item.reclaimable_percent else ""),
                           style=INFO if item.reclaimable_bytes else FAINT)
            table.add_row(Text(item.name, style=BAD if item.is_critical else TEXT), item.total_human, reclaim,
                          Text(item.details, style=DIM))
        if st.containerd_bytes is not None:
            table.add_row(Text("İmaj deposu (diskte)", style=DIM), human_bytes(st.containerd_bytes), "", "")
        return Panel(table, title=f"[bold {TEXT}]DOCKER DEPOLAMA[/bold {TEXT}]", border_style="#30363d", padding=(0, 0))
