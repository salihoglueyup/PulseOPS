from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from pulseops.ui.safe import PlainTable as Table
from rich.text import Text

from pulseops.models.storage import StorageOverview

class StoragePanel(Widget):
    """Corporate widget displaying Docker BuildKit, containerd snapshotter, and storage breakdown in Clean Minimalist Silver & White."""

    storage: reactive[StorageOverview] = reactive(StorageOverview)

    def render(self) -> Panel:
        st = self.storage

        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(ratio=1)

        # 1. Top Summary Metric Cards
        cards_table = Table(expand=True, box=None, padding=(0, 2))
        cards_table.add_column("ROOT DİSK KULLANIMI", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("BUILDKIT CACHE", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("CONTAINERD OVERLAYFS", style="bold #f0f6fc", ratio=1)
        cards_table.add_column("KURTARILABİLİR ALAN", style="bold #f0f6fc", ratio=1)

        # Root disk card
        root_style = "bold #f85149" if st.root_percent > 80 else ("bold #d29922" if st.root_percent > 70 else "bold #3fb950")
        root_text = Text()
        if 900.0 <= st.root_total_gb <= 1050.0:
            total_cap_str = "1 TB"
        elif 450.0 <= st.root_total_gb <= 525.0:
            total_cap_str = "512 GB"
        elif 220.0 <= st.root_total_gb <= 265.0:
            total_cap_str = "256 GB"
        else:
            total_cap_str = f"{st.root_total_gb:.0f} GB"
        root_text.append(f"{st.root_used_gb:.0f} GB / {total_cap_str}\n", style="#f0f6fc")
        root_text.append(f"Doluluk: %{st.root_percent:.1f}", style=root_style)

        # BuildKit cache card
        bk_style = "bold #f85149" if st.is_cache_bloated else "bold #3fb950"
        bk_text = Text()
        bk_text.append(f"{st.buildkit_cache_human}\n", style=bk_style)
        bk_sub = "AŞIRI BİRİKME!" if st.is_cache_bloated else "Sağlıklı ✓"
        bk_text.append(bk_sub, style=bk_style)

        # Containerd overlayfs card
        cntr_text = Text()
        cntr_text.append(f"{st.containerd_overlayfs_human}\n", style="#f0f6fc")
        cntr_text.append("io.containerd.snapshotter", style="#6e7681")

        # Reclaimable card
        rec_text = Text()
        rec_style = "bold #3fb950" if st.total_reclaimable_human != "0 B" else "#6e7681"
        rec_text.append(f"{st.total_reclaimable_human}\n", style=rec_style)
        rec_text.append("docker prune ile kurtarılabilir", style="#8b949e")

        cards_table.add_row(root_text, bk_text, cntr_text, rec_text)
        grid.add_row(Panel(cards_table, border_style="#30363d", padding=(0, 1)))

        # 2. Split Row: Docker System DF Table (Left) + Snapshot & Root-Cause Chain (Right)
        split_table = Table.grid(expand=True)
        split_table.add_column(ratio=3)
        split_table.add_column(ratio=2)

        # Docker DF Table
        df_table = Table(expand=True, box=None, padding=(0, 1))
        df_table.add_column("DEPOLAMA TÜRÜ", style="bold #f0f6fc", ratio=3)
        df_table.add_column("TOPLAM BOYUT", style="bold #f0f6fc", ratio=2)
        df_table.add_column("KURTARILABİLİR (RECLAIMABLE)", ratio=3)
        df_table.add_column("DURUM / DETAY", style="#8b949e", ratio=3)

        if not st.items:
            df_table.add_row(Text("Docker depolama verisi bekleniyor...", style="#6e7681"), "-", "-", "-")
        else:
            for it in st.items:
                reclaim_style = "bold #3fb950" if it.reclaimable_human != "0B" and "0 B" not in it.reclaimable_human else "#6e7681"
                type_style = "bold #f85149" if it.is_critical else "bold #f0f6fc"
                df_table.add_row(
                    Text(it.name, style=type_style),
                    it.total_human,
                    Text(it.reclaimable_human, style=reclaim_style),
                    it.details
                )

        left_panel = Panel(
            df_table,
            title="[bold #f0f6fc]DOCKER SİSTEM DEPOLAMA DAĞILIMI (DOCKER SYSTEM DF)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

        # Right Diagnostic & Snapshot Chain
        diag_text = Text()
        diag_text.append("Teşhis & Mimari Dağılım:\n", style="bold #f0f6fc")
        diag_text.append("Root (C:) ➔ Docker Desktop (WSL2) ➔ BuildKit Cache\n\n", style="#8b949e")

        if st.snapshot_groups:
            diag_text.append("Kritik Snapshot Katmanları:\n", style="bold #d29922")
            for sg in st.snapshot_groups:
                diag_text.append(f"• {sg.count}x {sg.size_human} [{sg.state}]\n", style="#f0f6fc")
                diag_text.append(f"  {sg.note} ({sg.inodes:,} inodes)\n", style="#6e7681")
            diag_text.append("\n")

        diag_text.append("Kalıcı Temizlik & Önlem:\n", style="bold #3fb950")
        diag_text.append("• Hızlı Güvenli Temizlik:\n", style="#8b949e")
        diag_text.append("  docker builder prune -a -f --keep-storage 10GB\n", style="bold #f0f6fc")
        diag_text.append("• Kullanılmayan İmajları Temizleme:\n", style="#8b949e")
        diag_text.append("  docker image prune -a\n", style="bold #f0f6fc")
        diag_text.append("• Docker Desktop GC Politikası:\n", style="#8b949e")
        diag_text.append('  "builder": { "gc": { "defaultKeepStorage": "10GB" } }\n', style="bold #3fb950")

        right_panel = Panel(
            diag_text,
            title="[bold #f0f6fc]TEŞHİS & ÖNLEME KILAVUZU[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 1),
        )

        split_table.add_row(left_panel, right_panel)
        grid.add_row(split_table)

        # 3. Bottom Recommendations Banner
        rec_table = Table(expand=True, box=None, padding=(0, 1))
        rec_table.add_column("DEPOLAMA ANALİZ RAPORU & TAVSİYELER", style="#f0f6fc")
        for r in st.recommendations:
            if "[GUVENLI]" in r or r.startswith("✓"):
                r_style = "bold #3fb950"
            elif "[DIKKAT]" in r or "AŞIRI" in r.upper():
                r_style = "bold #f85149"
            elif "[TEMIZLIK]" in r or "[FIRSAT]" in r:
                r_style = "bold #58a6ff"
            else:
                r_style = "#d29922"
            rec_table.add_row(Text(r, style=r_style))

        grid.add_row(Panel(rec_table, border_style="#30363d", padding=(0, 1)))

        return Panel(
            grid,
            title="[bold #f0f6fc]DEPOLAMA, BUILDKIT & CONTAINERD ANALİZÖRÜ (STORAGE ANALYZER)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )
