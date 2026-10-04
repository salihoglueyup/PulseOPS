from textual.widget import Widget
from textual.reactive import reactive
from rich.panel import Panel
from pulseops.ui.safe import PlainTable as Table, escape
from rich.text import Text

from pulseops.models.backup import BackupData, BackupStatus

class BackupDetailView(Widget):
    """Full-page corporate widget displaying snapshot history, timers, deployment SHAs, and retention audit in Clean Minimalist Silver & White."""

    backup_data: reactive[BackupData] = reactive(BackupData)

    def render(self) -> Panel:
        data = self.backup_data
        retention = data.retention
        deploy = data.deployment

        # 1. Top Summary Cards Table
        summary_table = Table(expand=True, box=None, padding=(0, 2))
        summary_table.add_column("SNAPSHOT DURUMU", style="bold #f0f6fc", ratio=1)
        summary_table.add_column("SON SNAPSHOT", style="bold #f0f6fc", ratio=1)
        summary_table.add_column("DAĞITIM (DEPLOY) SHA", style="bold #f0f6fc", ratio=1)
        summary_table.add_column("SAKLAMA (RETENTION)", justify="center", style="bold #f0f6fc", ratio=1)

        # Snapshot card info
        snap_info = f"{retention.total_snapshots} dosya ({retention.total_size_human})"
        
        # Last snapshot info
        last_snap = data.snapshots[0] if data.snapshots else None
        last_snap_str = f"{last_snap.age_human} ({last_snap.filename[:18]}...)" if last_snap else "Yok"

        # Deploy SHA card info
        active_sha = deploy.last_deploy_sha or "Tespit Edilemedi"
        prev_sha = deploy.prev_deploy_sha or "Yok"
        deploy_str = f"Aktif: [bold #f0f6fc]{escape(active_sha)}[/bold #f0f6fc] | Geri Alma: [bold #c9d1d9]{escape(prev_sha)}[/bold #c9d1d9]"

        # Retention badge
        ret_style = "bold #3fb950" if "SAĞLIKLI" in retention.retention_status else "bold #d29922"
        ret_badge = Text(f"● {retention.retention_status}", style=ret_style)

        summary_table.add_row(
            snap_info,
            last_snap_str,
            Text.from_markup(deploy_str),
            ret_badge
        )

        # 2. Main Snapshots Table (Left)
        snap_table = Table(expand=True, box=None, padding=(0, 1))
        snap_table.add_column("SNAPSHOT DOSYASI", style="bold #f0f6fc", ratio=3)
        snap_table.add_column("TARİH / SAAT", style="#6e7681", ratio=2)
        snap_table.add_column("GEÇEN SÜRE", style="#8b949e", ratio=2)
        snap_table.add_column("BOYUT", justify="right", style="bold #f0f6fc", ratio=1)
        snap_table.add_column("DURUM", justify="center", ratio=2)

        if not data.snapshots:
            snap_table.add_row(
                Text("Dizinde store snapshot dosyası bulunamadı", style="#6e7681"),
                "-", "-", "-", "-"
            )
        else:
            for s in data.snapshots:
                status_text = Text()
                if s.is_stale_warning:
                    status_text.append("30+ GÜN (ESKİ)", style="bold #d29922")
                elif s.age_days <= 1.0:
                    status_text.append("GÜNCEL ✓", style="bold #3fb950")
                else:
                    status_text.append("SAKLANIYOR", style="#3fb950")

                snap_table.add_row(
                    s.filename,
                    s.timestamp_str,
                    s.age_human,
                    s.size_human,
                    status_text
                )

        # 3. Scheduled Tasks Table (Right Top)
        task_table = Table(expand=True, box=None, padding=(0, 1))
        task_table.add_column("ZAMANLAYICI", style="bold #f0f6fc", ratio=2)
        task_table.add_column("TÜR", style="#8b949e", ratio=1)
        task_table.add_column("PLAN", style="#f0f6fc", ratio=2)
        task_table.add_column("DURUM", justify="center", ratio=1)

        if not data.tasks:
            task_table.add_row(Text("Zamanlayıcı yok", style="#6e7681"), "-", "-", "-")
        else:
            for t in data.tasks:
                b_text = Text()
                if t.status == BackupStatus.SUCCESS:
                    b_text.append("BAŞARILI ✓", style="bold #3fb950")
                elif t.status == BackupStatus.FAILED:
                    b_text.append("HATA ✗", style="bold #f85149")
                else:
                    b_text.append("AKTİF", style="bold #d29922")

                task_table.add_row(
                    t.name[:22],
                    t.mechanism[:12],
                    t.schedule[:18],
                    b_text
                )

        # 4. Master Layout Composition
        master = Table.grid(expand=True, padding=(0, 1))
        master.add_column(ratio=1)

        # Row 1: Summary Banner
        master.add_row(Panel(summary_table, border_style="#30363d", padding=(0, 1)))

        # Row 2: Two Columns (Left: Snapshots, Right: Timers & Retention Advice)
        side_table = Table.grid(expand=True)
        side_table.add_column(ratio=3)
        side_table.add_column(ratio=2)

        left_panel = Panel(
            snap_table,
            title=f"[bold #f0f6fc]STORE & DURUM SNAPSHOTLARI ({len(data.snapshots)})[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

        right_top = Panel(
            task_table,
            title="[bold #f0f6fc]ZAMANLANMIŞ YEDEK GÖREVLERİ[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )

        advice_text = Text()
        advice_text.append("Saklama Politikası Analizi:\n", style="bold #f0f6fc")
        advice_text.append(f"{retention.recommendation}\n\n", style="#8b949e")
        advice_text.append("Önerilen Bakım Komutları:\n", style="bold #f0f6fc")
        advice_text.append("• 30 Günden Eski Snapshotları Temizleme:\n", style="#8b949e")
        advice_text.append("  find . -name 'store-*.json' -mtime +30 -delete\n", style="bold #3fb950")
        if deploy.has_rollback_target:
            advice_text.append("• Önceki Başarılı Versiyona Geri Alma:\n", style="#8b949e")
            advice_text.append(f"  git checkout {deploy.prev_deploy_sha}\n", style="bold #f0f6fc")

        right_bottom = Panel(
            advice_text,
            title="[bold #f0f6fc]SAKLAMA ANALİZİ & GERİ ALMA (ROLLBACK)[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 1),
        )

        right_column = Table.grid(expand=True)
        right_column.add_column(ratio=1)
        right_column.add_row(right_top)
        right_column.add_row(right_bottom)

        side_table.add_row(left_panel, right_column)
        master.add_row(side_table)

        return Panel(
            master,
            title="[bold #f0f6fc]YEDEKLER, SNAPSHOT'LAR & DAĞITIM YÖNETİMİ[/bold #f0f6fc]",
            border_style="#30363d",
            padding=(0, 0),
        )
