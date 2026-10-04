import time
from pathlib import Path
from typing import Optional
from pulseops.models.system import SystemSnapshot
from pulseops.models.ports import ListeningPort, PortExposure
from pulseops.models.proxy import ProxyRoute
from pulseops.models.backup import BackupTask
from pulseops.models.docker import ContainerSummary
from pulseops.models.database import DatabaseInstance
from pulseops.models.services import ServiceUnit, ServiceState
from pulseops.models.security import SecurityOverview
from pulseops.models.storage import StorageOverview

def _md(value) -> str:
    """Telemetry text inside Markdown tables/code spans: neutralize table and code delimiters."""
    return str(value).replace("|", "¦").replace("`", "'").replace("\n", " ")


def _soc_section(security: SecurityOverview) -> list[str]:
    f2b, auth, access = security.fail2ban, security.auth, security.access
    lines = ["", "### Erişim & Saldırı Görünürlüğü (SOC)"]
    if not f2b.installed:
        lines.append("* **fail2ban:** Kurulu değil ⚠️")
    elif not f2b.known:
        lines.append("* **fail2ban:** Kurulu, durum okunamadı (root gerekli)")
    elif f2b.running is False:
        lines.append("* **fail2ban:** Kurulu ama ÇALIŞMIYOR 🚨")
    else:
        jails = ", ".join(f"`{_md(j.name)}` ({j.currently_banned} engelli / {j.total_banned} toplam)" for j in f2b.jails)
        lines.append(f"* **fail2ban:** Aktif ✓ — {jails or 'jail yok'}")

    if auth.known:
        lines.append(
            f"* **SSH girişleri ({_md(auth.window)}, kaynak `{_md(auth.source)}`):** {auth.failed} başarısız, "
            f"{auth.invalid_user} geçersiz kullanıcı, {auth.accepted} başarılı ({auth.accepted_password} şifreyle)"
        )
        if auth.top_sources:
            lines += ["", "| En çok deneyen kaynak | Deneme |", "| :--- | ---: |"]
            lines += [f"| `{_md(i.value)}` | {i.count} |" for i in auth.top_sources]
        if auth.recent_accepted:
            lines += ["", "| Son başarılı giriş | Kullanıcı | Kaynak | Yöntem |", "| :--- | :--- | :--- | :--- |"]
            lines += [f"| {_md(e.time)} | `{_md(e.user)}` | `{_md(e.source)}` | {_md(e.method)} |"
                      for e in reversed(auth.recent_accepted)]
    else:
        lines.append("* **SSH girişleri:** Okunamadı (root, sudo veya systemd-journal grubu gerekli)")

    lines.append(f"* **UID 0 hesaplar:** {', '.join(f'`{_md(u)}`' for u in access.uid0_users) or '-'}"
                 + (" 🚨 root dışı UID 0 hesap var!" if access.extra_uid0 else ""))
    lines.append(f"* **sudo/wheel üyeleri:** {', '.join(f'`{_md(u)}`' for u in access.admin_users) or '-'}")
    if access.sudo_rule_users:
        lines.append(f"* **sudoers ile yetkili:** {', '.join(f'`{_md(u)}`' for u in access.sudo_rule_users)}")
    if access.sudoers_known:
        lines.append(f"* **NOPASSWD kuralları:** {len(access.nopasswd_rules)}")
        lines += [f"  * `{_md(rule)}`" for rule in access.nopasswd_rules]
    else:
        lines.append("* **NOPASSWD kuralları:** Okunamadı (root gerekli)")
    if access.authorized_keys:
        keys = ", ".join(f"`{_md(u)}`: {n}" for u, n in sorted(access.authorized_keys.items()))
        lines.append(f"* **authorized_keys:** {keys}")

    upd = security.updates
    if upd.manager:
        lines.append("")
        lines.append("### Paket güncellemeleri")
        lines.append(f"* **Durum ({_md(upd.manager)}):** {_md(upd.summary)}")
        if upd.security_packages:
            lines.append(f"* **Güvenlik yaması bekleyen paketler:** {', '.join(f'`{_md(p)}`' for p in upd.security_packages)}")
        if upd.reboot_required:
            lines.append(f"* **Yeniden başlatma gerekli:** {_md(upd.reboot_reason)}")

    hard = security.hardening
    if hard.known:
        lines.append("")
        lines.append(f"### Sistem sertleştirme ({_md(hard.summary)})")
        lines.append("")
        lines.append("| Durum | Önem | Kontrol | Değer |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for c in sorted(hard.checks, key=lambda c: (c.passed, c.severity != "HIGH")):
            lines.append(f"| {'✓' if c.passed else '✗'} | {c.severity} | {_md(c.title)} | {_md(c.detail)} |")
        lines.append("")
        lines.append(f"* **SUID/SGID dosyalar (sistem dizinleri):** {len(hard.suid_files)}")
    return lines


def calculate_audit_score(
    snapshot: SystemSnapshot,
    ports: list[ListeningPort],
    routes: list[ProxyRoute],
    security: Optional[SecurityOverview] = None,
    storage: Optional[StorageOverview] = None,
    containers: Optional[list[ContainerSummary]] = None,
) -> tuple[int, str]:
    """Calculates an infrastructure health & security score (0-100) and grade."""
    score = 100

    # Risky exposed database/admin ports (-15 each)
    risky_ports = [p for p in ports if p.exposure == PortExposure.EXPOSED_RISK]
    score -= len(risky_ports) * 15

    # Firewall inactive (-15)
    firewall_off = snapshot.firewall.known and not snapshot.firewall.is_active
    if firewall_off or (security and security.firewall_known and not security.firewall_active):
        score -= 15

    # SSH PermitRootLogin (-10)
    if security and security.ssh.permit_root_login == "yes":
        score -= 10

    # Root-equivalent accounts other than root (-20 each): backdoor indicator
    if security:
        score -= 20 * len(security.access.extra_uid0)

    # SSH brute force without fail2ban protection (-10)
    if security and security.auth.known and security.auth.failed_total >= 100 and not security.fail2ban.protecting_ssh:
        score -= 10

    # Unapplied security updates (-10) and patches waiting for a reboot (-5)
    if security and security.updates.known and security.updates.security:
        score -= 10
    if security and security.updates.reboot_required:
        score -= 5

    # Failed hardening checks: -15 per critical one, -3 per medium one (at most -9)
    if security:
        failed = security.hardening.failed
        score -= 15 * sum(1 for c in failed if c.severity == "HIGH")
        score -= min(9, 3 * sum(1 for c in failed if c.severity == "MEDIUM"))

    # Containers that can take over the host (-10 each, at most -30)
    risky = [c for c in (containers or []) if c.security and any(r.severity == "HIGH" for r in c.security.risks)]
    score -= min(30, 10 * len(risky))

    # 502 / 504 Bad Gateway routes (-10 each)
    bad_routes = [r for r in routes if r.http_status in (502, 504)]
    score -= len(bad_routes) * 10

    # Expiring SSL within 7 days (-10 each)
    expiring_ssl = [r for r in routes if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7]
    score -= len(expiring_ssl) * 10

    # Bloated BuildKit cache (-15)
    if storage and storage.is_cache_bloated:
        score -= 15

    # Root Disk > 85% (-10)
    if any(d.percent > 85.0 for d in snapshot.disks):
        score -= 10

    score = max(15, min(100, score))

    if score >= 90:
        grade = "A+ (MÜKEMMEL)"
    elif score >= 80:
        grade = "A (GÜVENLİ & STABİL)"
    elif score >= 70:
        grade = "B (İYİ / KÜÇÜK RİSKLER MEVCUT)"
    elif score >= 50:
        grade = "C (DİKKAT / MÜDAHALE GEREKİR)"
    else:
        grade = "CRITICAL (ACİL AKSİYON ŞART)"

    return score, grade

def generate_audit_markdown(
    snapshot: SystemSnapshot,
    ports: list[ListeningPort],
    routes: list[ProxyRoute],
    backups: list[BackupTask],
    containers: list[ContainerSummary],
    databases: Optional[list[DatabaseInstance]] = None,
    services: Optional[list[ServiceUnit]] = None,
    security: Optional[SecurityOverview] = None,
    storage: Optional[StorageOverview] = None,
) -> str:
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    score, grade = calculate_audit_score(snapshot, ports, routes, security, storage, containers)

    md = [
        "```",
        " ⚡ P U L S E O P S   |   E X E C U T I V E   A U D I T   R E P O R T",
        " Altyapı Güvenlik, Donanım, Ağ, Servis ve Depolama Röntgen Raporu",
        "```",
        "",
        "# 🛡️ PulseOps Sunucu Güvenlik & Sistem Röntgen Raporu",
        "",
        "| ALTYAPI SAĞLIK & GÜVENLİK SKORU | GENEL DEĞERLENDİRME |",
        "| :--- | :--- |",
        f"| **`{score} / 100`** | **{grade}** |",
        "",
        f"> **Oluşturulma Tarihi:** {now_str}  ",
        f"> **Sunucu Adı (Hostname):** `{snapshot.hostname}`  ",
        f"> **İşletim Sistemi:** `{snapshot.os_name}` | **Çekirdek:** `{snapshot.kernel}`  ",
        f"> **Çalışma Süresi (Uptime):** `{snapshot.uptime_human}`  ",
        f"> **Güvenlik Duvarı:** `{snapshot.firewall.summary}`  ",
        "",
        "---",
        "",
        "## 1. ⚡ Donanım ve Kaynak Durumu",
        f"* **İşlemci (CPU):** %{snapshot.cpu.total_percent:.1f} ({snapshot.cpu.cores} Çekirdek) | **Load Avg:** {snapshot.cpu.load_avg[0]:.2f}, {snapshot.cpu.load_avg[1]:.2f}, {snapshot.cpu.load_avg[2]:.2f}",
        f"* **Bellek (RAM):** %{snapshot.memory.percent:.1f} ({snapshot.memory.used_gb:.1f} GB / {snapshot.memory.total_gb:.1f} GB)",
        f"* **Swap:** %{snapshot.memory.swap_percent:.1f}",
        "",
        "### Disk Bölümleri:",
        "| Bağlantı Noktası (Mount) | Cihaz | Dosya Sistemi | Kullanılan / Toplam | Doluluk |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]

    for d in snapshot.disks:
        md.append(f"| `{d.mountpoint}` | `{d.device}` | {d.fstype} | {d.used_gb:.1f} GB / {d.total_gb:.1f} GB | %{d.percent:.1f} |")

    md.extend([
        "",
        "---",
        "",
        "## 2. 🌐 WEB SİTELERİ & REVERSE PROXY HARİTASI",
        "| Alan Adı (Domain) | Dış Port | SSL Durumu | SSL Kalan Gün | Hedef (Proxy Pass) | Arka Plan Servisi / PID | Durum |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for r in routes:
        ssl_str = "Aktif (HTTPS)" if r.is_ssl else "YOK (HTTP)"
        ssl_days = f"{r.ssl_days_left} gün" if r.ssl_days_left is not None else "-"
        proc = r.target_process or "Bilinmiyor"
        md.append(f"| **{r.domain}** | `:{r.listen_port}` | {ssl_str} | {ssl_days} | `{r.target_url}` | {proc} | {r.status} |")

    md.extend([
        "",
        "---",
        "",
        "## 3. 🔍 DİNLENEN PORTLAR VE GÜVENLİK ANALİZİ",
        "| Port | Protokol | Bind IP | Servis / Proses | PID | Güvenlik Seviyesi | Risk Durumu |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for p in ports:
        risk = "NORMAL ✓"
        if p.exposure == PortExposure.EXPOSED_RISK:
            risk = "🚨 TEHLİKE: DIŞARI AÇIK!"
        elif p.exposure == PortExposure.ADMIN_SSH:
            risk = "YÖNETİM (SSH)"
        elif p.exposure == PortExposure.PUBLIC_WEB:
            risk = "GENEL WEB (80/443)"
        else:
            risk = "GÜVENLİ (DAHİLİ 127.0.0.1)"

        md.append(f"| `:{p.port}` | {p.proto.upper()} | `{p.ip}` | {p.process_name or 'Bilinmiyor'} | {p.pid or '-'} | {p.exposure.value} | {risk} |")

    # 4. Databases
    if databases:
        md.extend([
            "",
            "---",
            "",
            "## 4. 🗄️ VERİTABANI ENVANTERİ & İZOLASYON",
            "| Motor | Port | Durum | Dinleme IP (Bind) | İzolasyon Güvenliği | Yönetim Türü |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for db in databases:
            sec_badge = "🚨 DIŞARI AÇIK!" if db.is_external_open else "GÜVENLİ DAHİLİ ✓"
            md.append(f"| **{db.engine}** | `:{db.port}` | {db.status} | `{db.bind_ip}` | {sec_badge} | {db.managed_by} |")

    # 5. System Services
    if services:
        md.extend([
            "",
            "---",
            "",
            "## 5. ⚙️ SİSTEM SERVİSLERİ VE SYSTEMD DURUMU",
            "| Servis Adı | Görünen İsim | Durum | Başlangıç (Enabled) | Açıklama |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for s in services:
            state_str = "ÇALIŞIYOR ✓" if s.state == ServiceState.RUNNING else ("ÇÖKTÜ ✗" if s.state == ServiceState.FAILED else "DURDURULDU")
            md.append(f"| `{s.name}` | **{s.display_name}** | {state_str} | {s.enabled} | {s.description[:40]} |")

    # 6. SSH Security & Hardening
    if security:
        md.extend([
            "",
            "---",
            "",
            "## 6. 🛡️ SSH SERTLEŞTİRME & GÜVENLİK DUVARI DENETİMİ",
            f"* **Güvenlik Duvarı:** `{security.firewall_name}` — Durum: {'BİLİNMİYOR (root gerekli)' if not security.firewall_known else ('AKTİF ✓' if security.firewall_active else 'KAPALI 🚨')}",
            f"* **SSH Portu:** `:{security.ssh.port}`",
            f"* **Root ile Doğrudan Giriş (PermitRootLogin):** `{security.ssh.permit_root_login}` {'(ÖNERİLMEZ ⚠️)' if security.ssh.permit_root_login == 'yes' else '(GÜVENLİ ✓)'}",
            f"* **Şifreli Giriş (PasswordAuthentication):** `{security.ssh.password_authentication}`",
            f"* **SSH Anahtarı Doğrulaması (PubkeyAuthentication):** `{security.ssh.pubkey_authentication}`",
            f"* **SSH Genel Sertleştirme Puanı:** {'SERTLEŞTİRİLMİŞ ✓' if security.ssh.is_hardened else 'İYİLEŞTİRME GEREKİR ⚠️'}",
        ])
        md.extend(_soc_section(security))

    # 7. Backup Systems
    md.extend([
        "",
        "---",
        "",
        "## 7. 💾 YEDEKLEME SİSTEMİ DURUMU",
        "| Yedekleme Görevi | Mekanizma | Zaman Planı | Son Çalışma | Son Durum | Çıkış Kodu | Hedef Depolama |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for b in backups:
        md.append(f"| `{_md(b.name)}` | {_md(b.mechanism)} | {_md(b.schedule)} | {_md(b.last_run or 'Kayıt yok')} | "
                  f"{b.status.value} | {b.exit_code if b.exit_code is not None else '-'} | `{_md(b.target_path or '-')}` |")

    # 8. Docker Containers
    md.extend([
        "",
        "---",
        "",
        "## 8. 🐳 DOCKER KONTEYNERLERİ",
        "| Konteyner Adı | İmaj | Durum | Port Eşleşmeleri | Güvenlik |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ])

    if not containers:
        md.append("| Aktif Docker konteyneri bulunamadı | - | - | - | - |")
    else:
        for c in containers:
            ports_joined = ", ".join(c.ports) if c.ports else "Dahili"
            if c.security is None:
                sec_text = "-"
            else:
                risks = [f"{'⛔' if r.severity == 'HIGH' else '⚠️' if r.severity == 'MEDIUM' else 'ℹ️'} {r.text}"
                         for r in c.security.risks]
                sec_text = "; ".join(risks) or "✓"
            md.append(f"| **{_md(c.name)}** | `{_md(c.image)}` | {_md(c.status)} | `{_md(ports_joined)}` | {_md(sec_text)} |")

    # 9. Storage & BuildKit Analyzer
    if storage:
        md.extend([
            "",
            "---",
            "",
            "## 9. 📦 DEPOLAMA, BUILDKIT & CONTAINERD ANALİZİ",
            f"* **Kök Disk (Root):** {storage.root_used_gb:.1f} GB / {storage.root_total_gb:.1f} GB (%{storage.root_percent:.1f} Doluluk)",
            f"* **BuildKit Cache:** `{storage.buildkit_cache_human}` — {'🚨 AŞIRI BİRİKME TESPİT EDİLDİ!' if storage.is_cache_bloated else 'Normal ✓'}",
            f"* **Containerd OverlayFS:** `{storage.containerd_overlayfs_human}`",
            f"* **Kurtarılabilir Alan (Reclaimable):** `{storage.total_reclaimable_human}`",
            "",
            "| Depolama Türü | Toplam Boyut | Kurtarılabilir Alan | Durum / Detay |",
            "| :--- | :--- | :--- | :--- |",
        ])
        for it in storage.items:
            crit = "⚠️ ŞİŞMİŞ" if it.is_critical else "Normal"
            md.append(f"| `{it.name}` | {it.total_human} | {it.reclaimable_human} | {it.details or crit} |")

    # 10. Top Processes
    md.extend([
        "",
        "---",
        "",
        "## 10. 🧠 EN ÇOK KAYNAK TÜKETEN İLK 5 SÜREÇ",
        "| PID | Proses Adı | Kullanıcı | CPU % | Bellek (RAM MB) | Bellek % |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for proc in snapshot.top_processes[:5]:
        md.append(f"| `{proc.pid}` | **{proc.name}** | {proc.username} | %{proc.cpu_percent:.1f} | {proc.memory_mb:.1f} MB | %{proc.memory_percent:.1f} |")

    # 11. Actionable Recommendations Checklist
    recs: list[str] = []
    risky_ports = [p for p in ports if p.exposure == PortExposure.EXPOSED_RISK]
    for rp in risky_ports:
        recs.append(f"- [ ] **Güvenlik Riski:** Port `{rp.port}` ({rp.process_name or 'Servis'}) `0.0.0.0` üzerinden dışa açık! UFW ile kapatın veya bind adresini `127.0.0.1` yapın.")
    for r in routes:
        if r.http_status in (502, 504):
            recs.append(f"- [ ] **Çökmüş Servis:** `{r.domain}` sitesi {r.http_status} Bad Gateway hatası veriyor! `{r.target_url}` hedefini kontrol edin.")
        if r.is_ssl and r.ssl_days_left is not None and r.ssl_days_left <= 7:
            recs.append(f"- [ ] **SSL Yenileme:** `{r.domain}` SSL sertifikasının bitmesine yalnızca {r.ssl_days_left} gün kaldı! `certbot renew` çalıştırın.")
    if storage and storage.is_cache_bloated:
        recs.append(f"- [ ] **Önbellek Temizliği:** BuildKit önbelleği `{storage.buildkit_cache_human}` seviyesine ulaşmış! `docker builder prune -f --keep-storage 10GB` çalıştırın.")
        recs.append("- [ ] **Kalıcı GC:** `/etc/docker/daemon.json` dosyasına `\"builder\": {\"gc\": {\"defaultKeepStorage\": \"10GB\"}}` ekleyin.")
    if snapshot.firewall.known and not snapshot.firewall.is_active:
        recs.append("- [ ] **Güvenlik Duvarı:** Güvenlik duvarı devre dışı! `sudo ufw enable` ile aktif edin.")

    if not recs:
        recs.append("- [x] Tüm kontroller başarılı! Altyapıda acil müdahale gerektiren bir bulguya rastlanmadı.")

    md.extend([
        "",
        "---",
        "",
        "## 🎯 YÖNETİCİ EYLEM PLANI (ACTION CHECKLIST)",
        "",
        "\n".join(recs),
        "",
        "---",
        f"*Bu rapor **PulseOps (PulseTUI)** Altyapı Denetim Motoru tarafından otomatik olarak oluşturulmuştur. Tarih: {now_str}*",
    ])

    return "\n".join(md)

def export_audit_report(
    snapshot: SystemSnapshot,
    ports: list[ListeningPort],
    routes: list[ProxyRoute],
    backups: list[BackupTask],
    containers: list[ContainerSummary],
    databases: Optional[list[DatabaseInstance]] = None,
    services: Optional[list[ServiceUnit]] = None,
    security: Optional[SecurityOverview] = None,
    storage: Optional[StorageOverview] = None,
    output_dir: Path | str = "audit-reports"
) -> str:
    """Generates and writes an executive infrastructure audit markdown report to disk."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp_slug = time.strftime("%Y-%m-%d_%H%M%S")
    clean_host = "".join(c for c in snapshot.hostname if c.isalnum() or c in ("-", "_")) or "server"
    file_path = out_dir / f"pulseops-audit-{clean_host}-{timestamp_slug}.md"
    
    md_content = generate_audit_markdown(
        snapshot=snapshot,
        ports=ports,
        routes=routes,
        backups=backups,
        containers=containers,
        databases=databases,
        services=services,
        security=security,
        storage=storage,
    )
    file_path.write_text(md_content, encoding="utf-8")
    return str(file_path)
