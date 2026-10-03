import time
from pathlib import Path
from typing import Optional
from models.system import SystemSnapshot
from models.ports import ListeningPort, PortExposure
from models.proxy import ProxyRoute
from models.backup import BackupTask
from models.docker import ContainerSummary
from models.database import DatabaseInstance
from models.services import ServiceUnit, ServiceState
from models.security import SecurityOverview
from models.storage import StorageOverview

def calculate_audit_score(
    snapshot: SystemSnapshot,
    ports: list[ListeningPort],
    routes: list[ProxyRoute],
    security: Optional[SecurityOverview] = None,
    storage: Optional[StorageOverview] = None,
) -> tuple[int, str]:
    """Calculates an infrastructure health & security score (0-100) and grade."""
    score = 100

    # Risky exposed database/admin ports (-15 each)
    risky_ports = [p for p in ports if p.exposure == PortExposure.EXPOSED_RISK]
    score -= len(risky_ports) * 15

    # Firewall inactive (-15)
    if not snapshot.firewall.is_active or (security and not security.firewall_active):
        score -= 15

    # SSH PermitRootLogin (-10)
    if security and security.ssh.permit_root_login == "yes":
        score -= 10

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
    score, grade = calculate_audit_score(snapshot, ports, routes, security, storage)

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
            f"* **Güvenlik Duvarı:** `{security.firewall_name}` — Durum: {'AKTİF ✓' if security.firewall_active else 'KAPALI 🚨'}",
            f"* **SSH Portu:** `:{security.ssh.port}`",
            f"* **Root ile Doğrudan Giriş (PermitRootLogin):** `{security.ssh.permit_root_login}` {'(ÖNERİLMEZ ⚠️)' if security.ssh.permit_root_login == 'yes' else '(GÜVENLİ ✓)'}",
            f"* **Şifreli Giriş (PasswordAuthentication):** `{security.ssh.password_authentication}`",
            f"* **SSH Anahtarı Doğrulaması (PubkeyAuthentication):** `{security.ssh.pubkey_authentication}`",
            f"* **SSH Genel Sertleştirme Puanı:** {'SERTLEŞTİRİLMİŞ ✓' if security.ssh.is_hardened else 'İYİLEŞTİRME GEREKİR ⚠️'}",
        ])

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
        md.append(f"| `{b.name}` | {b.mechanism} | {b.schedule} | {b.last_run or 'Kayıt yok'} | {b.status.value} | {b.exit_code if b.exit_code is not None else '-'} | `{b.target_path or '-'}` |")

    # 8. Docker Containers
    md.extend([
        "",
        "---",
        "",
        "## 8. 🐳 DOCKER KONTEYNERLERİ",
        "| Konteyner Adı | İmaj | Durum | Port Eşleşmeleri |",
        "| :--- | :--- | :--- | :--- |",
    ])

    if not containers:
        md.append("| Aktif Docker konteyneri bulunamadı | - | - | - |")
    else:
        for c in containers:
            ports_joined = ", ".join(c.ports) if c.ports else "Dahili"
            md.append(f"| **{c.name}** | `{c.image}` | {c.status} | `{ports_joined}` |")

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
    if not snapshot.firewall.is_active:
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
