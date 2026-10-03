# 🏛️ PulseOps (PulseTUI) Altyapı ve Sistem Mimarisi

> **PulseOps (PulseTUI)**: Linux sunucuları için, ajan gerektirmeyen (agentless), gerçek zamanlı TUI (Terminal User Interface) gözlem, web proxy, güvenlik ve depolama teşhis motorudur.

---

## 1. Temel Prensipler ve Vizyon

Geleneksel sunucu izleme araçları (Datadog Agent, Prometheus Node Exporter, Zabbix vb.) sunucuya kalıcı ajanlar, servisler veya ağır arka plan süreçleri kurmayı zorunlu kılar. Bu durum özellikle üretim sunucularında ek yük, güvenlik açığı riski ve konfigürasyon karmaşıklığı doğurur.

**PulseOps** bu paradigmayı yıkar:
1. **Agentless (Ajansız Çalışma):** Uzak sunucuya hiçbir ajan, binary veya servis kurulmaz. Yalnızca standart SSH (`paramiko`) üzerinden standart Linux komutlarını (`ss`, `ps`, `df`, `docker`, `systemctl`, `ufw`) çalıştırarak telemetri toplar.
2. **Sıfır Ayak İzi & %100 Salt-Okunur (Read-Only):** Sunucu üzerinde hiçbir dosya değiştirilmez, servis durdurulmaz. Yalnızca okuma izinli teşhis komutları çalıştırılır.
3. **btop & Datadog Esintili UI:** Gelişmiş Textual reactive motoru ve Rich tabanlı kurumsal renk paleti (Datadog & JetBrains Dark) ile terminalde modern bir izleme deneyimi sunar.
4. **Linux Odaklı:** Linux sunucularda (Ubuntu, Debian, RHEL ailesi) doğrudan sunucu üzerinde (`pulseops`) veya uzaktan SSH ile (`pulseops user@host`) çalışır.

---

## 2. Genel Mimari Şeması

```mermaid
graph TD
    User([Terminal / Sistem Yöneticisi]) -->|CLI / Kısayol Tuşları| App[PulseOps Textual UI Engine]
    
    subgraph Data Collection Layer
        Collector[Collector Factory] -->|--demo| DemoCol[DemoCollector]
        Collector -->|pulseops - yerel Linux| ProbeCol[ProbeCollector + LocalTransport]
        Collector -->|pulseops user@host| SSHCol[SSHCollector = ProbeCollector + SSHTransport]
        ProbeCol --> Probe[Tek shell probe: FAST / SLOW / LOGS katmanları]
        SSHCol --> Probe
    end

    subgraph Parsing & Diagnostic Probes
        Probe --> NginxProbe[Nginx & Upstream Parser]
        Probe --> PortProbe[ss / netstat / proc-net & Port Security]
        Probe --> DBProbe[Database Discovery]
        Probe --> ServiceProbe[Systemd Service Probe]
        Probe --> SecProbe[sshd -T & Firewall INPUT Audit]
        Probe --> StorageProbe[BuildKit & Containerd Analyzer]
        Probe --> BackupProbe[Timers, Crontab & Snapshot Inspector]
    end

    subgraph Domain Models (Pydantic v2)
        Snap[SystemSnapshot]
        Ports[ListeningPort]
        Routes[ProxyRoute]
        DBs[DatabaseInstance]
        Services[ServiceUnit]
        Security[SecurityOverview]
        Storage[StorageOverview]
        Backups[BackupTask]
        Containers[ContainerSummary]
    end

    Data_Collection_Layer --> Domain_Models
    Domain_Models --> App
    
    subgraph UI & Reporting
        App --> Header[HeaderBar & Live Badge]
        App --> StatusBar[DashboardStatusBar]
        App --> Tabs[10 TabbedContent Panels]
        App --> Modals[Config Viewer & Port Finder Modals]
        App --> Exporter[Executive Audit Exporter Engine]
    end

    Exporter -->|'e' Tuşu| ReportFile["audit-reports/pulseops-audit-*.md"]
```

---

## 3. Katmanlı Mimari Detayları

### A. Veri Toplama Katmanı (Collector Layer)

Yerel ve uzak mod **aynı kodu** çalıştırır: tek bir POSIX shell betiği (probe) hedef makinede `sh -s` ile
çalışır, çıktısı bölümlere ayrılır ve aynı ayrıştırıcılardan geçer. Böylece iki mod aynı sonucu verir ve
her özellik bir kez yazılır.

* `collectors/probe.py`: Probe betiği ve bölüm ayrıştırıcı.
  * **FAST** (varsayılan 2 sn): `/proc` dosyaları shell builtin'leriyle (fork'suz) okunur — CPU, RAM, disk
    I/O, ağ — artı `ss -lntu` ve tüm süreçler için tek bir `awk` geçişi. sudo **asla** kullanılmaz.
  * **SLOW** (varsayılan 30 sn): host kimliği, diskler (`df`), port sahipleri (`ss -p`), nginx, timer/cron,
    yedek dosyaları, docker, depolama, güvenlik duvarı, servisler, `sshd -T`, yetki durumu.
    Neredeyse hiç değişmeyen bölümler (`systemctl list-unit-files`, `getconf`) 10 dakikada bir yenilenir.
  * **LOGS**: Yalnızca Loglar sekmesi açıkken veya yavaş turda.
  * Her çalıştırmada rastgele bir nonce bölüm işaretlerine eklenir; komut çıktısı (ör. bir log satırı) sahte
    bölüm enjekte edemez. `LC_ALL=C` ile çıktılar dilden bağımsızdır.
* `collectors/probe_parsers.py`: Saf (I/O'suz) ayrıştırıcılar: `/proc/stat`, `/proc/meminfo`, `df -P -T`,
  `/proc/diskstats`, `/proc/net/*`, `/proc/*/stat`, güvenlik duvarı (UFW, firewalld, iptables INPUT,
  nftables input hook), yedek dosyaları.
* `collectors/probe_collector.py` (`ProbeCollector`): Durumlu toplayıcı. Oranları (CPU, süreç CPU, ağ,
  disk I/O) iki örnek arasındaki farktan hesaplar; süre olarak hedefin `/proc/uptime` farkını kullanır,
  böylece SSH gecikmesi oranları bozmaz. İlk turda kısa bir baseline örneği alır, tek seferlik
  `pulseops status` da gerçek CPU değerini gösterir. Yavaş katmanı önbellekte tutar.
* `collectors/transport.py`: `LocalTransport` (alt süreç) ve `SSHTransport` (paramiko; keepalive, tek
  seferlik otomatik yeniden bağlanma, `~/.ssh/config` çözümleme, ProxyJump zincirleri, ProxyCommand).
  İkisi de betiği stdin'den `sh -s`'e verir; uzaktaki login shell fish/zsh olsa da çalışır.
* `collectors/hostkeys.py`: OpenSSH `StrictHostKeyChecking` semantiğiyle host key doğrulaması.
* `collectors/ssh_collector.py` (`SSHCollector`): `ProbeCollector` + `SSHTransport`.
* `collectors/base.py`: `BaseCollector.collect(include_slow, include_logs) -> Telemetry` tek giriş noktasıdır.
  `create_local_collector()` Linux'ta `ProbeCollector(LocalTransport())`, diğer platformlarda psutil tabanlı
  `LocalLiveCollector` döndürür. `DemoCollector` `collectors/mock_collector.py` üzerine kuruludur.
* `collectors/telemetry.py`: `collect_telemetry()` ve `summarize_alerts()` (eşikler yapılandırılabilir).
* `collectors/privilege_collector.py`: `PRIV` bölümünden yetki durumunu (`PrivilegeInfo`) çıkarır.
* SOC bölümleri (`FAIL2BAN`, `AUTH`, `ACCESS`): sshd kayıtları hedefte `awk` ile özetlenir (sayılar + ilk 10),
  saldırı altındaki bir sunucuda bile birkaç yüz bayt aktarılır. Ayrıntılar: [SECURITY.md](SECURITY.md).

* `collectors/drift.py`: Telemetriden güvenlik "parmak izi" (dışa açık portlar, hesaplar, UID 0, sudo grupları,
  NOPASSWD, authorized_keys, güvenlik duvarı, sshd, fail2ban, çöken servisler, konteynerler) ve iki parmak izi
  arasındaki farkı önem derecesiyle (HIGH/MEDIUM/INFO) çıkarır. Okunamayan kategori `None`'dır ve karşılaştırılmaz.
* `history.py` (`HistoryStore`): SQLite; makine kimliği (`/etc/machine-id`) başına metrik örnekleri, son parmak izi
  (baseline) ve değişiklik kayıtları. Her tüketicinin (`check`, `tui`) kendi "son okuma" imleci vardır.

### A2. Komut Satırı Katmanı
* `cli.py`: TUI argümanları (`--interval`, `--slow-interval`, `--no-color`, `--ascii`, `--no-mouse`), yapılandırma yükleme ve alt komut yönlendirmesi.
* `pulseops_config.py`: `/etc/pulseops/config.toml` ve `~/.config/pulseops/config.toml` (Pydantic ile doğrulanır; bilinmeyen anahtar hatadır).
* `logging_setup.py`: `~/.cache/pulseops/pulseops.log` (döndürmeli, 1 MB x 3). TUI terminali kullandığı için tanılama dosyaya yazılır.
* `commands.py`: Ortak bağlantı argümanları, collector seçimi, `status` / `report` / `check`.
* `installer.py`: `version` / `update` / `uninstall`; kurulum türünü (binary, venv, pipx, kaynak) algılar.
* `ui/ascii_filter.py`: `--ascii` modunda terminale giden her karakteri aynı hücre genişliğinde ASCII karşılığına çeviren Textual çıktı filtresi.

### B. Alan Modelleri (Domain Models - Pydantic v2)
Bütün telemetri verileri güçlü tip garantisi (`BaseModel`) ve doğrulama kurallarıyla modellenmiştir:
* `models/system.py`: `SystemSnapshot`, `CPUUsage`, `MemoryUsage`, `DiskPartition`, `ProcessInfo`, `FirewallStatus`.
* `models/ports.py`: `ListeningPort`, `PortExposure` (`SAFE_INTERNAL`, `PUBLIC_WEB`, `ADMIN_SSH`, `EXPOSED_RISK`).
* `models/proxy.py`: `ProxyRoute` (Nginx eşleşmesi, backend URL, upstream prosesi, HTTP sağlık kodu, SSL kalan gün).
* `models/database.py`: `DatabaseInstance`, `DatabaseType` (PostgreSQL, MySQL, Redis, MongoDB, ClickHouse vb.).
* `models/services.py`: `ServiceUnit`, `ServiceState` (Active, Failed, Inactive).
* `models/security.py`: `SecurityOverview`, `SSHSecurityAudit` (Port, PermitRootLogin, PasswordAuth).
* `models/storage.py`: `StorageOverview`, `StorageItem`, `ContainerdSnapshotGroup` (BuildKit & OverlayFS derin analiz).
* `models/backup.py`: `BackupTask`, `BackupStatus`.
* `models/docker.py`: `ContainerSummary`.

### C. Arayüz ve Sunum Katmanı (Textual Reactive Engine)
* `ui/app.py`: Ana Textual uygulaması. Her `interval`'de `collector.collect()` bir **thread worker**'da çalışır, sonuç `apply_telemetry()` ile UI thread'inde uygulanır; arayüz hiçbir zaman beklemez. Önceki tur bitmeden yenisi başlamaz (yavaş sunucularda istekler birikmez). Hata durumunda son veriler ekranda kalır, header'da kırmızı bağlantı uyarısı çıkar ve hata log dosyasına yazılır.
* `ui/safe.py`: Telemetri güvenilmeyen veridir (süreç adları, log satırları, domainler). `PlainTable` düz metin hücreleri markup olarak yorumlamaz; log görüntüleyici düz metni regex ile renklendirir.
* **10 Sekmeli Sekme Mimarisi (`TabbedContent`):**
  1. `1 - Dashboard`: Donanım göstergeleri, CPU/RAM/Swap çubukları ve sistem sağlık skoru.
  2. `2 - Süreçler`: CPU/RAM'e göre sıralı süreçler.
  3. `3 - Portlar`: Dinlenen portlar, bind IP'leri, güvenlik sınıflandırması.
  4. `4 - Servisler`: Systemd birimleri, aktif/hatalı durumlar.
  5. `5 - Veritabanı`: Keşfedilen DB servisleri, dış ağ riskleri.
  6. `6 - Siteler`: Reverse proxy domainleri, SSL gün sayaçları, 502 Bad Gateway teşhisi.
  7. `7 - Yedekler`: Systemd timer'ları, crontab işleri, snapshot durumları.
  8. `8 - Loglar`: Sistem ve web log akışları.
  9. `9 - Güvenlik`: SSH sertleştirme denetimi, güvenlik duvarı kuralları, açık risk portları.
  10. `0 - Depolama`: Docker disk kullanımı, BuildKit önbellek şişmesi, containerd snapshot analizi.
* **Modal Pencereler:**
  * `ConfigViewerModal` (`c` tuşu): Nginx, Docker Compose veya SSH konfigürasyonlarını sözdizimi renklendirmesiyle inceler.
  * `PortFinderModal` (`f` tuşu): Yeni servis açılmadan önce boş portları otomatik tarar ve listeler.

### D. Yönetici Denetim Raporlama Motoru (Executive Audit Exporter)
* `collectors/audit_exporter.py`:
  * Altyapı Sağlık ve Güvenlik Puanı (0-100) ve Harf Notu (A+, A, B, C, CRITICAL) hesaplar.
  * Sunucudaki 10 modülün tamamını detaylı Markdown tablolarına dönüştürür.
  * **Yönetici Eylem Planı (Action Checklist):** Tespit edilen risklere (örn. açık Mongo portu, süresi yaklaşan SSL, şişmiş BuildKit cache) özel çözüm komutları (`docker builder prune`, `certbot renew`, `ufw deny`) üretir.
  * `e` tuşuyla saniyeler içinde `audit-reports/pulseops-audit-<host>-<timestamp>.md` dosyasına kaydeder.

---

## 4. Renk Paleti ve Tasarım Dili

PulseOps, modern kurumsal operasyon araçlarının (Datadog & JetBrains Dark) tasarım dilini benimser:

| Bileşen | Renk Kodu | Anlam / Kullanım |
| :--- | :--- | :--- |
| **Arka Plan (Background)** | `#1e1e2e` / `#181825` | Yormayan kurumsal koyu gri/lacivert |
| **Vurgu & Marka (Primary Brand)** | `#6366f1` / `#818cf8` | PulseOps İndigo & Canlı Mor |
| **Canlı / Canlılık Rozeti** | `#10b981` (Emerald) | `● LIVE` aktif telemetri |
| **Başarı / Güvenli** | `#22c55e` (Green) | Sertleştirilmiş SSH, güvenli portlar, 200 OK |
| **Uyarı / Dikkat** | `#f59e0b` (Amber) | Biten SSL (<30 gün), yüksek disk doluluğu |
| **Kritik / Acil Hata** | `#ef4444` (Rose/Red) | 0.0.0.0 açık DB portu, 502 Bad Gateway, şişmiş cache |
| **Web & Bağlantılar** | `#38bdf8` (Sky Blue) | Domainler, dış portlar |
| **Metin & Başlıklar** | `#f8fafc` / `#94a3b8` | Yüksek okunurluklu kontrast beyaz ve gri tonları |

---

## 5. Güvenlik Prensipleri

1. **Parola ve Gizli Bilgi Sızdırmazlığı:** CLI argümanlarında verilen SSH parolaları veya anahtarları loglanmaz veya ekranda gösterilmez.
2. **Kabuk Enjeksiyonu Koruması:** SSH üzerinde yürütülen komutlar parametrik ve statik olarak tanımlanmıştır; kullanıcı girdisi doğrudan shell komutuna gömülmez.
3. **Sudo İhtiyacının İzolasyonu:** Temel telemetri standart kullanıcı yetkisiyle çalışır. sudo root olarak hiç, hızlı katmanda hiçbir zaman kullanılmaz; root olmayan kullanıcıda yalnızca parolasız sudo'nun çalıştığı bir kez tespit edildikten sonra yavaş katmanda `sudo -n` ile denenir (her sudo çağrısı auth log'a yazıldığı için). `[general] use_sudo = false` ile tamamen kapatılabilir. Okunamayan veriler (ör. güvenlik duvarı) "aktif" veya "kapalı" sayılmaz, **bilinmiyor** olarak gösterilir ve skordan puan düşürmez.
4. **Markup / Terminal Enjeksiyonu Koruması:** Sunucudan gelen hiçbir metin Rich markup olarak yorumlanmaz; `[/]` içeren bir istek yolu arayüzü çökertemez, `[link=...]` tıklanabilir link üretemez (`tests/test_markup_injection.py`).
5. **Probe Bütünlüğü:** Bölüm işaretleri çalıştırma başına rastgele nonce içerir; çıktıdaki sahte işaretler veri olarak kalır.
