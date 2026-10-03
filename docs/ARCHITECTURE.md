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
        Collector -->|--live (Local)| LocalCol[LocalLiveCollector]
        Collector -->|--host (SSH Remote)| SSHCol[SSHCollector]
    end

    subgraph Parsing & Diagnostic Probes
        SSHCol --> NginxProbe[Nginx & Upstream Parser]
        SSHCol --> PortProbe[SS/Netstat & Port Security]
        SSHCol --> DBProbe[Database Discovery Probe]
        SSHCol --> ServiceProbe[Systemd Service Probe]
        SSHCol --> SecProbe[SSH & Firewall Hardening Audit]
        SSHCol --> StorageProbe[BuildKit & Containerd Analyzer]
        SSHCol --> BackupProbe[Timers & Crontab Inspector]
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
* `collectors/base.py`:
  * `ServerCollector` soyut arayüzü `poll()` metodunu zorunlu kılar.
  * Polling sonucunda tam ve tipli telemetri paketleri döndürülür: `(snapshot, ports, routes, backups, containers, databases, services, security, storage)`.
* `collectors/ssh_collector.py` (`SSHCollector`):
  * `paramiko.SSHClient` kullanarak parola veya RSA/Ed25519 özel anahtarıyla bağlanır.
  * Tek bir toplu probe betiği (`BATCH_PROBE_SCRIPT`) çalıştırır; `ss`, `ps`, `df`, `docker`, `systemctl`, `sshd_config` vb. çıktıları `===SECTION:...===` işaretleriyle ayrıştırır.
* `collectors/base.py` (`LocalLiveCollector`):
  * Yerel işletim sistemini algılar (`platform.system()`).
  * Yerel Linux sistemde `psutil`, `/proc` ve `ss` gibi komutlarla telemetri üretir.
* `collectors/base.py` (`DemoCollector`, `collectors/mock_collector.py` üzerine kurulu):
  * Geliştirme, test ve sunum amaçlı gerçekçi mock veri simülatörüdür.

* `collectors/telemetry.py`: `collect_telemetry(collector)` tek bir polling turunu `models/telemetry.py::Telemetry` nesnesi olarak döndürür; `summarize_alerts()` aktif riskleri listeler. `status`/`report`/`check` komutları bunu kullanır.
* `collectors/privilege_collector.py`: Yerel süreç veya SSH probe'unun `PRIV` bölümünden yetki durumunu (`PrivilegeInfo`) çıkarır.

### A2. Komut Satırı Katmanı
* `cli.py`: TUI argümanları (`--interval`, `--no-color`, `--ascii`, `--no-mouse`) ve alt komut yönlendirmesi.
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
* `ui/app.py`: Ana Textual uygulaması. 1-saniye veya yapılandırılabilir aralıklarla arka planda çalışır (`set_interval`). Not: polling şu an UI thread'inde senkron çalışır; thread worker'a taşınması [ROADMAP](plans/ROADMAP.md) Faz 2'dedir.
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
3. **Sudo İhtiyacının İzolasyonu:** Temel telemetri (`ss`, `ps`, `df`, `docker ps`) için standart kullanıcı yetkileri yeterlidir; UFW veya kısıtlı loglar gibi alanlarda yetki yoksa uygulama çökmek yerine `[Yetki Yok / Bilinmiyor]` etiketleriyle graceful fallback uygular.
