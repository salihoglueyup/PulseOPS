# ServerTUI: btop Esintili Linux Sunucu & Web/Port/Yedekleme Gözlem Paneli
## Kapsamlı Uygulama ve Mimari Planı (v1.0)

> **Antigravity Ajanı İçin:** Bu plan adım adım, TDD (Test Driven Development) ve güvenli (read-only) geliştirme prensipleriyle uygulanacaktır.

**Amaç:** Birden fazla web sitesi, veritabanı ve servis barındıran Linux sunucularında; donanım sağlığı (CPU/RAM/Disk/Ağ) ile birlikte **web siteleri (domainler), reverse proxy eşleşmeleri, dinlenen portların güvenlik seviyeleri, yedekleme (backup) zamanlayıcıları ve Docker konteynerlerini** tek bir btop estetiğindeki terminal panelinde (TUI) canlı ve sıfır riskle izlemek.

**Temel Felsefe:**
1. **%100 Salt-Okunur (Read-Only) & Sıfır Risk:** Sunucuda hiçbir ayarı bozmaz, servisleri durdurmaz veya yeniden başlatmaz. Sadece durum röntgeni çeker.
2. **Web ve Port Odaklı Zeka:** Standart izleyicilerin (btop/htop) aksine, Nginx/Apache/Docker arkasındaki portların hangi domain'e ait olduğunu çözümler.
3. **Akıllı Güvenlik Uyarısı:** Dış dünyaya kontrolsüz açılmış (`0.0.0.0`) veritabanı portlarını (Postgres, MySQL, Mongo, Redis) anında tespit eder.

---

## 🛠️ Teknoloji Seçimi & Terminalde JavaScript vs Python İncelemesi

Terminal arayüzü (TUI) için iki güçlü aday:

### A. JavaScript / Node.js Dünyası:
* **Araçlar:** `ink` (React tabanlı CLI bileşenleri), `blessed` / `blessed-contrib` (Eski nesil dashboard kütüphanesi).
* **Artıları:** Web geliştiricileri için React JSX syntax'ı ile arayüz yazmak çok tanıdıktır.
* **Eksileri:**
  1. `blessed` ve `blessed-contrib` uzun yıllardır terk edilmiş durumdadır, modern terminallerde (TrueColor, modern Unicode) bozulmalar yapabilir.
  2. `ink` ise interaktif sihirbazlar veya formlar (örneğin `create-react-app` kurulum ekranları) için harikadır; ancak 60 FPS canlı metrikler, btop tarzı pikselli Braille grafikler ve çok pencereli karmaşık dashboard düzenlerinde performansı düşebilir.
  3. Sunucuda Node.js runtime'ı ve `node-gyp` bağımlılıkları gerekebilir.

### B. Python Dünyası (`Textual` + `Rich`):
* **Artıları:**
  1. **Günümüzün TUI standardı:** Will McGugan (Rich'in yaratıcısı) tarafından sıfırdan geliştirilen `Textual`, CSS destekli modern yerleşim (Grid/Flexbox), asenkron reaktif state motoru ve btop estetiğine birebir uyumlu bileşenler sunar.
  2. **Yerel Linux Entegrasyonu:** Linux sunucularda Python 3 zaten kuruludur. `/proc`, `sysfs`, `systemctl`, `ss` gibi sistem katmanlarına en hızlı ve en hafif erişimi sağlar (`psutil` ile sıfır overhead).
  3. **Yüksek Performans & Düşük Kaynak:** Sunucuda sadece %0.5 CPU ve 20-30 MB RAM ile çalışır.

> **Tavsiye Edilen Karar:** 
> Çekirdek motor ve btop tarzı zengin terminal arayüzü için **Python + Textual** omurgası kurulacak. Eğer ileride JavaScript ile Node/React tabanlı bir CLI veya TUI denemek istersen, çekirdek motorumuz dışarıya standart JSON çıktısı verecek şekilde soyutlanacaktır.

---

## 📁 Proje Dosya ve Dizin Hiyerarşisi (Ana Dizin Yerleşimi)

Gereksiz katmanlaşmayı önlemek ve hem Windows'ta hem de Linux'ta doğrudan `python main.py` veya `python cli.py` ile anında çalıştırabilmek için dosyalar **proje ana dizinine (`c:\Gelistirme\terminaltui\`)** yerleştirilecektir:

```text
c:\Gelistirme\terminaltui\
│
├── main.py                     # Doğrudan çalıştırma giriş noktası (Hızlı başlatıcı)
├── cli.py                      # Komut satırı argümanları (--demo, --interval, --help vb.)
├── pyproject.toml              # Proje metadata ve paket konfigürasyonu
├── requirements.txt            # Python bağımlılık listesi (textual, rich, psutil, pydantic)
├── .gitignore                  # Git dışlama kuralları (__pycache__, .venv vb.)
├── README.md                   # Proje tanıtım ve kullanım dokümantasyonu
│
├── docs/                       # Mimari ve plan dokümanları
│   └── plans/
│       └── 2026-09-30-server-tui.md
│
├── models/                     # Type-safe veri şemaları (Pydantic Modelleri)
│   ├── __init__.py
│   ├── system.py               # CPU, RAM, Disk, Ağ metrik modelleri
│   ├── ports.py                # Dinlenen portlar ve güvenlik seviyesi (Public/Safe)
│   ├── proxy.py                # Domain -> ProxyPass -> İç port eşleme modelleri
│   ├── backup.py               # Yedekleme zamanlayıcıları ve durum modelleri
│   └── docker.py               # Konteyner durum ve port eşleme modelleri
│
├── collectors/                 # Sistemden veri çeken toplayıcı ve parser motorları
│   ├── __init__.py
│   ├── base.py                 # Abstract Base Collector arayüzü
│   ├── system_collector.py     # psutil & /proc üzerinden donanım metrikleri
│   ├── port_collector.py       # ss -lntup / psutil soket toplayıcı ve sınıflandırıcı
│   ├── nginx_parser.py         # Nginx sites-enabled parser (Domain -> Proxy Port)
│   ├── backup_collector.py     # systemctl list-timers ve cron yedekleme keşif motoru
│   ├── docker_collector.py     # Docker container ve port haritası çıkarıcı
│   └── mock_collector.py       # Windows & Demo modu için gerçekçi sahte veri üretici
│
├── ui/                         # Textual tabanlı btop TUI arayüz motoru
│   ├── __init__.py
│   ├── app.py                  # Ana Textual App (Uygulama yaşam döngüsü ve döngü)
│   ├── styles.tcss             # btop / Catppuccin temalı CSS stil dosyası
│   └── widgets/                # Görsel paneller ve bileşenler
│       ├── __init__.py
│       ├── header_bar.py       # Sunucu adı, OS, Uptime ve Canlı Saat rozeti
│       ├── vitals_panel.py     # CPU Braille grafik, RAM/Swap barları, Ağ RX/TX
│       ├── port_table.py       # Domain -> Proxy -> Port -> Güvenlik durumu tablosu
│       ├── backup_panel.py     # Yedekleme timer'ları, son çalışma ve başarı durumu
│       ├── service_panel.py    # Docker konteynerleri ve systemd kritik servisleri
│       └── sparkline.py        # Canlı Unicode Braille (⢕⢍⢌⢂⠢⡪⡪⡑) grafik motoru
│
└── tests/                      # Otomatik testler ve TDD fixture'ları
    ├── __init__.py
    ├── test_models.py          # Veri modelleri doğrulama testleri
    ├── test_port_collector.py  # Port parse ve güvenlik sınıflandırma testleri
    ├── test_nginx_parser.py    # Nginx domain-proxy eşleştirme testleri
    ├── test_backup_collector.py# Backup timer ve cron regex testleri
    └── fixtures/               # Örnek ss çıktısı, nginx configleri, systemctl çıktıları
        ├── ss_output.txt
        ├── nginx_sample.conf
        └── timers_output.txt
```

---

## 🏗️ Sistem Mimarisi ve Katmanlar

```
┌────────────────────────────────────────────────────────────────────────┐
│                        SERVER TUI GÖZLEM MOTORU                        │
├────────────────────────────────────────────────────────────────────────┤
│ 1. ARAYÜZ KATMANI (Textual / Rich TUI Engine)                          │
│    ├─ HeaderBar (Canlı Saat / Uptime / OS / Hostname Rozeti)           │
│    ├─ VitalsGrid (CPU Braille Sparkline, RAM/Swap Barları, Ağ RX/TX)   │
│    ├─ PortProxyTable (Domain ──► SSL ──► Proxy Port ──► Servis Haritası)│
│    ├─ BackupStatusPanel (Systemd Timers, Crontab, Restic, Son Durum)   │
│    └─ ServiceContainerPanel (Docker & Systemd Sağlık Takibi)           │
├────────────────────────────────────────────────────────────────────────┤
│ 2. TOPLAYICI KATMANI (Collectors & Data Discovery)                     │
│    ├─ SystemCollector (CPU, RAM, Disk I/O, Ağ Bant Genişliği)          │
│    ├─ PortCollector (`ss -lntup`, `/proc/net`, IP Sınıflandırması)     │
│    ├─ NginxParser (`/etc/nginx/sites-enabled/`, server_name eşleme)    │
│    ├─ BackupCollector (`systemctl list-timers`, cron, restic/borg)     │
│    ├─ DockerCollector (`/var/run/docker.sock` veya CLI JSON)           │
│    └─ MockCollector (Windows'ta geliştirme & demo simülasyonu)         │
├────────────────────────────────────────────────────────────────────────┤
│ 3. VERİ MODELLERİ KATMANI (Pydantic / Typed Models)                    │
│    ├─ SystemSnapshot, CpuMetric, MemoryMetric, NetworkRate             │
│    ├─ ListeningPort (Protokol, IP, Port, PID, Process, ExposureLevel)  │
│    ├─ ProxyRoute (Domain, ListenPort, TargetUrl, TargetProcess)        │
│    └─ BackupTask (JobName, Schedule, LastRun, ExitStatus, TargetPath)  │
├────────────────────────────────────────────────────────────────────────┤
│ 4. ÇALIŞMA MODLARI (Run Modes)                                         │
│    ├─ Mod A: LOCAL (Doğrudan sunucuda `python main.py`)                │
│    ├─ Mod B: DEMO / SIMULATION (Windows'ta `python cli.py --demo`)     │
│    └─ Mod C: AGENTLESS REMOTE (Windows'tan SSH üzerinden uzaktan)      │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 📋 Ayrıntılı Görev ve Uygulama Maddeleri

### Görev 1: Proje Temeli, Konfigürasyon ve Test Ortamı
* **Amaç:** Projenin bağımsız çalışmasını sağlayacak modüler dizin ağacını ve bağımlılıkları hazırlamak.
* **Yapılacaklar:**
  1. `pyproject.toml` oluşturulması: Proje metadata'sı, bağımlılıklar (`textual>=0.70.0`, `rich>=13.7.0`, `psutil>=5.9.0`, `pydantic>=2.5.0`, `pytest>=7.4.0`).
  2. `requirements.txt` ve geliştirme gereksinimlerinin dondurulması.
  3. Git konfigürasyonu (`.gitignore` dosyasında `__pycache__`, `.venv`, `.pytest_cache` vb.).
  4. Temel dizin yapısının ana dizinde kurulması:
     - `models/`
     - `collectors/`
     - `ui/`
     - `ui/widgets/`
     - `tests/`
     - `tests/fixtures/`

---

### Görev 2: Pydantic Veri Modelleri (Type-Safe Şemalar)
* **Amaç:** Toplanan hiçbir verinin eksik veya bozuk formatta UI'a gitmemesini sağlamak.
* **Maddeler:**
  1. **`models/system.py`:**
     - `CpuMetric`: Çekirdek sayısı, anlık yüzde, çekirdek başına yük dizisi, yük ortalamaları (1m, 5m, 15m).
     - `MemoryMetric`: Toplam RAM, kullanılan, boş, önbellek, Swap toplamı ve yüzdesi.
     - `DiskPartition`: Cihaz (`/dev/sda1`), mount noktası (`/`), dosya sistemi (`ext4`), toplam/kullanılan GB, yüzde.
     - `NetworkRate`: Arayüz adı (`eth0`), saniyede indirilen (RX) KB/MB, yüklenen (TX) KB/MB.
  2. **`models/ports.py`:**
     - `PortExposure` (Enum): `SAFE_INTERNAL` (`127.0.0.1`), `PUBLIC_WEB` (`80`, `443`), `EXPOSED_RISK` (`0.0.0.0:3306`, `0.0.0.0:5432` vb.).
     - `ListeningPort`: Protokol (TCP/UDP), IP (`0.0.0.0`, `127.0.0.1`, `::`), Port numarası, PID, Process Adı, Exposure etiketi.
  3. **`models/proxy.py`:**
     - `ProxyRoute`: Alan adı (`site1.com`, `api.site.com`), dinlenen port (`80`, `443`), SSL durumu (Var/Yok), hedef URL (`http://127.0.0.1:3000`), hedef process/container adı.
  4. **`models/backup.py`:**
     - `BackupStatus` (Enum): `SUCCESS`, `FAILED`, `RUNNING`, `NEVER_RUN`.
     - `BackupTask`: Timer/Cron adı, zaman planı (ör. "Her gün 03:00"), son çalışma zamanı, çıkış kodu (0 = Başarılı), hedef dizin veya depolama alanı.
  5. **`models/docker.py`:**
     - `ContainerSummary`: Konteyner ID, isim, imaj, durum (`running`, `exited`), port eşleşmeleri (`3000:3000`), uptime.

---

### Görev 3: Port Keşif Motoru (`PortCollector` & Parser)
* **Amaç:** Sunucuda hangi servislerin hangi IP ve portta çalıştığını eksiksiz çıkarmak.
* **Maddeler:**
  1. Linux'ta `ss -lntup` (veya `netstat -tulpen`) komutunun çıktısını parse eden regex motoru yazımı (`collectors/port_collector.py`).
  2. Yerel Python çalışmasında `psutil.net_connections(kind='inet')` entegrasyonu ile C seviyesinde doğrudan soket okuma.
  3. **Güvenlik Sınıflandırma Mantığı (Security Classifier):**
     - Eğer dinlenen IP `127.0.0.1` veya `::1` ise -> **Güvenli / Dahili (Yeşil)**
     - Eğer port `80` veya `443` ise ve IP `0.0.0.0` ise -> **Standart Web Trafiği (Mavi)**
     - Eğer port `22` ise -> **Yönetim SSH (Sarı)**
     - Eğer port `3306, 5432, 27017, 6379, 9200, 8080, 3000` gibi bir servis olup IP `0.0.0.0` ise -> **AÇIK TEHLİKE / FIREWALL İNCELEMESİ GEREKİR (Kırmızı Yanıp Sönen Uyarı)**.
  4. Gerçek sunucu çıktılarıyla hazırlanmış fixture testleri (`tests/fixtures/ss_output.txt`).

---

### Görev 4: Web Siteleri & Reverse Proxy Eşleştirici (`NginxParser`)
* **Amaç:** Sunucudaki onlarca web sitesinin arka plandaki hangi portlara bağlandığını otomatik çözmek.
* **Maddeler:**
  1. `/etc/nginx/sites-enabled/*` ve `/etc/nginx/conf.d/*` dosyalarını tarayan parser motoru (`collectors/nginx_parser.py`).
  2. Her `server { ... }` bloğunda şunları yakalama:
     - `server_name` -> Domainler (örn: `ornek.com`, `www.ornek.com`)
     - `listen` -> Portlar (80, 443 ssl, http2)
     - `ssl_certificate` -> SSL aktif mi?
     - `location / { proxy_pass http://127.0.0.1:XXXX; }` -> Yönlendirilen iç port!
  3. **Port Eşleştirme Motoru (Correlator):**
     - Nginx'in yönlendirdiği `127.0.0.1:3001` portu ile `PortCollector`'dan gelen PID/Process'i eşleştir:
     - *Sonuç Çıktısı:* `musteri1.com (HTTPS 443) ──► Nginx ──► 127.0.0.1:3001 (Node.js PID 4120)`
  4. Karmaşık konfigürasyonlar (upstream blokları, unix socket yönlendirmeleri `unix:/run/php/php-fpm.sock`) için fallback desteği.

---

### Görev 5: Akıllı Yedekleme (Backup) Dedektörü (`BackupCollector`)
* **Amaç:** Sunucuda yedek alınıyor mu, en son ne zaman alındı ve hata verdi mi sorularına kesin cevap bulmak.
* **Maddeler:**
  1. **Systemd Timer Taraması (`collectors/backup_collector.py`):**
     - `systemctl list-timers --all` çıktısını okuma.
     - İçinde `backup`, `dump`, `restic`, `borg`, `rsync`, `snapshot` geçen timer servislerini filtreleme.
     - Timer'ın bir sonraki çalışma zamanı (`NEXT`) ve en son ne zaman çalıştığı (`LEFT / LAST`).
  2. **Servis Durumu & Çıkış Kodu Kontrolü:**
     - Timer'a bağlı servisin `systemctl status <isim>.service` kontrolü.
     - `Main PID ... (code=exited, status=0/SUCCESS)` kontrolü ile "Son yedek başarılı mı?" doğrulaması.
  3. **Cron Taraması:**
     - `/etc/crontab`, `/etc/cron.daily/`, `/etc/cron.hourly/` ve kullanıcının `crontab -l` listesinde yedekleme betiklerini arama.
  4. **Yedekleme Çıktı Formatı:**
     - Yedek Adı, Mekanizma (Systemd Timer / Cron / Restic), Sıklık, Son Çalışma, Sağlık Durumu (BAŞARILI ✓ / HATA ✗).

---

### Görev 6: Sistem Metrikleri & Donanım Motoru (`SystemCollector`)
* **Amaç:** Sunucunun CPU, RAM, Disk ve Ağ bant genişliği tüketimini canlı hesaplamak.
* **Maddeler:**
  1. `psutil.cpu_percent(percpu=True)` ile her bir işlemci çekirdeğinin anlık yükü (`collectors/system_collector.py`).
  2. Sistem yük ortalaması (Load Average: 1m, 5m, 15m).
  3. RAM (Used, Free, Buffers/Cache, Available) ve Swap bellek doluluğu.
  4. Disk bölümleri (`df -h` karşılığı): Root (`/`), data diskleri (`/var`, `/data`), doluluk oranları ve boş GB bilgisi.
  5. Ağ Arayüzleri (`eth0`, `ens3`): Son iki ölçüm arasındaki zaman farkı ile anlık İndirme (RX) ve Yükleme (TX) MB/s hesaplaması.

---

### Görev 7: Docker & Konteyner Durum Takibi (`DockerCollector`)
* **Amaç:** Docker ile koşan web siteleri, veritabanları ve servisleri portlarıyla listelemek.
* **Maddeler:**
  1. Docker kurulu mu kontrolü (`/var/run/docker.sock` varlığı veya `docker ps` komutu) (`collectors/docker_collector.py`).
  2. Docker yoksa arayüzü bozmadan paneli zarifçe gizleme / "Docker kurulu değil" notu düşme.
  3. Konteyner adı, kullanılan imaj, sağlık durumu (Healthy / Up / Restarting), dışarıya eşlenen portlar (`0.0.0.0:8080->80/tcp`).
  4. Docker ile Nginx reverse proxy arasındaki ilişkileri bağlama.

---

### Görev 8: btop Tarzı Modern Textual Arayüzü (`ui/`)
* **Amaç:** btop'un o efsanevi, temiz ve yüksek yoğunluklu dashboard deneyimini terminale getirmek.
* **Maddeler:**
  1. **Tema & TCSS (`ui/styles.tcss`):**
     - Catppuccin Mocha / Tokyo Night paleti: Derin lacivert/siyah arka plan, neon mavi başlıklar, zümrüt yeşili durumlar, pastel kırmızı uyarılar.
     - Responsive grid yerleşimi: Terminal penceresi büyütüldüğünde veya küçültüldüğünde otomatik hizalanan paneller.
  2. **Bileşen 1: HeaderBar (`ui/widgets/header_bar.py`):**
     - Sunucu Hostname, İşletim Sistemi (`Ubuntu 24.04`), Çekirdek Sürümü, Uptime, Anlık Saat, CPU Mimarisi.
  3. **Bileşen 2: VitalsPanel (`ui/widgets/vitals_panel.py`):**
     - CPU Yüzde Çubuğu + Unicode Braille (`⢕⢍⢌⢂⠢⡪⡪⡑`) canlı mini grafik (Sparkline).
     - RAM & Swap barları ve GB detayları.
     - Canlı Ağ RX / TX hız göstergeleri.
  4. **Bileşen 3: Port & Reverse Proxy Tablosu (`ui/widgets/port_table.py` - Ana Sahne):**
     - Sütunlar: `DOMAIN` | `PORT` | `SSL` | `PROXY TARGET` | `UYGULAMA/PID` | `GÜVENLİK DURUMU`
     - Renkli durum ikonları: `[GÜVENLİ ✓]` (Yeşil), `[STANDART WEB]` (Mavi), `[TEHLİKE: DIŞARI AÇIK !]` (Kırmızı).
  5. **Bileşen 4: Yedekleme & Disk Paneli (`ui/widgets/backup_panel.py`):**
     - Disklerin doluluk çubukları.
     - Yedekleme zamanlayıcıları ve son başarı durumları.
  6. **Bileşen 5: Docker & Sistem Servisleri (`ui/widgets/service_panel.py`):**
     - Nginx, PostgreSQL, Redis gibi kritik servislerin systemd aktiflik ikonları (`● active (running)`).
  7. **Klavye Kısayolları (Keybindings):**
     - `1` veya `d`: Genel Dashboard görünümü
     - `2` veya `p`: Port & Proxy odak modu (Tam ekran tablo)
     - `3` veya `b`: Yedekleme & Disk odak modu
     - `r`: Manuel anında yenileme
     - `q` veya `ESC`: Güvenli çıkış

---

### Görev 9: Simülasyon / Demo Modu (`collectors/mock_collector.py`)
* **Amaç:** Windows ortamında geliştirme yaparken veya sunucuya geçmeden önce, gerçekçi çoklu web sitesi ve yedekleme verileriyle arayüzü birebir görebilmek.
* **Maddeler:**
  1. `MockCollector`: 4 adet sanal web sitesi (`firma.com`, `api.firma.com`, `panel.firma.com`, `test.firma.com`), simüle edilmiş Node/FastAPI/Wordpress backendleri, sahte diskler ve sahte bir `db-backup.timer` üreten jeneratör.
  2. Geliştirici hiçbir Linux komutuna bağımlı kalmadan Windows terminalinde (PowerShell / Windows Terminal) tüm panelleri test edebilir.

---

### Görev 10: Çalıştırılabilir CLI & Paketleme (`cli.py` & `main.py`)
* **Amaç:** Aracı sunucuda ve yerelde tek komutla çalışabilir hale getirmek.
* **Maddeler:**
  1. `cli.py` komut satırı arayüzü:
     - `--demo`: Simülasyon modunda başlat.
     - `--interval <sn>`: Yenileme sıklığı (varsayılan 1.0 saniye).
     - `--no-docker`: Docker taramasını atla.
  2. `main.py`: Varsayılan hızlı başlatıcı (`python main.py`).
  3. `pyproject.toml` içerisine `[project.scripts]` tanımı eklenerek terminalde doğrudan `server-tui` yazarak çalıştırılabilmesi.

---

## 🔒 Güvenlik ve Üretim (Production) Garantileri

1. **Hiçbir Dosyayı Değiştirmez:** Sadece `read()` ve salt-okunur soket sorguları yapar.
2. **Root Şartı Yoktur:** Normal kullanıcı yetkileriyle de çalışır. Process isimleri için `sudo` verilirse daha detaylı PID gösterir, verilmezse hata vermeden anonim servis olarak listeler.
3. **Bellek Sızıntısı Koruması:** Geçmiş metrik dizileri sabit boyutlu kuyruklarda (`collections.deque(maxlen=60)`) tutulur, bellek tüketimi asla şişmez.

---

## 🚀 Uygulama Durumu

Hiyerarşi tamamen proje ana dizini (`c:\Gelistirme\terminaltui\`) merkezli olarak plana işlendi. Tüm modüller, modeller ve bileşenler doğrudan kök dizin altındaki temiz klasörlerde yer alacak.
