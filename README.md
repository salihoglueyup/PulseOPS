<div align="center">

```
  ██████╗ ██╗   ██╗██╗     ███████╗███████╗ ██████╗ ██████╗ ███████╗
  ██╔══██╗██║   ██║██║     ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██████╔╝██║   ██║██║     ███████╗█████╗  ██║   ██║██████╔╝███████╗
  ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  ██║   ██║██╔═══╝ ╚════██║
  ██║     ╚██████╔╝███████╗███████║███████╗╚██████╔╝██║     ███████║
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚══════╝
```

### ⚡ PulseOps (PulseTUI)
**Agentless Real-Time Server, Web & Infrastructure Observability TUI**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Textual TUI](https://img.shields.io/badge/TUI-Textual_0.70%2B-indigo.svg)](https://textual.textualize.io/)
[![Design](https://img.shields.io/badge/theme-Datadog_%26_JetBrains_Dark-purple.svg)](docs/ARCHITECTURE.md)
[![CI](https://github.com/salihoglueyup/PulseOPS/actions/workflows/ci.yml/badge.svg)](https://github.com/salihoglueyup/PulseOPS/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](#-hızlı-başlangıç)
[![Security](https://img.shields.io/badge/audit-100%25_Read--Only-success.svg)](docs/ARCHITECTURE.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

*Sunucunuza hiçbir ajan (agent) kurmadan; web sitelerinizi, reverse proxy rotalarınızı, 502 hatalarını, dinlenen portları, veritabanlarını, SSL sürelerini, BuildKit önbellek birikmelerini ve sistem sağlığını terminalinizde canlı izleyin.*

[Özellikler](#-öne-çıkan-özellikler) •
[Hızlı Başlangıç](#-hızlı-başlangıç) •
[10 Sekmeli Panel Turu](#-10-sekmeli-modüler-gözlem-paneli) •
[Klavye Kısayolları](#-klavye-kısayolları) •
[Yönetici Denetim Raporu](#-yönetici-denetim-raporu-executive-audit) •
[Mimari](#-mimari-ve-tasarım)

---

</div>

## 💡 Neden PulseOps?

Geleneksel gözlem araçları (Datadog, Prometheus, Zabbix vb.) sunucuya kalıcı arka plan ajanları kurmayı zorunlu kılar. Bu durum hem sunucuya kaynak yükü bindirir hem de güvenlik denetimlerinde onay süreçlerini uzatır. 

**PulseOps (PulseTUI)** bu yaklaşımı kökten değiştirir:
* **%100 Ajansız (Agentless):** Hedef sunucuya hiçbir daemon, binary veya servis yüklenmez. Standart SSH bağlantısı üzerinden Linux komutlarıyla (`ss`, `ps`, `df`, `docker`, `systemctl`) telemetri toplar.
* **Sıfır Risk & Salt-Okunur (Read-Only):** Sunucudaki hiçbir konfigürasyonu değiştirmez, servis durdurmaz veya yeniden başlatmaz. Sıfır yan etki garantilidir.
* **Akıllı Web & Nginx Haritalama:** Hangi domain'in hangi porta gittiğini ve arkasında hangi Node.js/Python/Go servisinin çalıştığını otomatik eşleştirir.
* **Görünmeyen Disk Canavarlarını Yakalama:** Docker BuildKit önbelleklerinin (`/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs`) ve sahipsiz Docker katmanlarının diski doldurmasını saniyeler içinde tespit eder.
* **Gelişmiş Terminal Estetiği:** Clean Minimalist Silver & Charcoal paleti, interaktif modallar ve zengin Rich widget'ları.

---

## 🚀 Hızlı Başlangıç

### 1. Kurulum (Linux)

Sunucuya SSH ile bağlanıp tek komutla kurun:

```bash
curl -fsSL https://raw.githubusercontent.com/salihoglueyup/PulseOPS/main/install.sh | bash
```

Installer önce hazır binary'yi indirir (Python gerekmez; x86_64, glibc 2.28+ yani Ubuntu 20.04+, Debian 10+, RHEL 8+) ve SHA-256 ile doğrular. Binary yoksa veya çalışmazsa Python 3.10+ ile izole bir ortama kaynak koddan kurar. `root` olarak çalıştırılırsa `/usr/local/bin`, değilse `~/.local/bin` altına kurar.

```bash
pulseops update       # en son sürüme güncelle
pulseops uninstall    # kaldır
pulseops version      # sürüm ve kurulum türü
```

Geliştirme için kaynak koddan kurulum:

```bash
git clone https://github.com/salihoglueyup/PulseOPS.git
cd PulseOPS
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Çalıştırma

```bash
# Bu sunucuyu canlı izle (varsayılan mod):
pulseops

# Tam görünüm (tüm süreçlerin port sahipleri, güvenlik duvarı kuralları, docker):
sudo pulseops

# Simülasyon / Demo Modu (gerçekçi örnek verilerle):
pulseops --demo

# Başka bir sunucuyu kendi makinenizden SSH ile ajansız izleme:
pulseops ubuntu@192.168.1.50 --key ~/.ssh/id_ed25519
pulseops web01                              # ~/.ssh/config'teki Host adı (HostName, User, Port, IdentityFile, ProxyJump)
pulseops deploy@10.0.0.5 -J bastion         # atlama sunucusu üzerinden (zincir: -J a,b)
```

**SSH güvenliği:** Kimlik doğrulama OpenSSH ile aynı sırayı izler: önce `--key`, `~/.ssh/config`, ssh-agent ve `~/.ssh/id_*`. Anahtar parolalıysa anahtar parolası, anahtarlar reddedilirse şifre güvenli şekilde sorulur. Komut satırında şifre verilemez (`ps` ve shell geçmişinde görünürdü); otomasyon için `PULSEOPS_SSH_PASSWORD`. Sunucu anahtarları `~/.ssh/known_hosts` ile doğrulanır: bilinmeyen sunucuda parmak izi gösterilip onay istenir, **değişmiş** bir anahtarla bağlantı her zaman reddedilir (MITM koruması). Etkileşimsiz komutlar (`check`, cron) bilinmeyen anahtarı asla kabul etmez; davranış `[ssh] host_key_checking = "ask" | "accept-new" | "yes"` ile ayarlanır.

> **Root olmayan kullanıcılar:** PulseOps yetkinizi otomatik algılar. Erişemediği veriler varsa header'da `kullanıcı (kısıtlı)` rozeti ve ne eksik olduğunu anlatan bir bildirim gösterir.

### 3. SSH Terminali İçin Seçenekler

| Seçenek | Ne işe yarar |
| :--- | :--- |
| `--interval 5` | Hızlı metriklerin (CPU, RAM, port, süreç) yenileme aralığı, varsayılan 2 sn. Yavaş SSH bağlantılarında artırın. |
| `--slow-interval 60` | Ağır kontrollerin (servis, docker, nginx, yedek, güvenlik duvarı) aralığı, varsayılan 30 sn. `r` tuşu hepsini anında yeniler. |
| `--no-color` | Renksiz (gri tonlamalı) çıktı. `NO_COLOR` ortam değişkeni de desteklenir. |
| `--ascii` | Emoji / Unicode desteklemeyen terminaller için yalnızca ASCII. UTF-8 olmayan terminallerde otomatik açılır. |
| `--no-mouse` | Fare desteğini kapatır; tmux/screen içinde metin seçimi için. |

### 4. Etkileşimsiz Komutlar (cron, script, monitoring)

```bash
pulseops status                 # TUI açmadan tek ekranlık özet
pulseops status --json          # makine tarafından okunabilir tam telemetri
pulseops report                 # Markdown denetim raporu -> audit-reports/
pulseops report -f json -o -    # JSON raporu stdout'a
pulseops check                  # sağlık skoruna göre çıkış kodu
pulseops probe                  # sunucuda çalışacak salt-okunur betiği göster (denetim için)
pulseops history [--since 7d]   # kayıtlı trendler ve güvenlik değişiklikleri (bağlantı kurmaz)
```

`pulseops check` Nagios/Icinga eklenti formatında tek satır ve performans verisi yazar. Çıkış kodları: `0` OK, `1` WARNING (skor < `--warn`, varsayılan 80), `2` CRITICAL (skor < `--crit`, varsayılan 50), `3` UNKNOWN (veri toplanamadı).

```bash
# Örnek: skor düşerse her saat e-posta at
0 * * * * pulseops check --warn 70 || pulseops report -f md -o - | mail -s "PulseOps uyarısı" ops@ornek.com
```

> **İpucu:** Tüm komutlar uzak sunucu için de çalışır: `pulseops check root@sunucu --key ~/.ssh/id_ed25519`


### 5. Değişiklik Tespiti & Geçmiş

PulseOps her yavaş turda sunucunun güvenlik durumunu bir öncekiyle karşılaştırır ve değişiklikleri
`~/.local/share/pulseops/history.db` dosyasına (0600) kaydeder:

- yeni **dışa açık port** (hangi süreç), yeni **UID 0** hesap, **sudo/wheel**'e eklenen kullanıcı,
  `authorized_keys`'e eklenen **SSH anahtarı**, yeni `NOPASSWD` kuralı, **kapatılan güvenlik duvarı**,
  zayıflayan `sshd` ayarı, duran fail2ban, çöken servis, yeni konteyner

TUI'de yüksek önemli değişiklikler anında bildirilir; `h` tuşu 24 saatlik CPU/RAM/disk/skor trendlerini ve
7 günlük değişiklik akışını gösterir. Okunamayan veriler (ör. root olmadan sudoers) karşılaştırılmaz, böylece
yetki farkı sahte alarm üretmez.

Ajansız olduğu için geçmiş PulseOps çalıştıkça birikir. Sürekli gözlem için tek bir cron satırı yeterli
(arka planda servis kurulmaz):

```bash
# her 5 dakikada bir: metrik kaydı + değişiklik tespiti; yeni bir değişiklikte çıkış kodu WARNING olur
*/5 * * * * /usr/local/bin/pulseops check >> /var/log/pulseops-check.log 2>&1
```

`pulseops check`, kim tespit etmiş olursa olsun (TUI, `status`, önceki `check`) **son `check`'ten beri**
oluşan değişiklikleri bir kez raporlar.

### 6. Bildirimler (Telegram, Slack, Discord, e-posta, webhook)

Cron'daki `pulseops check` yalnızca **durum değiştiğinde** (OK → WARNING, WARNING → CRITICAL, düzelince → OK)
ve **yeni güvenlik değişikliğinde** bildirim gönderir; aynı uyarı her 5 dakikada tekrar edilmez.

```toml
# ~/.config/pulseops/config.toml  (chmod 600)
[notify]
min_severity = "MEDIUM"           # HIGH | MEDIUM | INFO

[[notify.channels]]
type = "telegram"
bot_token = "env:PULSEOPS_TELEGRAM_TOKEN"   # sırlar ortam değişkeninden okunabilir
chat_id = "123456789"

[[notify.channels]]
type = "slack"                    # "discord" ve "webhook" (JSON POST) de aynı biçimde: url = "..."
url = "env:PULSEOPS_SLACK_WEBHOOK"
```

```bash
pulseops notify --test            # her kanala deneme mesajı
```

Sunucudan gelen metinler (süreç/kullanıcı adları) her kanal için kaçışlanır: Slack'te `<url|metin>`, Discord'da
`[metin](url)` gibi sahte linklere veya `@everyone` gibi bahsetmelere dönüşemez.

### 7. Çoklu Sunucu (Filo)

```toml
[fleet]
hosts = ["local", "web01", "deploy@10.0.0.5:2222"]   # ~/.ssh/config Host adları kullanılabilir
groups = { web = ["web01", "web02"], db = ["db01"] }
```

```bash
pulseops fleet                 # tüm sunucular tek ekranda: durum, skor, uyarı, CPU/RAM/disk, 24s değişiklik
pulseops fleet --group web     # Enter: sunucunun tam TUI'si, q: filoya dönüş
pulseops check --all           # cron/monitoring: sunucu başına bir satır + özet, en kötü durum çıkış kodu
```

Sunucular paralel ve etkileşimsiz sorgulanır (SSH anahtarı/agent gerekir; bilinmeyen host key kabul edilmez).
Erişilemeyen sunucu `UNKNOWN` olur; erişilemez hale gelmesi ve düzelmesi de bildirim üretir. Aynı makine farklı
yollardan (ör. `local` ve SSH) izlense bile geçmiş ve değişiklik tespiti makine kimliğiyle (`/etc/machine-id`)
birleştirilir; değişiklikler bir kez raporlanır.

### 8. Yapılandırma

```bash
pulseops config           # geçerli ayarlar ve okunan dosyalar
pulseops config --init    # ~/.config/pulseops/config.toml şablonunu oluşturur
```

Ayarlar önce `/etc/pulseops/config.toml` (sunucu geneli), sonra `~/.config/pulseops/config.toml` dosyasından okunur; komut satırı bayrakları ikisini de ezer. Yazım hatalı bir anahtar sessizce yok sayılmaz, hata olarak raporlanır.

```toml
[general]
interval = 2          # hızlı metrikler (sn)
slow_interval = 30    # servis, docker, nginx, yedek (sn)
use_sudo = true       # root değilken yavaş kontrollerde parolasız `sudo -n`

[check]               # `pulseops check` eşikleri
warn = 80
crit = 50

[history]
enabled = true        # trend + değişiklik tespiti
drift_exit = "warning"  # check: yüksek önemli yeni değişiklikte en az bu çıkış kodu (none | warning | critical)

[alerts]              # uyarı eşikleri
disk_percent = 80
memory_percent = 85
ssl_days = 7
```

Sorun giderme için log dosyası: `~/.cache/pulseops/pulseops.log`.

Güvenlik ekipleri için ayrıntılı model (çalıştırılan komutlar, sudo, SSH, yazılan dosyalar): [docs/SECURITY.md](docs/SECURITY.md).

### 9. Nasıl Çalışır?

Yerel modda da SSH modunda da hedef makinede aynı salt-okunur shell betiği (`sh -s`) çalışır ve çıktısı aynı kodla ayrıştırılır. Ucuz ve sık değişen metrikler (CPU, RAM, ağ, portlar, süreçler) her 2 saniyede, `systemctl`, `docker`, `nginx -T` gibi ağır kontroller 30 saniyede bir toplanır; veri toplama ayrı bir thread'de yürür, arayüz hiç beklemez. 4 çekirdekli bir sunucuda canlı modun kendi tükettiği CPU tek çekirdeğin yaklaşık %2'si kadardır (`--interval 5` ile ~%1.3).

`sudo` root olarak hiç, hızlı kontrollerde hiçbir zaman kullanılmaz; root olmayan kullanıcıda yalnızca parolasız sudo varsa ve yavaş kontrollerde `sudo -n` ile denenir (her sudo çağrısı sunucunun auth log'una yazılır, PulseOps bu logları doldurmaz). Okunamayan bir veri, ör. yetkisiz kullanıcıda güvenlik duvarı durumu, "aktif" sayılmaz: **bilinmiyor** olarak gösterilir.

---

## 🖥️ 10 Sekmeli Modüler Gözlem Paneli

PulseOps klavyedeki `1` - `0` tuşlarıyla geçiş yapılabilen 10 derinlemesine inceleme paneli sunar:

| Sekme No | Sekme Adı | Açıklama & Sağlanan Telemetri |
| :---: | :--- | :--- |
| **`1`** | **⚡ Dashboard** | Donanım tüketimi (CPU, RAM, Swap), disk bölümleri, disk I/O hızları, UFW durumu ve sistem sağlık skoru. |
| **`2`** | **🔥 Süreçler (Top Processes)** | CPU ve RAM tüketimine göre canlı sıralanan süreçler, kullanıcı ve PID dökümleri. |
| **`3`** | **🔍 Portlar (Port Exposure)** | Dinlenen portlar, bind IP adresleri (`127.0.0.1` vs `0.0.0.0`), güvenlik seviyesi ve dinamik RPC filtreleme (`p`). |
| **`4`** | **⚙️ Servisler** | Systemd birimleri. Aktif, pasif ve çökmüş (`failed`) servislerin anlık takibi. |
| **`5`** | **🗄️ Veritabanı** | Otomatik keşfedilen PostgreSQL, MySQL, Redis, MongoDB örnekleri ve dış ağ maruziyet durumları. |
| **`6`** | **🌐 Siteler (Web & Proxy)** | Nginx & Docker yönlendirme haritası. Domainler, dinlenen portlar, SSL gün sayaçları, **502 Bad Gateway kök neden teşhisi** ve tarayıcıda tek tuşla açma (`Enter`). |
| **`7`** | **💾 Yedekler** | Systemd timer'ları, crontab yedekleme görevleri (pg_dump, restic, rsync) ve saklama risk analizleri. |
| **`8`** | **📋 Loglar** | Canlı sistem ve web log akışı, hata filtreleme ve gerçek zamanlı takip. |
| **`9`** | **🛡️ Güvenlik** | SSH sertleştirmesi (`sshd -T`), güvenlik duvarı (UFW/firewalld/iptables/nftables), riskli açık portlar ve **SOC görünümü**: fail2ban durumu, son 24 saatteki başarısız/başarılı SSH girişleri ve en çok deneyen IP'ler, UID 0 hesaplar, sudo/wheel üyeleri, `NOPASSWD` kuralları, `authorized_keys` sayıları. |
| **`0`** | **📦 Depolama** | Disk bölümleri, Docker BuildKit önbellek analizi, containerd katmanları ve geri kazanılabilecek (`reclaimable`) alan uyarısı. |

---

## ⌨️ Klavye Kısayolları

| Tuş | Kısayol İşlevi |
| :---: | :--- |
| **`1` - `0`** | Doğrudan ilgili sekmeye geçiş yapar (`1`: Dashboard, ..., `6`: Siteler, ..., `0`: Depolama). |
| **`w`** | **Site Kategori Filtresi:** Siteler sekmesinde `TÜMÜ`, `WEB`, `HATALI (502)`, `SSL`, `TCP` modları arasında geçiş yapar. |
| **`Enter` / `o`** | **Tarayıcıda Aç:** Seçili web sitesini varsayılan tarayıcında (`Chrome`, `Edge`, vb.) anında açar. |
| **`p`** | **Port Filtresi:** Dinlenen portlarda sistem RPC portlarını gizler / gösterir. |
| **`f`** | **Akıllı Boş Port Bulucu:** Yeni bir backend/Docker konteyneri açmadan önce boş port aralıklarını listeler. |
| **`c`** | **Konfigürasyon İnceleyici:** Nginx, Docker veya SSH ayar dosyalarını sözdizimi renklendirmesiyle açar. |
| **`a`** | **Akıllı Risk & Uyarı Paneli:** Sunucudaki açık riskleri (açık portlar, süresi biten SSL, şişmiş cache) listeler. |
| **`h`** | **Geçmiş & Değişiklikler:** 24 saatlik trendler ve 7 günlük güvenlik değişikliği akışı. |
| **`e`** | **Yönetici Denetim Raporu Al:** Tek tuşla tam kapsamlı Markdown röntgen raporu üretir (`audit-reports/`). |
| **`/`** | **Canlı Filtreleme & Arama:** Web siteleri ve port tablolarında anında arama yapar. |
| **`t`** | **Tema Değiştir:** Kurumsal koyu temalar arasında geçiş yapar. |
| **`r`** | **Zorla Yenile:** Telemetri verilerini ve HTTP sağlık kontrollerini anında tekrar toplar. |
| **`Ctrl+C` / `q`** | **Hızlı Çıkış:** Uygulamayı anında ve güvenle kapatır. |

---

## 📊 Yönetici Denetim Raporu (Executive Audit)

Klavyeden `e` tuşuna basıldığında PulseOps o anki tüm sistem durumunu analiz ederek profesyonel bir **Yönetici Altyapı Denetim Raporu** üretir ve `audit-reports/pulseops-audit-<host>-<timestamp>.md` konumuna yazar.

### Raporda Neler Var?
1. **Altyapı Sağlık ve Güvenlik Skoru (0 - 100):**
   * *A+ (Mükemmel), A (Güvenli & Stabil), B (İyi / Küçük Riskler), C (Müdahale Gerekir), CRITICAL (Acil Aksiyon Şart)*
2. **10 Ayrı Bölümde Donanım, Ağ, Port, Servis, Güvenlik ve Depolama Dökümü**
3. **Yönetici Eylem Planı (Action Checklist):**
   * Riski ortadan kaldırmak için gereken doğrudan terminal komutları:
   ```markdown
   - [ ] Güvenlik Riski: Port 27017 (mongod) 0.0.0.0 üzerinden dışa açık! UFW ile kapatın.
   - [ ] SSL Yenileme: api.sirket-ana.com sertifikasının bitmesine 4 gün kaldı! `certbot renew` çalıştırın.
   - [ ] Önbellek Temizliği: BuildKit önbelleği 28.5 GB seviyesinde! `docker builder prune -f --keep-storage 10GB` çalıştırın.
   ```

---

## 🏛️ Mimari ve Tasarım

Detaylı mimari şeması, veri modelleri (Pydantic v2), reactive UI yaşam döngüsü ve güvenlik modeli için [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) dosyasını inceleyin.

---

## 🧪 Testler ve Kalite Güvencesi

Tüm toplayıcılar, ayrıştırıcılar, veri modelleri, UI yaşam döngüsü ve raporlama motoru pytest ile doğrulanır. Her push ve PR'da CI; `ruff` ve Python 3.10–3.13 üzerinde test paketini çalıştırır.

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

---

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) kapsamında sunulmaktadır.
