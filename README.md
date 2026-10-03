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
[![Tests](https://img.shields.io/badge/tests-42%2F42_passing-brightgreen.svg)](tests/)
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

### 1. Gereksinimler & Kurulum

Python 3.10 veya üzeri sürüm gereklidir.

```bash
# Depoyu klonlayın
git clone https://github.com/AloGroupTR/pulseops.git
cd pulseops

# Sanal ortamı hazırlayın ve bağımlılıkları kurun
python -m venv .venv
source .venv/bin/activate  # Windows için: .venv\Scripts\activate
pip install -e .
```

### 2. Çalıştırma Modları

PulseOps üç esnek çalışma modunu destekler:

```bash
# 1. Simülasyon / Demo Modu (Gerçekçi web siteleri, veritabanları ve şişmiş cache senaryoları):
pulseops --demo

# 2. Yerel Canlı Mod (Kendi Linux veya Windows 11 makinenizi canlı gözlemleyin):
pulseops --live

# 3. Uzak SSH ile Ajansız Sunucu İzleme:
pulseops --host 192.168.1.50 --user ubuntu --key ~/.ssh/id_rsa

# Parola ile bağlanmak için:
pulseops --host 192.168.1.50 --user root --password "GizliSifre" --port 2222
```

> **İpucu:** `pulseops` veya `pulsetui` komutlarının her ikisi de kullanılabilir.

---

## 🖥️ 10 Sekmeli Modüler Gözlem Paneli

PulseOps klavyedeki `1` - `0` tuşlarıyla geçiş yapılabilen 10 derinlemesine inceleme paneli sunar:

| Sekme No | Sekme Adı | Açıklama & Sağlanan Telemetri |
| :---: | :--- | :--- |
| **`1`** | **⚡ Dashboard** | Donanım tüketimi (CPU, RAM, Swap), disk bölümleri, disk I/O hızları, UFW durumu ve sistem sağlık skoru. |
| **`2`** | **🔥 Süreçler (Top Processes)** | CPU ve RAM tüketimine göre canlı sıralanan süreçler, kullanıcı ve PID dökümleri. |
| **`3`** | **🔍 Portlar (Port Exposure)** | Dinlenen portlar, bind IP adresleri (`127.0.0.1` vs `0.0.0.0`), güvenlik seviyesi ve dinamik RPC filtreleme (`p`). |
| **`4`** | **⚙️ Servisler** | Systemd birimleri ve Windows servisleri. Aktif, pasif ve çökmüş (`failed`) servislerin anlık takibi. |
| **`5`** | **🗄️ Veritabanı** | Otomatik keşfedilen PostgreSQL, MySQL, Redis, MongoDB örnekleri ve dış ağ maruziyet durumları. |
| **`6`** | **🌐 Siteler (Web & Proxy)** | Nginx & Docker yönlendirme haritası. Domainler, dinlenen portlar, SSL gün sayaçları, **502 Bad Gateway kök neden teşhisi** ve tarayıcıda tek tuşla açma (`Enter`). |
| **`7`** | **💾 Yedekler** | Systemd timer'ları, crontab yedekleme görevleri (pg_dump, restic, rsync) ve saklama risk analizleri. |
| **`8`** | **📋 Loglar** | Canlı sistem ve web log akışı, hata filtreleme ve gerçek zamanlı takip. |
| **`9`** | **🛡️ Güvenlik** | SSH güvenlik sertleştirmesi (`PermitRootLogin`), güvenlik duvarı aktif kuralları ve riskli açık port analizi. |
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

PulseOps %100 test kapsamını hedefler. Tüm toplayıcılar, ayrıştırıcılar, veri modelleri, UI yaşam döngüsü ve raporlama motoru pytest ile doğrulanır:

```bash
# Test paketini çalıştırın
pytest -v
```

```text
tests/test_audit_exporter.py::test_calculate_audit_score PASSED          [  2%]
tests/test_audit_exporter.py::test_calculate_audit_score_clean PASSED    [  5%]
tests/test_audit_exporter.py::test_generate_audit_markdown_comprehensive PASSED [  8%]
tests/test_audit_exporter.py::test_export_audit_report_to_disk PASSED    [ 11%]
...
============================= 36 passed in 9.13s ==============================
```

---

## 📄 Lisans

Bu proje [MIT Lisansı](LICENSE) kapsamında sunulmaktadır.
