# PulseOps Yol Haritası

> Hedef platform: **Linux (amd64)**. Asıl kullanım senaryosu, sunucuya SSH ile girip
> `pulseops` yazarak TUI'yi doğrudan sunucu üzerinde çalıştırmaktır. Uzaktan SSH ile
> bağlanma modu (`pulseops user@host`) ikincil olarak desteklenmeye devam eder.
>
> Kapsam dışı (şimdilik): Ollama / yerel AI entegrasyonu, Windows, macOS, ARM.

Durum: ✅ tamamlandı · 🚧 devam ediyor · ⬜ planlandı

---

## Faz 0 — Stabilizasyon ✅

Amaç: Uygulama desteklenen tüm Python sürümlerinde açılsın, her değişiklik CI'da doğrulansın.

- ✅ `ui/modals/config_viewer_modal.py` içindeki eksik `Optional` import'u
  (Python < 3.14'te uygulama açılışta `NameError` ile çöküyordu)
- ✅ Kullanılmayan import'ların temizlenmesi, `ruff` yapılandırması
- ✅ Push/PR'da çalışan CI: ruff + pytest, Python 3.10 / 3.11 / 3.12 / 3.13 matrisi
- ✅ `requirements.txt` ↔ `pyproject.toml` bağımlılık uyumu (`paramiko` eksikti, `textual` üst sınır)
- ✅ README ve ARCHITECTURE düzeltmeleri (repo adresi, test rozeti, var olmayan dosyalar,
  `--password` örneği)

## Faz 1 — Linux Sunucu Deneyimi ✅

Amaç: Herhangi bir Linux sunucusunda tek komutla kurulup `pulseops` ile sorunsuz açılsın.

### Kurulum & dağıtım
- ✅ Linux release binary'si AlmaLinux 8 (glibc 2.28) container'ında derleniyor; yayından önce
  binary üzerinde smoke test; tüm release dosyaları için `.sha256`
  (önceden `ubuntu-latest` üzerinde derleniyordu → Ubuntu 22.04 / Debian 12'de çalışmıyordu)
- ✅ `install.sh`: önce binary (SHA-256 doğrulamalı), olmazsa Python/venv; root → `/usr/local/bin`
- ✅ `pulseops version`, `pulseops update` (binary: checksum doğrulamalı atomik değişim), `pulseops uninstall`

### Terminal deneyimi (SSH oturumu içinde)
- ✅ Küçük terminal (80x24) uyumu doğrulandı
- ✅ `--no-color` / `NO_COLOR`, `--ascii` (genişlik korumalı dönüşüm; UTF-8 olmayan terminalde otomatik)
- ✅ `--no-mouse`, ayarlanabilir `--interval`
- ✅ TUI'nin kaynak tüketimi ölçüldü (4 çekirdek, 140x40 terminal):

  | Mod | CPU (tek çekirdek) | RSS | Terminal çıktısı |
  | :--- | ---: | ---: | ---: |
  | `--demo` (render maliyeti) | %1.0 | 58 MB | 3.1 KB/s |
  | `--live`, 1.5 sn | %18.1 | 58 MB | 3.0 KB/s |
  | `--live`, 5 sn | %5.8 | 58 MB | 1.0 KB/s |

  Render ucuz; maliyet her turda yapılan toplama (~226 ms: `systemctl` 125 ms, `docker system df` 39 ms,
  `docker ps` 19 ms, loglar 19 ms). %2 hedefi Faz 2'deki hızlı/yavaş polling katmanlarıyla karşılanacak.

### Root olmayan kullanıcı
- ✅ Yerel ve SSH modunda yetki tespiti (root, parolasız sudo, docker erişimi)
- ✅ Header'da `kullanıcı (kısıtlı)` rozeti + eksik verileri ve çözümü anlatan tek seferlik bildirim;
  `pulseops status` çıktısında da gösterilir

### Etkileşimsiz komutlar
- ✅ `pulseops status [--json]`
- ✅ `pulseops report --format md|json [-o DİZİN | -o -]`
- ✅ `pulseops check [--warn N --crit N]` — Nagios uyumlu çıkış kodu ve perfdata

## Faz 2 — Mimari

Amaç: Arayüz hiç donmasın, yerel ve SSH modu aynı kod yolunu kullansın.

- ⬜ Polling'in Textual thread worker'a taşınması (şu an her turda UI ~0.2 sn donuyor)
- 🚧 Tek `Telemetry` Pydantic modeli (`models/telemetry.py`, CLI komutları kullanıyor); TUI'nin de buna
  geçmesi, `poll()` tuple'ı ve `hasattr` kontrollerinin kaldırılması
- ⬜ Tek veri toplama yolu: yerel modda da aynı probe betiği + aynı parser
- ⬜ Hızlı / yavaş polling katmanları (CPU/RAM/port ≈ 2 sn; servis/docker/depolama/yedek ≈ 30–60 sn)
  — hedef: canlı modda boşta < %2 CPU (Faz 1 ölçümü: %18)
- ⬜ Hataların yutulmaması: bağlantı/toplama hatası banner'ı + `~/.cache/pulseops/pulseops.log`
- ⬜ Yapılandırma dosyası: `/etc/pulseops/config.toml`, `~/.config/pulseops/config.toml`

## Faz 3 — Güvenlik

Amaç: Bir güvenlik/gözlem aracının kendisi güvenli olsun; güvenlik paneli SOC için değerli veri sunsun.

- ⬜ SSH host key doğrulaması (`known_hosts`), bilinmeyen anahtarda fingerprint onayı
  (`AutoAddPolicy` kaldırılacak)
- ⬜ `~/.ssh/config`, ssh-agent ve ProxyJump desteği
- ⬜ Şifrenin CLI argümanından kaldırılması (`PULSEOPS_SSH_PASSWORD` veya prompt)
- ⬜ fail2ban durumu, son başarısız SSH girişleri, sudoers / yetkili kullanıcı denetimi
- ⬜ Salt-okunur garantisinin dokümantasyonu (`sudo -n` kullanımı dahil)

## Faz 5 — Ürünleşme

- ⬜ Çoklu sunucu: `~/.config/pulseops/hosts.toml`, TUI içinde sunucular arası geçiş
- ⬜ Hafif geçmiş kaydı (SQLite) ve trend grafikleri
- ⬜ `.deb` / `.rpm` paketleri
