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

## Faz 2 — Mimari ✅

Amaç: Arayüz hiç donmasın, yerel ve SSH modu aynı kod yolunu kullansın.

- ✅ Polling Textual thread worker'da; turlar üst üste binmez, UI hiç beklemez
- ✅ Tek `Telemetry` modeli ve tek giriş noktası `collector.collect(include_slow, include_logs)`;
  `poll()` tuple'ı ve `hasattr` kontrolleri TUI'den kaldırıldı
- ✅ Tek veri toplama yolu: Linux'ta yerel mod da aynı shell probe'u (`sh -s`) çalıştırır
  (`ProbeCollector` + `LocalTransport` / `SSHTransport`)
- ✅ Hızlı / yavaş / log katmanları (2 sn / 30 sn / yalnızca Loglar sekmesinde); nadir değişen bölümler 10 dk
- ✅ Hatalar görünür: header'da bağlantı uyarısı, tek seferlik bildirim, toparlanma bildirimi,
  `~/.cache/pulseops/pulseops.log`
- ✅ Yapılandırma: `/etc/pulseops/config.toml`, `~/.config/pulseops/config.toml`, `pulseops config [--init]`

Ölçüm (4 çekirdek, 140x40 terminal, 30 sn, TUI + başlattığı tüm alt süreçler, tek çekirdek yüzdesi):

| Mod | Faz 1 | Faz 2 |
| :--- | ---: | ---: |
| `--demo` (yalnızca render) | %1.0 | %0.8 |
| Yerel canlı, 2 sn (Faz 1'de 1.5 sn) | %18.1 | %2.1 |
| Yerel canlı, 5 sn | %5.8 | %1.3 |
| SSH (istemci tarafı) | — | %1.5 |

Hızlı tur hedefte ~15 ms CPU (önce ~226 ms), SSH üzerinden ~55 ms duvar saati.

Bu fazda bulunan ve düzeltilen hatalar:
- **Güvenlik:** Log satırı, süreç adı, domain gibi sunucudan gelen metinler Rich markup olarak
  yorumlanıyordu: `GET /[/]` isteği TUI'yi çökertiyor, `[link=...]` terminale tıklanabilir link ekliyordu
- **Güvenlik:** Probe root olarak bile her 2 sn'de `sudo -n` çağırıyor, sunucunun auth log'unu dolduruyordu
- SSH modunda CPU yüzdesi load average'dan tahmin ediliyordu; çekirdek başı değerler sahte, disk I/O hep 0
- Güvenlik duvarı: SSH modunda modelde olmayan alanlar gönderildiği için durum hep "Aktif" görünüyordu;
  yerel modda okunamayan durum "aktif" sayılıyordu; Docker'ın iptables/nft kuralları "aktif" sanılıyordu
- `sshd_config`: varsayılanlar ve öncelik yanlıştı (OpenSSH'ta ilk değer geçerli, `Match` blokları
  koşullu); artık mümkünse `sshd -T` ile etkin yapılandırma okunuyor
- Yerel modda nginx access log her turda baştan sona okunuyordu (GB'larca log dosyasında ciddi yük)
- `ss`/`netstat` olmayan sistemlerde port listesi boş kalıyordu (`/proc/net` yedeği eklendi)

## Faz 3 — Güvenlik ✅

Amaç: Bir güvenlik/gözlem aracının kendisi güvenli olsun; güvenlik paneli SOC için değerli veri sunsun.

- ✅ SSH host key doğrulaması (`known_hosts` + `/etc/ssh/ssh_known_hosts`): değişen anahtar her zaman
  reddedilir, bilinmeyen anahtarda SHA256 parmak izi onayı; `check`/cron bilinmeyen anahtarı asla kabul
  etmez; `[ssh] host_key_checking = ask | accept-new | yes` (`AutoAddPolicy` kaldırıldı)
- ✅ `~/.ssh/config` (HostName, User, Port, IdentityFile, ProxyJump, ProxyCommand), ssh-agent,
  `-J` atlama sunucusu zincirleri
- ✅ OpenSSH benzeri kimlik doğrulama: önce anahtar/agent, gerektiğinde anahtar parolası veya şifre istemi;
  `--password` kaldırıldı, otomasyon için `PULSEOPS_SSH_PASSWORD`
- ✅ SOC görünümü: fail2ban (jail, engelli IP), SSH giriş aktivitesi (journald 24 saat / auth.log; başarısız,
  geçersiz kullanıcı, başarılı, şifreyle giriş, en çok deneyen IP/kullanıcı, son girişler), UID 0 hesaplar,
  sudo/wheel üyeleri, `NOPASSWD` kuralları, `authorized_keys` sayıları; uyarılar ve sağlık skoru
- ✅ Salt-okunur garantisi: `pulseops probe` ile çalıştırılan betik görülebilir; CI'da betik değiştiren
  komutlar için otomatik tarama (mutasyon testiyle doğrulandı); [docs/SECURITY.md](../SECURITY.md)
- ✅ CI'da gerçek sshd ile entegrasyon testleri (host key, ProxyJump, root olmayan + sudo'lu kullanıcı)

Bu fazda bulunan ve düzeltilen hatalar:
- **Güvenlik:** SSH bağlantısı her sunucu anahtarını sorgusuz kabul ediyordu (MITM)
- **Güvenlik:** `pulseops status` çıktısı hostname, mount noktası ve uyarı metinlerini Rich markup olarak
  yorumluyordu (TUI'deki markup enjeksiyonunun CLI karşılığı); tablo başlıkları da artık düz metin
- Anahtar bulunmayan makinede şifre sorulmadan "bağlanılamadı" hatası veriliyordu
- Başarısız şifre denemeleri iki kez sayılıyordu (sshd her denemeden sonra "Connection closed by
  authenticating user" da yazıyor); geçersiz kullanıcı denemeleri de iki kez sayılıyordu

## Faz 5 — Ürünleşme

- ✅ **v1.1.0 yayınlandı**; release workflow Actions sekmesinden sürüm girdisiyle de çalıştırılabiliyor.
  Doğrulama: gerçek `curl | bash` kurulumu, SHA-256, `update`, `uninstall`; paketlenmiş 65 kütüphanenin
  en yüksek glibc ihtiyacı **2.28** (eski `ubuntu-latest` derlemesi 2.38 istiyordu → Ubuntu 22.04'te çalışmazdı)
- ✅ Güvenlik değişikliği tespiti + geçmiş (SQLite): yeni dışa açık port, UID 0 / sudo / NOPASSWD / SSH anahtarı
  değişiklikleri, güvenlik duvarı, sshd, fail2ban, servisler, konteynerler; TUI bildirimi ve `h` modalı (trend +
  akış), `pulseops history`, `check` entegrasyonu (son `check`'ten beri, WARNING'e yükseltme), cron ile sürekli gözlem
- ⬜ Bildirimler: webhook, Slack, Telegram, Discord, e-posta
- ⬜ Çoklu sunucu: `~/.ssh/config` grupları, filo görünümü, `check --all`
- ⬜ `.deb` / `.rpm` paketleri
