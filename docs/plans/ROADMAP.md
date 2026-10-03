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

## Faz 1 — Linux Sunucu Deneyimi

Amaç: Herhangi bir Linux sunucusunda tek komutla kurulup `pulseops` ile sorunsuz açılsın.

### Kurulum & dağıtım
- ⬜ Release yalnızca Linux amd64: eski glibc ile uyumlu binary (manylinux / eski base image)
- ⬜ `install.sh`: varsayılan olarak binary indirme, Python/venv yolu yedek; checksum doğrulama
- ⬜ `pulseops --version`, `pulseops update`, `pulseops uninstall`

### Terminal deneyimi (SSH oturumu içinde)
- ⬜ Küçük terminal (80x24) uyumu
- ⬜ `--no-color` / `NO_COLOR`, `--ascii` (emoji/Unicode olmayan terminaller)
- ⬜ `--no-mouse` (tmux/screen), ayarlanabilir yenileme aralığı
- ⬜ TUI'nin kendi kaynak tüketiminin ölçülmesi (hedef: boşta < %2 CPU)

### Root olmayan kullanıcı
- ⬜ Yetki gerektiren veriler için boş tablo yerine açıklayıcı mesaj
  ("root veya docker grubu gerekli")
- ⬜ Başlangıçta yetki durumunun tespiti ve header'da gösterimi

### Etkileşimsiz komutlar
- ⬜ `pulseops status` — TUI açmadan düz metin özet
- ⬜ `pulseops report --format md|json` — denetim raporu
- ⬜ `pulseops check` — sağlık skoruna göre çıkış kodu (cron / monitoring için)

## Faz 2 — Mimari

Amaç: Arayüz hiç donmasın, yerel ve SSH modu aynı kod yolunu kullansın.

- ⬜ Polling'in Textual thread worker'a taşınması (UI thread'i bloklanmasın)
- ⬜ Tek `Telemetry` Pydantic modeli; `poll()` tuple'ı ve `hasattr` kontrollerinin kaldırılması
- ⬜ Tek veri toplama yolu: yerel modda da aynı probe betiği + aynı parser
- ⬜ Hızlı / yavaş polling katmanları (CPU/RAM/port ≈ 2 sn; disk/docker/nginx/yedek ≈ 30–60 sn)
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
