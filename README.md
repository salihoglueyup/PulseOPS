<div align="center">

```
  ██████╗ ██╗   ██╗██╗     ███████╗███████╗ ██████╗ ██████╗ ███████╗
  ██╔══██╗██║   ██║██║     ██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██████╔╝██║   ██║██║     ███████╗█████╗  ██║   ██║██████╔╝███████╗
  ██╔═══╝ ██║   ██║██║     ╚════██║██╔══╝  ██║   ██║██╔═══╝ ╚════██║
  ██║     ╚██████╔╝███████╗███████║███████╗╚██████╔╝██║     ███████║
  ╚═╝      ╚═════╝ ╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝     ╚══════╝
```

**Ajansız, salt-okunur sunucu, güvenlik ve altyapı gözlemi: terminalinizde.**

[![CI](https://github.com/salihoglueyup/PulseOPS/actions/workflows/ci.yml/badge.svg)](https://github.com/salihoglueyup/PulseOPS/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/salihoglueyup/PulseOPS)](https://github.com/salihoglueyup/PulseOPS/releases/latest)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](docs/development.md)
[![Platform](https://img.shields.io/badge/platform-Linux-orange.svg)](docs/installation.md)
[![Read-only](https://img.shields.io/badge/probe-100%25_read--only-success.svg)](docs/security.md)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[Kurulum](docs/installation.md) •
[Arayüz](docs/tui.md) •
[Otomasyon](docs/automation.md) •
[Neler Denetlenir?](docs/checks.md) •
[Yerel AI](docs/ai.md) •
[Güvenlik Modeli](docs/security.md) •
[Tüm Belgeler](docs/README.md)

</div>

---

Sunucuya SSH ile bağlanın, `pulseops` yazın: CPU'dan SSL sürelerine, dışa açık veritabanı portlarından SSH
kaba kuvvet saldırılarına, bekleyen güvenlik yamalarından riskli Docker konteynerlerine kadar her şey tek
ekranda. Sunucuya **hiçbir ajan veya servis kurulmaz**, **hiçbir şey değiştirilmez**.

## Öne çıkanlar

- **Ajansız ve salt-okunur:** hedefte yalnızca okuma yapan bir shell betiği çalışır (`pulseops probe` ile birebir
  görülebilir); CI her değişiklikte betiği değiştiren komutlara karşı tarar. Yerel modda ve SSH'ta aynı kod.
- **Hafif:** canlı modda tek çekirdeğin ~%2'si; arayüz hiç beklemez; 3000 portlu sunucuda bile akıcı.
- **SOC görünümü:** SSH giriş aktivitesi ve en çok deneyen IP'ler, fail2ban, UID 0 hesaplar, sudo/sudoers
  yetkileri, `NOPASSWD` kuralları, `authorized_keys`.
- **Güvenlik denetimi:** bekleyen güvenlik güncellemeleri ve yeniden başlatma ihtiyacı, CIS tarzı sistem
  sertleştirme, konteyner kaçış riskleri (`--privileged`, Docker soketi, tehlikeli yetenekler).
- **Değişiklik tespiti:** yeni dışa açık port, UID 0 hesap, SSH anahtarı, SUID dosya, kapatılan güvenlik duvarı…
  geçmişe kaydedilir, bir kez bildirilir.
- **Depolama:** inode tükenmesi, hata nedeniyle salt-okunur kalan diskler, "bu hızla N günde dolacak" tahmini,
  silinmiş ama açık tutulan dosyalar, log şişmesi (journald, Docker konteyner logları), en büyük dizinler.
- **Web & altyapı:** nginx/Docker yönlendirme haritası, SSL kalan gün, 502 teşhisi, veritabanı keşfi, systemd,
  yedekler, Docker/BuildKit depolama.
- **Otomasyon:** Nagios uyumlu `check`, JSON ve Prometheus çıktısı, systemd zamanlayıcısı, Telegram / Slack /
  Discord / e-posta / webhook bildirimleri, çoklu sunucu (filo).
- **Yerel AI (Ollama):** sunucunun durumunu yerel bir modelle yorumlatın; veri makineden çıkmaz, prompt
  injection'a karşı korunur.
- **Güvenilmez veriye dayanıklı:** sunucudan gelen hiçbir metin terminal markup'ı olarak yorumlanmaz;
  ayrıştırıcılar fuzzing ile sınanır.

## Hızlı başlangıç

```bash
curl -fsSL https://raw.githubusercontent.com/salihoglueyup/PulseOPS/main/install.sh | bash

pulseops                 # bu sunucuyu canlı izle  (tam görünüm: sudo pulseops)
pulseops --demo          # örnek verilerle dene
pulseops root@web01      # başka bir sunucuyu SSH ile izle
pulseops status          # TUI açmadan özet
pulseops check           # cron / monitoring için çıkış kodu
pulseops ai explain      # yerel AI ile analiz (Ollama)
```

`.deb` / `.rpm` paketleri ve diğer yöntemler: [Kurulum](docs/installation.md). Linux x86_64, glibc 2.28+ (Ubuntu
20.04+, Debian 10+, RHEL 8+).

## Belgeler

| | |
| :--- | :--- |
| [Kurulum](docs/installation.md) | install.sh, paketler, güncelleme, kaldırma |
| [Arayüz (TUI)](docs/tui.md) | sekmeler, kısayollar, SSH terminali seçenekleri |
| [Uzak Sunucular & Filo](docs/remote.md) | SSH, host key doğrulaması, ProxyJump, çoklu sunucu |
| [Otomasyon & İzleme](docs/automation.md) | `check` (Nagios / JSON / Prometheus), zamanlayıcı, geçmiş, bildirimler, rapor |
| [Neler Denetlenir?](docs/checks.md) | uyarılar, sağlık skoru hesabı, sertleştirme, konteyner riskleri, değişiklik tespiti |
| [Yerel AI (Ollama)](docs/ai.md) | `pulseops ai`, gizlilik ve güvenlik |
| [Yapılandırma](docs/configuration.md) | `config.toml` tam referansı |
| [Güvenlik Modeli](docs/security.md) | çalıştırılan komutlar, sudo, SSH, yazılan dosyalar |
| [Mimari](docs/architecture.md) · [Geliştirme](docs/development.md) · [Yol Haritası](docs/roadmap.md) | |

## Lisans

[MIT](LICENSE)
