# Yapılandırma

```bash
pulseops config           # geçerli ayarlar ve okunan dosyalar
pulseops config --init    # ~/.config/pulseops/config.toml şablonunu oluşturur (tüm satırlar yorumlu)
```

Ayarlar sırayla okunur, sonraki öncekini ezer:

1. `/etc/pulseops/config.toml`: sunucu geneli (paketle kurulumda örnek: `/usr/share/doc/pulseops/config.example.toml`)
2. `~/.config/pulseops/config.toml` (`$XDG_CONFIG_HOME`)
3. komut satırı bayrakları

Yazım hatalı veya bilinmeyen bir anahtar sessizce yok sayılmaz; dosya adı ve satırıyla hata olarak raporlanır
(`check` bu durumda `UNKNOWN` döner). Sır içeren dosyaları `chmod 600` yapın; sırlar için `env:DEGISKEN`
yazılabilir.

## Tam referans

Aşağıdaki blok `pulseops config` çıktısıdır (varsayılan değerler):

```toml
[general]
# Hızlı metrik yenileme aralığı (sn): CPU, RAM, port, süreç
interval = 2.0
# Ağır kontrollerin aralığı (sn): servis, docker, nginx, yedek
slow_interval = 30.0
# Yalnızca ASCII karakter kullan
ascii = false
# Renksiz (gri tonlamalı) çıktı
no_color = false
# Fare desteği
mouse = true
# Root değilken yavaş kontrollerde parolasız `sudo -n` kullan (her çağrı auth log'a yazılır)
use_sudo = true

[fleet]
# Filo: `pulseops fleet` ve `check --all` için sunucular (ör. "web01", "deploy@10.0.0.5:2222", "local")
hosts = []
# Gruplar (--group ile seçilir), ör. { web = ["web01", "web02"] }
groups = {  }
# Aynı anda sorgulanacak en fazla sunucu
parallel = 8

[notify]
# Bu önemin altındaki güvenlik değişiklikleri bildirilmez
min_severity = "MEDIUM"
# check durumu değişince bildir (OK → WARNING, düzelince → OK)
on_state_change = true
# Bildirim kanalları (yalnızca `pulseops check` gönderir; durum değişince ve yeni güvenlik değişikliğinde).
# Gizli değerler için "env:DEGISKEN" yazabilirsiniz; deneme: pulseops notify --test
#
# [[notify.channels]]
# type = "telegram"
# bot_token = "env:PULSEOPS_TELEGRAM_TOKEN"
# chat_id = "123456789"
#
# [[notify.channels]]
# type = "slack"            # veya "discord", "webhook" (JSON POST)
# url = "env:PULSEOPS_SLACK_WEBHOOK"
#
# [[notify.channels]]
# type = "email"
# smtp_host = "smtp.ornek.com"
# smtp_port = 587
# security = "starttls"     # starttls | ssl | none
# username = "alarm@ornek.com"
# password = "env:PULSEOPS_SMTP_PASSWORD"
# sender = "alarm@ornek.com"
# to = ["ops@ornek.com"]

[history]
# Metrik geçmişi ve güvenlik değişikliği tespiti (~/.local/share/pulseops/history.db)
enabled = true
# `pulseops check`: yüksek önemli yeni değişiklikte en az bu çıkış kodu
drift_exit = "warning"

[ssh]
# Bilinmeyen sunucu anahtarı: ask = parmak izini sor, accept-new = ilk bağlantıda kabul et, yes = reddet
host_key_checking = "ask"

[check]
# `pulseops check`: bu skorun altı WARNING
warn = 80
# `pulseops check`: bu skorun altı CRITICAL
crit = 50

[alerts]
# Disk doluluk uyarı eşiği (%)
disk_percent = 80.0
# RAM kullanım uyarı eşiği (%)
memory_percent = 85.0
# SSL bitişine kalan gün uyarı eşiği
ssl_days = 7
# Bu sayının üzerinde başarısız SSH denemesi ve fail2ban koruması yoksa uyar
ssh_failed_logins = 100

[ai]
# Ollama adresi
url = "http://127.0.0.1:11434"
# Kullanılacak model (`ollama pull <model>`)
model = "qwen2.5:7b"
# Bir yanıtın toplam süre sınırı (sn); aşılırsa yanıt kesilir
timeout = 180.0
# Yanıt başına en fazla token (döngüye giren modeli durdurur)
max_tokens = 1200
# Model bağlam penceresi (token)
num_ctx = 8192
# localhost dışındaki bir Ollama'ya telemetri gönderilmesine izin ver
allow_remote = false
# IP adreslerini ve hostname'i modele göndermeden önce maskele
redact = false
# Son log satırlarını da gönder (komut enjeksiyonu riski taşıyan ham metin)
include_logs = false
```

## Bölümler

| Bölüm | Belge |
| :--- | :--- |
| `[general]` | [Arayüz (TUI)](tui.md) |
| `[fleet]`, `[ssh]` | [Uzak Sunucular & Filo](remote.md) |
| `[notify]`, `[history]`, `[check]` | [Otomasyon & İzleme](automation.md) |
| `[alerts]` | [Neler Denetlenir?](checks.md) |
| `[ai]` | [Yerel AI](ai.md) |
