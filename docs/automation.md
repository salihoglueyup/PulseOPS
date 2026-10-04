# Otomasyon & İzleme

Tüm komutlar TUI açmadan çalışır ve uzak sunucu kabul eder (`pulseops <komut> root@sunucu`).

```bash
pulseops status [--json]          # tek ekranlık özet / tam telemetri JSON
pulseops report [-f md|json] [-o DİZİN | -o -]   # denetim raporu (varsayılan: audit-reports/)
pulseops check [-f nagios|json|prometheus] [-o DOSYA] [--warn N --crit N] [--all | --group G]
pulseops history [HOST] [--since 7d] [--json]     # kayıtlı trendler ve güvenlik değişiklikleri (bağlantı kurmaz)
pulseops probe [--tier fast|slow|logs|all]       # sunucuda çalışacak salt-okunur betiği göster
pulseops schedule install|show|status|remove     # systemd zamanlayıcısı
pulseops notify --test                           # bildirim kanallarını dene
```

## `pulseops check`

Sağlık skoruna ve yeni güvenlik değişikliklerine göre çıkış kodu verir; Nagios/Icinga/Zabbix eklentisi
olarak doğrudan kullanılabilir.

| Çıkış kodu | Durum | Ne zaman |
| :---: | :--- | :--- |
| `0` | OK | skor ≥ `--warn` (varsayılan 80) |
| `1` | WARNING | skor < `--warn`, veya son `check`'ten beri YÜKSEK önemli yeni değişiklik (`[history] drift_exit`) |
| `2` | CRITICAL | skor < `--crit` (varsayılan 50) |
| `3` | UNKNOWN | veri toplanamadı, sunucuya erişilemedi, yapılandırma hatası |

Filo modunda (`--all`, `--group`) çıkış kodu en kötü durumdur: CRITICAL > UNKNOWN > WARNING > OK.

### Çıktı biçimleri

Çıkış kodu her biçimde aynıdır.

**Nagios** (varsayılan): tek satır + performans verisi:

```
PULSEOPS WARNING - web01 skor 65/100 C (DİKKAT / MÜDAHALE GEREKİR); Port :27017 (mongod) dışa açık! | score=65;80;50;0;100 alerts=3 changes=0
```

**JSON** (`-f json`): skor, uyarılar, yeni değişiklikler ve güvenlik özeti (bekleyen/güvenlik güncellemeleri,
yeniden başlatma, başarısız sertleştirme kontrolleri, riskli konteynerler, başarısız SSH girişleri). Filo
modunda sunucu başına bir nesne ve durum sayıları.

**Prometheus** (`-f prometheus`): node_exporter'ın textfile collector'ı için. `-o` ile atomik yazılır (geçici
dosya + rename; yarım dosya asla okunmaz):

```bash
*/5 * * * * pulseops check --all -f prometheus -o /var/lib/node_exporter/textfile/pulseops.prom
```

| Metrik | Etiketler | Anlam |
| :--- | :--- | :--- |
| `pulseops_up` | target, hostname | sunucuya ulaşıldı mı (1/0) |
| `pulseops_check_state` | | 0 OK · 1 WARNING · 2 CRITICAL · 3 UNKNOWN |
| `pulseops_score` | | sağlık skoru (0-100) |
| `pulseops_alerts`, `pulseops_security_changes` | | aktif uyarı ve yeni değişiklik sayısı |
| `pulseops_security_updates`, `pulseops_pending_updates` | | bekleyen güncellemeler |
| `pulseops_reboot_required` | | yeniden başlatma gerekiyor mu |
| `pulseops_hardening_failed_checks` | severity | başarısız sertleştirme kontrolleri |
| `pulseops_risky_containers` | | host'u ele geçirebilecek konteynerler |
| `pulseops_ssh_failed_logins` | | başarısız SSH girişleri |
| `pulseops_firewall_active`, `pulseops_exposed_risky_ports` | | güvenlik duvarı, dışa açık riskli portlar |
| `pulseops_cpu_percent`, `pulseops_memory_percent` | | kaynak kullanımı |
| `pulseops_disk_used_percent` | mountpoint | disk doluluğu |
| `pulseops_last_check_timestamp_seconds` | | son kontrol zamanı |

Okunamayan değerler 0 olarak değil, **hiç yazılmaz**.

## Düzenli çalıştırma

**systemd zamanlayıcısı** (önerilen):

```bash
sudo pulseops schedule install                         # her 5 dakikada `pulseops check`
sudo pulseops schedule install --every 1m --args "check --all -f prometheus -o /var/lib/node_exporter/textfile/pulseops.prom"
pulseops schedule show                                 # yazılacak birimleri yalnızca göster
pulseops schedule status
sudo pulseops schedule remove
```

Root için `/etc/systemd/system`, diğer kullanıcılar için `~/.config/systemd/user` (oturum kapalıyken de
çalışması için `loginctl enable-linger`). WARNING/CRITICAL/UNKNOWN sonuçları birimi "failed" yapmaz; uyarılar
bildirim kanallarından gider. Birim düşük öncelikle (`Nice`, boşta I/O) ve `ProtectSystem=full` ile çalışır.

**cron**:

```bash
*/5 * * * * /usr/local/bin/pulseops check >> /var/log/pulseops-check.log 2>&1
0 * * * * pulseops check --warn 70 || pulseops report -o - | mail -s "PulseOps uyarısı" ops@ornek.com
```

## Geçmiş ve değişiklik tespiti

Her yavaş turda sunucunun güvenlik "parmak izi" bir öncekiyle karşılaştırılır; metrik örnekleri (30 gün) ve
değişiklikler (180 gün) `~/.local/share/pulseops/history.db` (0600) dosyasına yazılır. Hangi değişikliklerin
hangi önemle raporlandığı: [Neler Denetlenir?](checks.md#değişiklik-tespiti).

- TUI'de yüksek önemli değişiklikler anında bildirilir; `h` tuşu trendleri ve 7 günlük akışı gösterir.
- `pulseops check`, kim tespit etmiş olursa olsun (TUI, `status`, önceki `check`) **son `check`'ten beri** oluşan
  değişiklikleri bir kez raporlar.
- Ajansız olduğu için geçmiş PulseOps çalıştıkça birikir; sürekli gözlem için zamanlayıcı yeterlidir.

## Bildirimler

`pulseops check` yalnızca **durum değiştiğinde** (OK → WARNING, düzelince → OK…) ve **yeni güvenlik
değişikliğinde** bildirim gönderir; aynı uyarı her 5 dakikada tekrar edilmez. Kanallar: Telegram, Slack,
Discord, e-posta (SMTP), genel webhook (JSON POST).

```toml
# ~/.config/pulseops/config.toml  (chmod 600)
[notify]
min_severity = "MEDIUM"

[[notify.channels]]
type = "telegram"
bot_token = "env:PULSEOPS_TELEGRAM_TOKEN"   # sırlar ortam değişkeninden okunabilir
chat_id = "123456789"

[[notify.channels]]
type = "slack"                              # "discord" ve "webhook" aynı biçimde: url = "..."
url = "env:PULSEOPS_SLACK_WEBHOOK"
```

Sunucudan gelen metinler her kanal için kaçışlanır: Slack'te `<url|metin>`, Discord'da `[metin](url)` gibi
sahte linklere veya `@everyone` gibi bahsetmelere dönüşemez. Düz metin sır içeren bir yapılandırma dosyası
başkalarınca okunabiliyorsa PulseOps uyarır. Tüm kanal seçenekleri: [Yapılandırma](configuration.md).

## Denetim raporu

`pulseops report` (veya TUI'de `e`) tüm modülleri Markdown tablolarına döker: sağlık skoru ve notu, donanım,
ağ, portlar, servisler, siteler, yedekler, konteynerler (güvenlik bulgularıyla), depolama, SOC bulguları,
güncellemeler, sertleştirme tablosu ve **eylem planı** (ör. `ufw deny 27017`, `certbot renew`,
`docker builder prune`). `-f json` aynı veriyi makine okunur verir.
