# Arayüz (TUI)

## Çalıştırma

```bash
pulseops                    # bu sunucuyu canlı izle
sudo pulseops               # tam görünüm: tüm süreçlerin port sahipleri, güvenlik duvarı, docker, sudoers
pulseops --demo             # gerçekçi örnek verilerle demo
pulseops root@web01         # başka bir sunucuyu SSH ile (bkz. Uzak Sunucular)
pulseops fleet              # tüm sunucular tek ekranda (bkz. Uzak Sunucular & Filo)
```

**Root olmayan kullanıcı:** PulseOps yetkinizi algılar. Parolasız `sudo` varsa ağır kontrollerde `sudo -n`
kullanır; yoksa erişemediği veriler için header'da `kullanıcı (kısıtlı)` rozeti ve neyin eksik olduğunu
anlatan tek seferlik bir bildirim gösterir. Okunamayan veri **bilinmiyor** olarak gösterilir, asla "sorun yok"
olarak değil.

## SSH terminali için seçenekler

| Seçenek | Ne işe yarar |
| :--- | :--- |
| `--interval 5` | Hızlı metriklerin (CPU, RAM, port, süreç) yenileme aralığı; varsayılan 2 sn. Yavaş bağlantılarda artırın. |
| `--slow-interval 60` | Ağır kontrollerin (servis, docker, nginx, yedek, güvenlik) aralığı; varsayılan 30 sn. `r` hepsini yeniler. |
| `--no-color` | Renksiz çıktı; `NO_COLOR` ortam değişkeni de desteklenir. |
| `--ascii` | Yalnızca ASCII karakter; UTF-8 olmayan terminallerde otomatik açılır. |
| `--no-mouse` | Fare desteğini kapatır (tmux/screen içinde metin seçimi için). |

Aynı ayarlar kalıcı olarak `[general]` bölümünde de verilebilir ([Yapılandırma](configuration.md)).

## Sekmeler

`1`–`0` tuşlarıyla geçilir. Uzun sekmeler ok tuşları, `PgUp`/`PgDn`, `Home`/`End` ile kaydırılır (80x24
terminalde de tüm içeriğe ulaşılır).

| Tuş | Sekme | İçerik |
| :---: | :--- | :--- |
| `1` | Dashboard | CPU/RAM/swap, disk bölümleri, disk I/O, güvenlik duvarı, sağlık skoru, yedek ve servis özeti |
| `2` | Süreçler | CPU ve RAM'e göre canlı sıralı süreçler, kullanıcı, PID |
| `3` | Portlar | Dinlenen portlar, bind adresi (`127.0.0.1` / `0.0.0.0`), sahip süreç, risk sınıfı; `p` RPC portlarını gizler |
| `4` | Servisler | systemd birimleri; çökmüş (`failed`) servisler her zaman listede |
| `5` | Veritabanı | Otomatik keşfedilen PostgreSQL, MySQL, Redis, MongoDB… ve dışa açıklık durumları |
| `6` | Siteler | nginx ve Docker yönlendirme haritası, SSL kalan gün, HTTP durumu, 502 kök neden teşhisi |
| `7` | Yedekler | systemd timer'ları, crontab yedek işleri, snapshot dosyaları, saklama riski |
| `8` | Loglar | nginx access log veya journald akışı, renklendirme ve filtre |
| `9` | Güvenlik | SSH sertleştirme, güvenlik duvarı, SOC görünümü (fail2ban, SSH giriş aktivitesi, yetkili hesaplar), güncellemeler, sistem sertleştirme, konteyner güvenliği |
| `0` | Depolama | Dosya sistemleri (doluluk, inode, salt-okunur), dolma tahmini, en büyük dizinler, silinmiş ama açık dosyalar, log şişmesi (journald, `/var/log`, Docker konteyner logları), Docker depolama, tavsiyeler |

Neyin, nasıl denetlendiği: [Neler Denetlenir?](checks.md).

## Klavye kısayolları

| Tuş | İşlev |
| :---: | :--- |
| `1`–`0`, `F1`–`F10` | Sekmeye geç |
| `a` | Uyarılar paneli |
| `h` | Geçmiş: 24 saatlik trendler ve 7 günlük güvenlik değişikliği akışı |
| `i` | Yerel AI analizi (Ollama); takip soruları sorulabilir ([Yerel AI](ai.md)) |
| `e` | Markdown denetim raporu üret (`audit-reports/`) |
| `c` | Yapılandırma görüntüleyici (nginx, sshd) |
| `f` | Boş port bulucu |
| `p` | Port filtresi (sistem RPC portları) |
| `w` | Site filtresi: tümü, web, hatalı (502), SSL, TCP |
| `Enter` / `o` | Seçili siteyi tarayıcıda aç |
| `/` | Canlı arama |
| `t` | Tema değiştir |
| `r` | Her şeyi şimdi yenile |
| `q` / `Ctrl+C` | Çıkış |

## Kaynak tüketimi

Yerel canlı modda PulseOps'un kendi CPU kullanımı 4 çekirdekli bir sunucuda tek çekirdeğin yaklaşık %2'sidir
(`--interval 5` ile ~%1.3). Veri toplama ayrı bir thread'de yürür; arayüz hiçbir zaman beklemez. 3000 portlu,
8000 süreçli bir sunucuda bile her yenileme ~40 ms sürer. Ayrıntılar: [Mimari](architecture.md).

Sorun giderme logu: `~/.cache/pulseops/pulseops.log`.
