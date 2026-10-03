# PulseOps Güvenlik Modeli

Bu belge, PulseOps'u bir sunucuda çalıştırmadan önce güvenlik / SOC ekiplerinin sorduğu sorulara yanıt verir.

## 1. Sunucuda ne çalışır?

Tek bir POSIX shell betiği (`sh -s`, stdin üzerinden). Yerel modda bu makinede, uzak modda SSH üzerinden
çalışır; hedefe hiçbir dosya, ajan veya servis kurulmaz. Çalışacak betiğin **birebir aynısını** görmek için:

```bash
pulseops probe                 # tüm katmanlar
pulseops probe --tier fast     # her 2 sn çalışan kısım
pulseops probe --sudo off      # sudo hiç kullanılmadığında
```

| Katman | Sıklık | Okunanlar |
| :--- | :--- | :--- |
| FAST | 2 sn | `/proc/{uptime,loadavg,stat,meminfo,diskstats,net/dev}`, `ss -lntu` (yoksa `/proc/net/*`), `/proc/*/stat` |
| SLOW | 30 sn | hostname/os-release, `df`, `ss -lntup`, `ps`, `nginx -T`, `systemctl list-timers/list-units`, `crontab -l`, yedek dosyası araması (`find`, en fazla 4 seviye), `docker ps` / `docker system df`, `du` (öncelik düşük, 10 sn sınırlı), güvenlik duvarı (`ufw status`, `firewall-cmd --state`, `iptables -S INPUT`, `nft list ruleset`), `sshd -T` veya `sshd_config`, `fail2ban-client status`, sshd kimlik doğrulama kayıtları (journald son 24 saat veya `auth.log`/`secure` son 20.000 satır), `/etc/passwd`, `/etc/group`, sudoers'taki `NOPASSWD` satırları, `authorized_keys` satır sayıları |
| LOGS | Loglar sekmesi açıkken | nginx access log veya journald son 40 satır |

### Salt-okunur garantisi

`tests/test_probe.py::test_probe_is_read_only` her CI çalışmasında betiğin tamamını tarar ve şunları içerirse
başarısız olur: dosya yazan yönlendirmeler (`/dev/null` dışında), `rm`/`mv`/`cp`/`tee`/`chmod`/`sed -i`…,
`systemctl start|stop|restart…`, `docker rm|run|exec|prune…`, `ufw allow|deny|enable…`,
`iptables -A|-D|-I…`, `nft add|delete|flush…`, `fail2ban-client set|unban…`, `crontab -r|-e`, `nginx -s`,
dosyaya yazan veya komut çalıştıran awk programları. Bu test, tehlikeli komut enjekte edilerek
doğrulanmıştır (mutasyon testi).

İçerik olarak okunmayan, yalnızca **sayılan** veya **özetlenen** veriler: `authorized_keys` (yalnızca anahtar
sayısı), sshd kayıtları (yalnızca sayılar, en çok deneyen 10 IP/kullanıcı ve son 10 başarılı giriş), sudoers
(yalnızca `NOPASSWD` içeren satırlar).

## 2. sudo davranışı

- **root** olarak çalışırken sudo hiç çağrılmaz.
- **Hızlı katman** hiçbir zaman sudo kullanmaz (`tests/test_probe.py::test_fast_tier_never_uses_sudo`).
- Root olmayan kullanıcıda, parolasız sudo varsa ilk yavaş turda **bir kez** `sudo -n true` ile tespit edilir;
  sonra yalnızca yavaş katmandaki okuma komutları için `sudo -n` kullanılır (parola asla sorulmaz).
- Her sudo çağrısı sunucunun auth log'una yazılır; bu yüzden çağrı sayısı en aza indirilmiştir
  (ör. sudoers ve `authorized_keys` okuması tek bir `sudo -n sh -c` ile yapılır).
- Tamamen kapatmak için: `[general] use_sudo = false`.

## 3. Yetki yetmediğinde

Okunamayan veri **"bilinmiyor"** olarak gösterilir, asla "güvenli" sayılmaz ve sağlık skorundan puan düşürmez:
güvenlik duvarı, fail2ban, SSH giriş kayıtları, sudoers. Örneğin journald'yi okuma yetkisi olmayan bir
kullanıcı yalnızca kendi kayıtlarını görür; PulseOps bu durumda "0 başarısız giriş" yerine "okunamadı" der.

## 4. SSH bağlantı güvenliği

- **Host key doğrulaması** `~/.ssh/known_hosts` ve `/etc/ssh/ssh_known_hosts` ile yapılır (hash'li kayıtlar dahil).
  Anahtar **değişmişse** bağlantı her zaman reddedilir ve iki parmak izi gösterilir (MITM koruması).
  Bilinmeyen sunucuda SHA256 parmak izi gösterilip onay istenir; onaylanan anahtar `~/.ssh/known_hosts`
  dosyasına (0600) OpenSSH biçiminde eklenir. Etkileşimsiz çalışmalar (`check`, cron) bilinmeyen anahtarı
  asla kabul etmez. Ayar: `[ssh] host_key_checking = "ask" | "accept-new" | "yes"`.
- **Kimlik doğrulama** OpenSSH sırasını izler: `--key`, `~/.ssh/config` `IdentityFile`, ssh-agent, `~/.ssh/id_*`;
  gerektiğinde anahtar parolası veya şifre etkileşimli sorulur. Şifre komut satırından verilemez
  (`ps` ve shell geçmişinde görünürdü); otomasyon için `PULSEOPS_SSH_PASSWORD`.
- **Atlama sunucuları** (`-J`, `ProxyJump`) aynı host key politikasıyla doğrulanır.

## 5. Sunucudan gelen veri güvenilmez kabul edilir

Süreç adları, log satırları, domainler, kullanıcı adları gibi değerler başkaları tarafından
belirlenebilir. Hiçbiri terminal markup'ı olarak yorumlanmaz: `GET /[/]` gibi bir istek arayüzü
çökertemez, `[link=…]` tıklanabilir link üretemez (`tests/test_markup_injection.py` tüm sekmeleri, modalları,
`status` ve `report` çıktısını kötü niyetli veriyle dener). Probe bölüm işaretleri çalıştırma başına rastgele
bir nonce içerir; komut çıktısı sahte bölüm enjekte edemez.

## 6. PulseOps'un yerelde yazdığı dosyalar

| Dosya | Ne zaman |
| :--- | :--- |
| `~/.ssh/known_hosts` | Bir sunucu anahtarını onayladığınızda (veya `accept-new`) |
| `~/.config/pulseops/config.toml` | Yalnızca `pulseops config --init` ile |
| `~/.cache/pulseops/pulseops.log` | Tanılama logu (1 MB × 3 döndürmeli); şifre veya anahtar içermez |
| `audit-reports/*.md` | `e` tuşu veya `pulseops report` ile |
| `~/.local/share/pulseops/history.db` | Metrik örnekleri (30 gün) ve güvenlik değişiklikleri (180 gün); 0600, dizin 0700. Kullanıcı adları, port/süreç adları ve sudoers satırları içerir. Kapatmak için `[history] enabled = false` |

PulseOps, SSH bağlantısı ve `pulseops update` (GitHub release, SHA-256 doğrulamalı) dışında ağ bağlantısı
kurmaz; telemetri hiçbir yere gönderilmez.
