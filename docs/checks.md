# Neler Denetlenir?

Bu sayfa PulseOps'un ürettiği uyarıları, sağlık skorunun nasıl hesaplandığını ve değişiklik tespitinin neyi,
hangi önemle raporladığını listeler. Temel ilke: **okunamayan veri "bilinmiyor"dur**. Ne uyarı üretir ne de
"sorun yok" sayılır, ne de skordan puan düşürür.

## Uyarılar

TUI'de `a`, `pulseops status`, `check` ve bildirimlerde görünür. Eşikler `[alerts]` ile ayarlanır.

| Uyarı | Koşul |
| :--- | :--- |
| Port dışa açık | Riskli port tüm arayüzlerde dinliyor: veritabanları (`3306`, `5432`, `1433`, `1521`, `6379`, `27017`, `9200`, `11211`), Telnet, SMB/RPC, RDP, şifresiz Docker soketi (`2375`), Kafka/RabbitMQ ve geliştirme sunucuları (`3000`, `5000`, `8000`, `8080`) |
| SSL bitiyor | Sertifikanın bitmesine `ssl_days` (7) gün veya daha az |
| 502 / 504 | Sitenin upstream'i yanıt vermiyor |
| Disk / RAM | `disk_percent` (80) / `memory_percent` (85) aşıldı |
| Güvenlik duvarı KAPALI | Durum okunabildi ve aktif değil |
| Kritik servis çalışmıyor | nginx, docker, postgres, mysql, redis durmuş veya çökmüş |
| Yedekleme riski | Snapshot saklama analizi YÜKSEK/KRİTİK |
| UID 0 hesap | `root` dışında UID 0 olan hesap (arka kapı göstergesi) |
| SSH kaba kuvvet | `ssh_failed_logins` (100) üstü başarısız giriş ve fail2ban sshd'yi korumuyor |
| Güvenlik güncellemesi | Bekleyen güvenlik güncellemesi var |
| Yeniden başlatma gerekli | `reboot-required`, `needs-restarting`, veya kurulu daha yeni çekirdek |
| Sertleştirme | Her başarısız YÜKSEK önemli kontrol (aşağıda) |
| Riskli konteyner | YÜKSEK önemli konteyner riski; sağlıksız veya ≥5 kez yeniden başlamış konteyner |
| BuildKit önbelleği | 10 GB'ı aştı |

## Sağlık skoru

100'den başlar, en düşük 15 olabilir.

| Bulgu | Puan |
| :--- | ---: |
| Dışa açık riskli port | −15 her biri |
| Güvenlik duvarı kapalı (durum biliniyorsa) | −15 |
| `PermitRootLogin yes` | −10 |
| `root` dışında UID 0 hesap | −20 her biri |
| SSH kaba kuvvet + fail2ban koruması yok | −10 |
| Bekleyen güvenlik güncellemesi | −10 |
| Yeniden başlatma bekliyor | −5 |
| Başarısız YÜKSEK sertleştirme kontrolü | −15 her biri |
| Başarısız ORTA sertleştirme kontrolü | −3 her biri (en çok −9) |
| Host'u ele geçirebilecek konteyner | −10 her biri (en çok −30) |
| 502/504 veren site | −10 her biri |
| 7 gün içinde biten SSL | −10 her biri |
| BuildKit önbelleği > 10 GB | −15 |
| Bir disk > %85 | −10 |

Not: **A+** ≥ 90 · **A** ≥ 80 · **B** ≥ 70 · **C** ≥ 50 · **CRITICAL** < 50. `check` eşikleri: `[check] warn`
(80), `crit` (50).

## SOC görünümü

| Veri | Kaynak | Root olmadan |
| :--- | :--- | :--- |
| fail2ban jail'leri, engelli IP'ler | `fail2ban-client status` | çoğunlukla okunamaz |
| SSH giriş aktivitesi | journald son 24 saat veya `auth.log`/`secure` son 20.000 satır; hedefte `awk` ile özetlenir | `systemd-journal`/`adm` grubu gerekir |
| UID 0 hesaplar, giriş yapabilen hesaplar, sudo/wheel üyeleri | `/etc/passwd`, `/etc/group` | okunur |
| sudoers ile yetkili kullanıcı/gruplar, `NOPASSWD` kuralları | `/etc/sudoers`, `/etc/sudoers.d/*` | okunamaz |
| `authorized_keys` anahtar sayıları | kullanıcı ev dizinleri | yalnızca kendi |

## Paket güncellemeleri ve yeniden başlatma

Mevcut paket önbelleğinden okunur; metadata **asla yenilenmez** (`apt update` / `dnf makecache` çalıştırılmaz):

| Yönetici | Komut | Güvenlik ayrımı |
| :--- | :--- | :--- |
| apt | `apt-get -s dist-upgrade` (yalnızca simülasyon) | `-security` deposundan gelenler |
| dnf / yum | `dnf -C check-update`, `dnf -C updateinfo list --security` (yalnızca önbellek) | updateinfo |
| apk | `apk version -l '<'` | yok (bilinmiyor) |

Paket listesinin yaşı gösterilir; 7 günden eskiyse sayıların güncel olmayabileceği belirtilir. Önbellek yoksa
(yeni container, başka kullanıcının dnf önbelleği) sonuç "okunamadı"dır, "0" değil. Yeniden başlatma:
`/var/run/reboot-required(.pkgs)`, `needs-restarting -r` veya çalışandan daha yeni kurulu çekirdek.

## Sistem sertleştirme

| Önem | Kontrol |
| :--- | :--- |
| YÜKSEK | `/etc/shadow`, `/etc/gshadow` herkes tarafından okunamıyor |
| YÜKSEK | `/etc/passwd`, `/etc/group` herkes tarafından; `/etc/sudoers`, `sshd_config` başkalarınca yazılamıyor |
| YÜKSEK | `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, `/root`, `/srv`, `/opt` altında SUID/SGID dosya yok (root gerekir) |
| YÜKSEK | `/etc` ve bin dizinlerinde herkesin yazabildiği dosya yok |
| YÜKSEK | Boş parolalı hesap yok (yalnızca kullanıcı adları okunur; root gerekir) |
| ORTA | `kernel.randomize_va_space = 2`, `fs.protected_symlinks = 1`, `fs.protected_hardlinks = 1`, `net.ipv4.tcp_syncookies = 1`, `accept_source_route = 0` |
| DÜŞÜK | `kptr_restrict`, `dmesg_restrict`, `yama.ptrace_scope`, `suid_dumpable`, ICMP redirect'leri, `rp_filter` (etkin değer: `all` ve `default`'un büyüğü), `/tmp` ve `/dev/shm` için `nosuid,nodev` |

Sistem bin dizinlerindeki SUID/SGID dosyaların listesi de tutulur: yeni bir SUID dosya değişiklik tespitine düşer.

## Konteyner güvenliği

Çalışan konteynerler için tek bir `docker inspect`:

| Önem | Risk |
| :--- | :--- |
| YÜKSEK | `--privileged` |
| YÜKSEK | Docker/containerd soketi bağlı (konteyner host'ta root olur) |
| YÜKSEK | Host sistem dizini yazılabilir bağlı (`/`, `/etc`, `/root`, `/boot`, `/proc`, `/sys`, `/dev`, `/var/lib/docker`, `/home`, `/run`) |
| YÜKSEK | `ALL`, `SYS_ADMIN`, `SYS_MODULE` yetenekleri |
| ORTA | Diğer tehlikeli yetenekler (`NET_ADMIN`, `SYS_PTRACE`, `DAC_READ_SEARCH`, `SYS_RAWIO`, `BPF`, `PERFMON`), salt-okunur host dizinleri, `--network=host`, `--pid=host` |
| DÜŞÜK | root kullanıcısıyla çalışıyor |

Ayrıca healthcheck durumu ve yeniden başlama sayısı (≥5: çökme döngüsü uyarısı).

## Değişiklik tespiti

Her yavaş turda güvenlik parmak izi bir öncekiyle karşılaştırılır. Okunamayan kategori karşılaştırılmaz; böylece
root ve normal kullanıcıyla izlemek sahte alarm üretmez.

| Önem | Değişiklik |
| :--- | :--- |
| YÜKSEK | Yeni dışa açık port; yeni UID 0 hesap; sudo/wheel'e eklenen kullanıcı; yeni `NOPASSWD` kuralı; sudoers ile verilen yetki; `authorized_keys`'e eklenen anahtar; güvenlik duvarının kapatılması; zayıflayan `sshd` ayarı; duran fail2ban; yeni riskli konteyner; yeni SUID/SGID dosya; şüpheli konumda SUID; parolası boşaltılan hesap; herkesin yazabildiği sistem dosyası; bozulan dosya izni |
| ORTA | Yeni giriş yapabilen hesap; çöken servis |
| BİLGİ | Yeni yerel (loopback) port, kapanan port, kaldırılan hesap/anahtar/kural, düzelen servis ve izinler, yeni/kaldırılan konteyner, güçlenen ayarlar |
