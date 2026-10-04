# Uzak Sunucular & Filo

## SSH ile izleme

Uzak sunucuya hiçbir şey kurulmaz: PulseOps aynı salt-okunur betiği SSH üzerinden `sh -s` ile çalıştırır.

```bash
pulseops ubuntu@192.168.1.50 --key ~/.ssh/id_ed25519
pulseops web01                       # ~/.ssh/config'teki Host adı (HostName, User, Port, IdentityFile, ProxyJump, ProxyCommand)
pulseops deploy@10.0.0.5:2222
pulseops deploy@10.0.0.5 -J bastion  # atlama sunucusu üzerinden (zincir: -J a,b)
```

Etkileşimsiz komutların hepsi de uzak sunucu kabul eder: `pulseops status web01`, `pulseops check web01`,
`pulseops ai explain web01`…

## Kimlik doğrulama

OpenSSH ile aynı sıra izlenir: `--key`, `~/.ssh/config`, ssh-agent ve `~/.ssh/id_*`. Anahtar parolalıysa
anahtar parolası, anahtarlar reddedilirse şifre güvenli şekilde sorulur.

Komut satırında şifre **verilemez** (`ps` çıktısında ve shell geçmişinde görünürdü). Otomasyon için
`PULSEOPS_SSH_PASSWORD` ortam değişkeni kullanılabilir; anahtar tercih edilmelidir.

## Sunucu anahtarı (host key) doğrulaması

Anahtarlar `~/.ssh/known_hosts` ve `/etc/ssh/ssh_known_hosts` ile doğrulanır:

- **Değişmiş** bir anahtarla bağlantı her zaman reddedilir (MITM koruması).
- Bilinmeyen sunucuda SHA256 parmak izi gösterilir ve onay istenir; onaylanan anahtar `known_hosts`'a eklenir.
- Etkileşimsiz komutlar (`check`, cron, filo) bilinmeyen anahtarı **asla** kabul etmez.

```toml
[ssh]
host_key_checking = "ask"   # ask | accept-new (ilk bağlantıda kabul et) | yes (bilinmeyeni reddet)
```

Bağlantı koptuğunda (NAT zaman aşımı, sshd yeniden başlatma) bir sonraki turda otomatik yeniden bağlanılır;
host key ve kimlik doğrulama hataları ise asla tekrar denenmez.

## Filo (çoklu sunucu)

```toml
[fleet]
hosts = ["local", "web01", "deploy@10.0.0.5:2222"]   # ~/.ssh/config Host adları kullanılabilir
groups = { web = ["web01", "web02"], db = ["db01"] }
parallel = 8
```

```bash
pulseops fleet                 # tüm sunucular: durum, skor, uyarılar, CPU/RAM/disk, 24 saatlik değişiklikler
pulseops fleet --group web     # Enter: seçili sunucunun tam TUI'si, q: filoya dönüş
pulseops check --all           # cron/monitoring: sunucu başına bir satır + özet, en kötü durum çıkış kodu
pulseops check --group db -f json
```

- Sunucular paralel ve etkileşimsiz sorgulanır (SSH anahtarı veya agent gerekir).
- Erişilemeyen sunucu `UNKNOWN` olur; erişilemez hale gelmesi ve düzelmesi de bildirim üretir.
- Aynı makine farklı yollardan izlense bile (ör. `local` ve SSH, root ve normal kullanıcı) geçmiş ve
  değişiklik tespiti makine kimliğiyle (`/etc/machine-id`) birleştirilir; değişiklikler bir kez raporlanır.
