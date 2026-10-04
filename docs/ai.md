# Yerel AI Analizi (Ollama)

PulseOps toplanan veriyi **kendi makinenizdeki** bir Ollama modeline yorumlatabilir: öncelikli bulgular, neden
önemli oldukları, verideki kanıtları ve uygulanabilir adımlar (Türkçe). Hiçbir komut otomatik çalıştırılmaz.

## Kurulum

```bash
curl -fsSL https://ollama.com/install.sh | sh     # Ollama (bir kez)
ollama pull qwen2.5:7b                             # model (daha küçük makinede: qwen2.5:3b, llama3.2:3b)
pulseops ai status                                 # erişim ve model kontrolü
```

## Kullanım

```bash
pulseops ai explain                    # bu sunucunun SOC analizi (yanıt akarak gelir)
pulseops ai ask "SSH saldırıları ne kadar ciddi, ne yapmalıyım?"
pulseops ai explain root@web01         # uzak sunucu için de
pulseops ai explain -m llama3.2:3b     # yapılandırmadaki model yerine
pulseops ai explain --show-prompt      # modele gidecek veriyi göster, GÖNDERME
```

TUI'de `i` tuşu aynı analizi açar; alttaki kutudan takip soruları aynı bağlam içinde sorulur.

Modele ham telemetri değil, yapılandırılmış bir **özet** gider: skor ve uyarılar, kaynak kullanımı ve en çok
tüketen süreçler, dışa açık portlar, güvenlik duvarı, SSH ayarları ve giriş aktivitesi, fail2ban, yetkili
hesaplar, güncellemeler, sertleştirme sonuçları, konteyner riskleri, çökmüş servisler ve son 24 saatin güvenlik
değişiklikleri. Okunamayan değerler `null` olarak gider ve modelden bunları "bilinmiyor" saymasını istenir.

## Yapılandırma

```toml
[ai]
url = "http://127.0.0.1:11434"
model = "qwen2.5:7b"
timeout = 180         # bir yanıtın toplam süre sınırı (sn)
max_tokens = 1200     # yanıt başına en fazla token: döngüye giren modeli durdurur
num_ctx = 8192        # bağlam penceresi
redact = false        # true: IP adresleri ve hostname modele gitmeden maskelenir
include_logs = false  # ham log satırları varsayılan olarak gönderilmez
allow_remote = false  # başka bir makinedeki Ollama için bilinçli onay
```

## Güvenlik

| Risk | Önlem |
| :--- | :--- |
| Telemetrinin makineden çıkması | Loopback dışı adres `allow_remote = true` olmadan reddedilir; istekler `HTTP(S)_PROXY` üzerinden **geçmez**. `redact` IP'leri tutarlı biçimde (`IP-1`, `IP-2`…) ve hostname'i maskeler; dinleme adresleri (`0.0.0.0`, `127.0.0.1`) anlamları için korunur |
| Prompt injection | Log satırı, süreç/konteyner/kullanıcı adı veya sudoers kuralı içine gizlenmiş "önceki talimatları unut" gibi metinler. Veri, her istekte rastgele üretilen bir anahtarla çevrili ayrı bir JSON bloğunda gönderilir; sistem talimatı bloğun yalnızca kanıt olduğunu, içindeki talimatların uygulanmayacağını belirtir. Ham loglar varsayılan olarak gönderilmez |
| Önerilen komutların çalışması | Model yalnızca metin üretir; araç veya komut erişimi yoktur. Her yanıtın sonunda doğrulama uyarısı gösterilir |
| Model çıktısıyla terminal saldırısı | Çıktı terminale ulaşmadan C0/C1 kontrol karakterlerinden temizlenir (kaçış dizileri, OSC 52 pano yazma, ekran silme engellenir); TUI'de düz metin olarak gösterilir, markup olarak yorumlanmaz |
| Sonsuz yanıt | Token sınırı (`max_tokens`), tekrar cezası ve toplam süre sınırı (`timeout`); kesilen yanıtta bu belirtilir |
| Uydurma | Model yalnızca veriye dayanmaya ve emin olmadığında bunu söylemeye yönlendirilir; çıktı her zaman doğrulanmalıdır |

Test kapsamı: Ollama API'sini taklit eden bir sunucu ile CLI ve TUI testleri, CI'da gerçek `ollama/ollama`
konteyneri ve küçük bir modelle uçtan uca test. Ayrıntılar: [Güvenlik Modeli](security.md#7-yerel-ai-ollama).
