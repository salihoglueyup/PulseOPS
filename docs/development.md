# Geliştirme

## Ortam

```bash
git clone https://github.com/salihoglueyup/PulseOPS.git && cd PulseOPS
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m pulseops --demo          # veya: pulseops --demo
ruff check .
pytest
```

Python 3.10–3.13 desteklenir. Bağımlılıkların tek kaynağı `pyproject.toml`'dur.

## Test katmanları

| Katman | Dosya | Ne doğrular | Ne zaman çalışır |
| :--- | :--- | :--- | :--- |
| Birim testleri | `tests/test_*.py` | ayrıştırıcılar, modeller, skor, değişiklik tespiti, bildirimler, yapılandırma, CLI, TUI (Textual pilot) | her zaman |
| Salt-okunur koruması | `test_probe.py::test_probe_is_read_only` | betikte değiştiren komut, dosyaya yazma, `-s`'siz apt, `-C`'siz dnf yok (mutasyon testli) | her zaman |
| Markup enjeksiyonu | `test_markup_injection.py` | sunucudan gelen metin hiçbir görünümde markup olarak yorumlanmaz | her zaman |
| Fuzzing | `test_fuzz_probe.py` | gerçek probe çıktısı bozularak tüm hat (toplayıcı, uyarılar, drift, status, JSON, rapor, TUI) çökmeden çalışır; her ayrıştırıcı girdisindeki her değer 16 düşmanca değerle tek tek denenir | her zaman (`PULSEOPS_FUZZ_EXAMPLES` ile uzatılır) |
| Ölçek | `test_scale.py` | 8000 süreç / 3000 port / 300 konteyner / 1500 servis; 80x24 terminalde kaydırma | her zaman |
| Dağıtım matrisi | `test_distros.py` | probe 8 dağıtımda (Ubuntu 20.04–24.04, Debian 11/12, Alma 8/9, Alpine), root / `nobody` / sudo'lu kullanıcı, çıplak ve kurulu sunucu | CI (`PULSEOPS_TEST_DISTROS`) |
| Gerçek sshd | `test_ssh_integration.py`, `test_ssh_security.py` | host key, ProxyJump, root olmayan + sudo, bağlantı kopması ve yeniden bağlanma | CI (`PULSEOPS_TEST_SSH_*`) |
| Gerçek Docker | `test_containers.py` | riskli ve güvenli konteynerlerin tespiti | CI (`PULSEOPS_TEST_DOCKER=1`) |
| Gerçek systemd | CI adımı | `schedule install`, servisin çalışması, `remove` | CI |
| Gerçek Ollama | `test_ai_live.py` | `ai status/explain/ask` küçük bir modelle | CI (`PULSEOPS_TEST_OLLAMA_MODEL`) |

Yerelde Docker varsa dağıtım matrisi:

```bash
PULSEOPS_TEST_DISTROS="ubuntu:24.04 debian:12 alpine:3.20" pytest tests/test_distros.py
PULSEOPS_FUZZ_EXAMPLES=5000 pytest tests/test_fuzz_probe.py
```

## Kurallar

- Sunucuda çalışan her şey **salt-okunur** olmalı; yeni bir probe bölümü eklerken `pulseops probe` çıktısını
  kontrol edin, koruma testi geçmeli. Paket yöneticileri yalnızca simülasyon/önbellek modunda çalışır.
- Okunamayan veri **bilinmiyor** olarak modellenir (`known`, `None`), asla "sorun yok" olarak değil.
- Sunucudan gelen metin güvenilmezdir: tablolar `ui/safe.py`'deki `PlainTable`, bildirimler `markup=False`,
  rapor `_md()` kaçışlaması kullanır. Sayıları `isdecimal()` ve sonlu kontrolüyle ayrıştırın.
- Yeni bir ayar eklediğinizde `docs/configuration.md` (`pulseops config` çıktısı) ve paketlerle dağıtılan
  `packaging/config.example.toml` (`pulseops config --init` şablonu) dosyalarını yenileyin; testler ikisinin de
  koddan sapmadığını kontrol eder; ikisini birden `python scripts/update_config_docs.py` yeniler.

## Yayın süreci

1. `pulseops/version.py` sürümünü artırın, `main`'e gönderin.
2. Actions → **Build and Release Binaries** → `tag` girdisiyle çalıştırın (ör. `v1.4.0`). Etiket `version.py` ile
   eşleşmezse yayın reddedilir.
3. İş akışı: testler → Linux binary (AlmaLinux 8 / glibc 2.28, smoke test) → `.deb`/`.rpm` (nfpm; `.deb` gerçekten
   `apt` ile kurulup test edilir) → Windows/macOS binary → SHA-256 dosyalarıyla GitHub Release.

`tag` boş bırakılırsa her şey derlenip test edilir ama yayın oluşturulmaz (kuru çalıştırma).
