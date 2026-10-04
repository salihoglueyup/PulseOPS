# Kurulum

PulseOps Linux sunucular (x86_64) için tasarlanmıştır. Hedef sunucuya kalıcı bir servis kurulmaz; kurduğunuz şey
yalnızca `pulseops` komutudur.

## Tek komutla kurulum (önerilen)

Sunucuya SSH ile bağlanıp:

```bash
curl -fsSL https://raw.githubusercontent.com/salihoglueyup/PulseOPS/main/install.sh | bash
```

Kurulum betiği:

1. Son sürümün hazır binary'sini indirir ve **SHA-256** ile doğrular. Python gerekmez; glibc 2.28+ yeterlidir
   (Ubuntu 20.04+, Debian 10+, RHEL/Alma/Rocky 8+).
2. Binary indirilemez veya çalışmazsa Python 3.10+ ile izole bir sanal ortama (`~/.local/share/pulseops/venv`)
   kaynak koddan kurar.
3. `root` olarak çalıştırıldıysa `/usr/local/bin`, değilse `~/.local/bin` altına kurar.

Ortam değişkenleri: `PULSEOPS_INSTALL_METHOD=binary|venv` yöntemi zorlar, `PULSEOPS_RELEASE_URL` farklı bir yayın
adresi verir.

## Paketlerle kurulum

[Releases](https://github.com/salihoglueyup/PulseOPS/releases/latest) sayfasındaki paketlerin tek bağımlılığı
glibc 2.28+'dır:

```bash
sudo apt install ./pulseops_<sürüm>-1_amd64.deb          # Debian / Ubuntu
sudo dnf install ./pulseops-<sürüm>-1.x86_64.rpm         # RHEL / Alma / Rocky / Fedora
```

Paket `/usr/bin/pulseops` (ve `pulsetui` kısayolu) kurar; örnek yapılandırma ve belgeler
`/usr/share/doc/pulseops/` altındadır. Paketle kurulduğunda güncelleme ve kaldırma paket yöneticisiyle yapılır.

## Güncelleme ve kaldırma

```bash
pulseops version      # sürüm ve kurulum türü: binary | venv | pipx | package | source
pulseops update       # en son sürüme güncelle (binary: SHA-256 doğrulamalı, atomik değişim)
pulseops uninstall    # kaldır (onay ister; -y ile sormadan)
```

`pulseops update` kurulum türüne göre doğru yolu seçer; paketle kurulmuşsa `apt`/`dnf` komutunu söyler.

## Kaynak koddan (geliştirme)

```bash
git clone https://github.com/salihoglueyup/PulseOPS.git
cd PulseOPS
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pulseops --demo          # veya: python -m pulseops --demo
```

Ayrıntılar: [Geliştirme](development.md).

## Diğer platformlar

Windows ve macOS için de binary yayınlanır (`pulseops-windows-amd64.exe`, `pulseops-macos-arm64`); bunlar
öncelikle **uzak Linux sunucularını SSH ile izlemek** ve `--demo` için kullanılır. Yerel izleme Linux içindir.
Windows yardımcı betikleri `scripts/` altındadır.
