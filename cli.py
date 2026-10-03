import sys
import argparse
import platform
import getpass

from collectors.base import LocalLiveCollector, DemoCollector
from ui.app import ServerTUIApp

def main():
    parser = argparse.ArgumentParser(
        description="PulseOps (PulseTUI): Agentless Real-Time Server, Web & Infrastructure Observability TUI"
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Uzak sunucu hedefi (örn: root@192.168.1.100 veya 192.168.1.100 veya demo)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Simülasyon / Demo modunu başlatır (Örnek verilerle)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Doğrudan yerel makine verilerini çeker",
    )
    parser.add_argument(
        "--ssh", "--host",
        dest="host",
        type=str,
        help="Uzak Linux sunucusuna SSH üzerinden bağlanır (örn: root@192.168.1.100 veya 192.168.1.100)",
    )
    parser.add_argument(
        "-u", "--user",
        type=str,
        default=None,
        help="SSH kullanıcı adı (varsayılan: root)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=22,
        help="SSH port numarası (varsayılan: 22)",
    )
    parser.add_argument(
        "-k", "--key",
        type=str,
        help="SSH özel anahtar dosyası yolu (örn: ~/.ssh/id_rsa veya id_ed25519)",
    )
    parser.add_argument(
        "-P", "--password",
        type=str,
        help="SSH giriş şifresi (özel anahtar kullanılmıyorsa)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.5,
        help="Metrik yenileme aralığı (saniye cinsinden, varsayılan: 1.5)",
    )

    args = parser.parse_args()

    # Determine target from positional or flags
    ssh_target = args.host or args.target
    if ssh_target in ("demo", "mock"):
        args.demo = True
        ssh_target = None
    elif ssh_target in ("live", "local"):
        args.live = True
        ssh_target = None

    if ssh_target:
        from collectors.ssh_collector import SSHCollector
        ssh_target = ssh_target.strip()
        if "@" in ssh_target:
            username, host = ssh_target.split("@", 1)
        else:
            username, host = (args.user or "root"), ssh_target
            
        if args.user:
            username = args.user

        password = args.password
        key_filename = args.key

        # Interactive password prompt if not provided and no key specified
        if not password and not key_filename:
            try:
                pwd_input = getpass.getpass(f"🔑 {username}@{host} için SSH Şifresi (Varsayılan anahtarı denemek için Enter): ")
                if pwd_input.strip():
                    password = pwd_input.strip()
            except (KeyboardInterrupt, EOFError):
                print("\nİptal edildi.")
                sys.exit(0)

        print(f"🔗 Uzak Linux sunucusuna bağlanılıyor: {username}@{host}:{args.port}...")
        collector = SSHCollector(
            host=host,
            username=username,
            port=args.port,
            key_filename=key_filename,
            password=password,
        )

        # Pre-flight connection test
        try:
            collector.test_connection()
            print("✓ SSH Bağlantısı başarılı! Sistem telemetrisi toplanıyor...")
        except Exception as e:
            print(f"\n❌ [HATA] Sunucuya SSH ile bağlanılamadı:\n   {e}\n")
            print("💡 Olası Nedenler:")
            print(f"   1. {host}:{args.port} adresine erişim engellenmiş veya port kapalı olabilir.")
            print(f"   2. '{username}' kullanıcısı için şifre veya anahtar reddedildi.")
            print("   3. Sunucudaki güvenlik duvarı (UFW / iptables) bağlantıyı kısıtlıyor olabilir.")
            sys.exit(1)

    elif args.demo:
        collector = DemoCollector()
    elif args.live:
        collector = LocalLiveCollector()
    else:
        # Auto-detect: if on Windows, default to demo mode unless --live is passed
        if platform.system() == "Windows":
            print("💡 Bilgi: Windows ortamı algılandı. Gerçekçi simülasyon (Demo Modu) başlatılıyor...")
            print("   (Uzak Linux sunucusu için: .\\run.ps1 root@sunucu-ip)")
            print("   (veya: .\\run.ps1 --host sunucu-ip -u root)")
            collector = DemoCollector()
        else:
            collector = LocalLiveCollector()

    app = ServerTUIApp(collector=collector, poll_interval=args.interval)
    app.run()

if __name__ == "__main__":
    main()
