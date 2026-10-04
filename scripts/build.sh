#!/usr/bin/env bash
set -e
cd "$(dirname "$0")/.."

echo "⚡ PulseOps Standalone Binary Derleniyor (Linux/macOS)..."

if ! command -v pyinstaller &> /dev/null; then
    echo "📦 PyInstaller yükleniyor..."
    pip install pyinstaller
fi

echo "🔨 PyInstaller çalıştırılıyor..."
pyinstaller --noconfirm --clean --onefile --name pulseops --collect-all textual --add-data "pulseops/ui/styles.tcss:pulseops/ui" packaging/pyinstaller_entry.py

echo "✓ Derleme başarıyla tamamlandı!"
echo "Çıktı: dist/pulseops"
