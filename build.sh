#!/usr/bin/env bash
set -e

echo "⚡ PulseOps Standalone Binary Derleniyor (Linux/macOS)..."

if ! command -v pyinstaller &> /dev/null; then
    echo "📦 PyInstaller yükleniyor..."
    pip install pyinstaller
fi

echo "🔨 PyInstaller çalıştırılıyor..."
pyinstaller --noconfirm --clean --onefile --name pulseops --collect-all textual --add-data "ui/styles.tcss:ui" cli.py

echo "✓ Derleme başarıyla tamamlandı!"
echo "Çıktı: dist/pulseops"
