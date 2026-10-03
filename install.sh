#!/usr/bin/env bash
set -e

echo "⚡ PulseOps Otomatik Kurulumu Başlatılıyor..."

# 1. Check Python3
if ! command -v python3 &> /dev/null; then
    echo "❌ HATA: python3 bulunamadı. Lütfen önce python3 kurun (örn: sudo apt install python3 python3-venv)."
    exit 1
fi

REPO_URL="${PULSEOPS_REPO:-https://github.com/salihoglueyup/PulseOPS.git}"

# 2. Check if pipx is available, use pipx if present
if command -v pipx &> /dev/null; then
    echo "📦 pipx bulundu, izole ortamda kuruluyor..."
    pipx install --force "git+$REPO_URL"
    pipx ensurepath
    echo ""
    echo "✓ Kurulum tamamlandı!"
    echo "⚡ Mevcut terminalinizde hemen çalıştırmak için:"
    echo "   source ~/.bashrc && pulseops"
    echo "   (veya doğrudan: ~/.local/bin/pulseops)"
    echo "Yeni açacağınız tüm terminallerde artık doğrudan 'pulseops' yazabilirsiniz!"
    exit 0
fi

# 3. Otherwise, set up an isolated venv in ~/.local/share/pulseops (PEP 668 uyumlu)
INSTALL_DIR="$HOME/.local/share/pulseops"
BIN_DIR="$HOME/.local/bin"

echo "📦 İzole ortam hazırlanıyor: $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR" "$BIN_DIR"

python3 -m venv "$INSTALL_DIR/venv" || {
    echo "❌ HATA: python3-venv paketi eksik olabilir. Lütfen 'sudo apt install python3-venv' veya 'sudo apt install python3-full' çalıştırın."
    exit 1
}

echo "⬇️ PulseOps indiriliyor ve kuruluyor ($REPO_URL)..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install --upgrade "git+$REPO_URL" --quiet

# 4. Create symlink in ~/.local/bin
ln -sf "$INSTALL_DIR/venv/bin/pulseops" "$BIN_DIR/pulseops"
ln -sf "$INSTALL_DIR/venv/bin/pulsetui" "$BIN_DIR/pulsetui"

# 5. Check if ~/.local/bin is in PATH
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
    SHELL_RC="$HOME/.bashrc"
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    fi
    echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    echo "ℹ️ $BIN_DIR PATH değişkenine eklendi ($SHELL_RC)."
    echo "Lütfen 'source $SHELL_RC' çalıştırın veya terminali kapatıp açın."
fi

echo ""
echo "🎉 TEBRİKLER! PulseOps başarıyla kuruldu."
echo "Çalıştırmak için doğrudan:"
echo "  pulseops"
echo "veya"
echo "  pulseops --live"
echo "yazabilirsiniz!"
