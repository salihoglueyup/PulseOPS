#!/usr/bin/env bash
set -e

echo "⚡ PulseOps Otomatik Kurulumu Başlatılıyor..."

# 1. Check Python3
if ! command -v python3 &> /dev/null; then
    echo "❌ HATA: python3 bulunamadı. Lütfen önce python3 kurun (örn: sudo apt install python3 python3-venv)."
    exit 1
fi

REPO_URL="${PULSEOPS_REPO:-https://github.com/salihoglueyup/PulseOPS.git}"
PULSEOPS_EXECUTABLE=""

# 2. Check if pipx is available, use pipx if present
if command -v pipx &> /dev/null; then
    echo "📦 pipx ile izole kurulum yapılıyor..."
    pipx install --force "git+$REPO_URL"
    pipx ensurepath
    PULSEOPS_EXECUTABLE="$HOME/.local/bin/pulseops"
else
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

    ln -sf "$INSTALL_DIR/venv/bin/pulseops" "$BIN_DIR/pulseops"
    ln -sf "$INSTALL_DIR/venv/bin/pulsetui" "$BIN_DIR/pulsetui"
    PULSEOPS_EXECUTABLE="$BIN_DIR/pulseops"

    if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        SHELL_RC="$HOME/.bashrc"
        [ -f "$HOME/.zshrc" ] && SHELL_RC="$HOME/.zshrc"
        echo "export PATH=\"\$HOME/.local/bin:\$PATH\"" >> "$SHELL_RC"
    fi
fi

# 4. Global symlink to /usr/local/bin so it works INSTANTLY without restarting terminal or sourcing
if [ -n "$PULSEOPS_EXECUTABLE" ] && [ -f "$PULSEOPS_EXECUTABLE" ]; then
    if [ -w /usr/local/bin ]; then
        ln -sf "$PULSEOPS_EXECUTABLE" /usr/local/bin/pulseops
        ln -sf "$PULSEOPS_EXECUTABLE" /usr/local/bin/pulsetui 2>/dev/null || true
    elif command -v sudo &> /dev/null; then
        echo "🔗 /usr/local/bin altına bağlanıyor (anında çalışması için)..."
        sudo ln -sf "$PULSEOPS_EXECUTABLE" /usr/local/bin/pulseops 2>/dev/null || true
        sudo ln -sf "$PULSEOPS_EXECUTABLE" /usr/local/bin/pulsetui 2>/dev/null || true
    fi
fi

echo ""
echo "🎉 TEBRİKLER! PulseOps başarıyla kuruldu."
echo "Terminalinizde doğrudan şu komutla başlatabilirsiniz:"
echo "  pulseops"
echo "veya canlı yerel izleme için:"
echo "  pulseops --live"
