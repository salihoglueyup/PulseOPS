#!/usr/bin/env bash
# PulseOps installer for Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/salihoglueyup/PulseOPS/main/install.sh | bash
#
# Environment variables:
#   PULSEOPS_INSTALL_METHOD  auto (default) | binary | source
#   PULSEOPS_REPO_SLUG       GitHub owner/repo (default: salihoglueyup/PulseOPS)
#   PULSEOPS_RELEASE_URL     Binary download base URL (default: latest GitHub release)
set -euo pipefail

REPO_SLUG="${PULSEOPS_REPO_SLUG:-salihoglueyup/PulseOPS}"
METHOD="${PULSEOPS_INSTALL_METHOD:-auto}"
ASSET="pulseops-linux-amd64"
RELEASE_URL="${PULSEOPS_RELEASE_URL:-https://github.com/${REPO_SLUG}/releases/latest/download}"
REPO_URL="https://github.com/${REPO_SLUG}.git"
TMP_DIR=""
trap 'if [ -n "$TMP_DIR" ]; then rm -rf "$TMP_DIR"; fi' EXIT

info() { echo "$@"; }
fail() { echo "❌ HATA: $*" >&2; exit 1; }

if [ "$(uname -s)" != "Linux" ]; then
    fail "PulseOps yalnızca Linux'u destekler (algılanan: $(uname -s))."
fi

if [ "$(id -u)" -eq 0 ]; then
    BIN_DIR="/usr/local/bin"
else
    BIN_DIR="$HOME/.local/bin"
fi

download() {
    # download <url> <output-file>
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$2" "$1"
    else
        return 1
    fi
}

link_globally() {
    # Makes `pulseops` available immediately, without reopening the terminal
    local exe="$1"
    [ "$BIN_DIR" = "/usr/local/bin" ] && return 0
    if [ -w /usr/local/bin ]; then
        ln -sf "$exe" /usr/local/bin/pulseops
        ln -sf "$exe" /usr/local/bin/pulsetui
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        sudo ln -sf "$exe" /usr/local/bin/pulseops
        sudo ln -sf "$exe" /usr/local/bin/pulsetui
    elif [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
        local rc="$HOME/.bashrc"
        [ -f "$HOME/.zshrc" ] && rc="$HOME/.zshrc"
        echo "export PATH=\"$BIN_DIR:\$PATH\"" >> "$rc"
        info "ℹ️  $BIN_DIR PATH'e eklendi ($rc). Yeni bir terminal açın veya: source $rc"
    fi
}

install_binary() {
    if [ "$(uname -m)" != "x86_64" ]; then
        info "ℹ️  Hazır binary yalnızca x86_64 için var (algılanan: $(uname -m))."
        return 1
    fi
    command -v sha256sum >/dev/null 2>&1 || { info "ℹ️  sha256sum bulunamadı, binary doğrulanamaz."; return 1; }

    TMP_DIR="$(mktemp -d)"
    local tmp="$TMP_DIR"

    info "⬇️  Hazır binary indiriliyor (${REPO_SLUG})..."
    if ! download "${RELEASE_URL}/${ASSET}" "$tmp/$ASSET" || ! download "${RELEASE_URL}/${ASSET}.sha256" "$tmp/$ASSET.sha256"; then
        info "ℹ️  Release bulunamadı veya indirilemedi."
        return 1
    fi

    local expected actual
    expected="$(cut -d' ' -f1 < "$tmp/$ASSET.sha256")"
    actual="$(sha256sum "$tmp/$ASSET" | cut -d' ' -f1)"
    if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
        fail "SHA-256 doğrulaması başarısız! Beklenen: ${expected:-yok}, indirilen: $actual"
    fi
    info "✓ SHA-256 doğrulandı."

    chmod +x "$tmp/$ASSET"
    if ! "$tmp/$ASSET" --version >/dev/null 2>&1; then
        info "ℹ️  Binary bu sistemde çalışmadı (eski glibc olabilir)."
        return 1
    fi

    mkdir -p "$BIN_DIR"
    install -m 755 "$tmp/$ASSET" "$BIN_DIR/pulseops"
    ln -sf "$BIN_DIR/pulseops" "$BIN_DIR/pulsetui"
    link_globally "$BIN_DIR/pulseops"
    return 0
}

install_source() {
    command -v python3 >/dev/null 2>&1 || fail "python3 bulunamadı. Önce kurun (örn: sudo apt install python3 python3-venv)."
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
        || fail "Python 3.10+ gerekli (bulunan: $(python3 --version 2>&1))."

    if command -v pipx >/dev/null 2>&1; then
        info "📦 pipx ile izole kurulum yapılıyor..."
        pipx install --force "git+$REPO_URL"
        link_globally "$HOME/.local/bin/pulseops"
        return 0
    fi

    local install_dir="$HOME/.local/share/pulseops"
    info "📦 İzole ortam hazırlanıyor: $install_dir"
    mkdir -p "$install_dir" "$HOME/.local/bin"
    python3 -m venv "$install_dir/venv" \
        || fail "python3-venv eksik olabilir: 'sudo apt install python3-venv' çalıştırın."
    "$install_dir/venv/bin/pip" install --upgrade pip --quiet
    "$install_dir/venv/bin/pip" install --upgrade "git+$REPO_URL" --quiet

    ln -sf "$install_dir/venv/bin/pulseops" "$HOME/.local/bin/pulseops"
    ln -sf "$install_dir/venv/bin/pulsetui" "$HOME/.local/bin/pulsetui"
    BIN_DIR="$HOME/.local/bin"
    link_globally "$install_dir/venv/bin/pulseops"
}

info "⚡ PulseOps kurulumu başlatılıyor..."
case "$METHOD" in
    binary) install_binary || fail "Binary kurulumu başarısız." ;;
    source) install_source ;;
    auto)
        if ! install_binary; then
            info "↪️  Kaynak koddan kuruluma geçiliyor..."
            install_source
        fi
        ;;
    *) fail "Geçersiz PULSEOPS_INSTALL_METHOD: $METHOD (auto | binary | source)" ;;
esac

echo ""
echo "🎉 PulseOps kuruldu. Başlatmak için:"
echo "  pulseops            # bu sunucuyu canlı izle"
echo "  sudo pulseops       # tam görünüm (tüm süreçler, güvenlik duvarı, docker)"
echo "  pulseops status     # TUI açmadan özet"
echo "  pulseops --help     # tüm komutlar"
