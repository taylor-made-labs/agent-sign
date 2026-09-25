#!/usr/bin/env bash
set -euo pipefail

echo "=========================================="
echo " Installing Agent-Sign Toolchain"
echo "=========================================="

INSTALL_DIR="$HOME/.agent-sign/bin"
KEYS_DIR="$HOME/.agent-sign/keys"

mkdir -p "$INSTALL_DIR"
mkdir -p "$KEYS_DIR"
chmod 700 "$HOME/.agent-sign"
chmod 700 "$KEYS_DIR"

echo "==> Building release binaries via Cargo..."
cargo build --release

echo "==> Installing binaries to $INSTALL_DIR..."
cp target/release/agent-signd "$INSTALL_DIR/agent-signd"
cp target/release/agent-sign "$INSTALL_DIR/agent-sign"
cp target/release/agent-git "$INSTALL_DIR/git"

chmod +x "$INSTALL_DIR/agent-signd"
chmod +x "$INSTALL_DIR/agent-sign"
chmod +x "$INSTALL_DIR/git"

echo "==> Initializing agent signing keypair..."
"$INSTALL_DIR/agent-signd" setup

echo ""
echo "=========================================="
echo " Installation Complete!"
echo "=========================================="
echo "Binaries installed to: $INSTALL_DIR"
echo ""
echo "To use with your agents, run your agent with:"
echo "  PATH=\"$INSTALL_DIR:\$PATH\" <agent-command>"
echo ""
echo "To launch the background daemon:"
echo "  $INSTALL_DIR/agent-signd &"
echo "=========================================="
