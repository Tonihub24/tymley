#!/bin/bash

set -e

# Detect OS + ARCH
OS=$(uname -s)
ARCH=$(uname -m)

APP="runxguard"
REPO="Tonihub24/RunxGuard"

if [[ "$OS" != "Linux" ]]; then
  echo "❌ Only Linux supported for now"
  exit 1
fi

# Map architecture (future-proof)
if [[ "$ARCH" == "x86_64" ]]; then
  ARCH="amd64"
elif [[ "$ARCH" == "aarch64" ]]; then
  ARCH="arm64"
else
  echo "❌ Unsupported architecture: $ARCH"
  exit 1
fi

INSTALL_DIR="/usr/local/bin"
BINARY_NAME="${APP}"

echo "[+] Detecting system: $OS/$ARCH"

echo "[+] Downloading latest release..."

URL="https://github.com/$REPO/releases/latest/download/${APP}-${OS}-${ARCH}"

curl -L -o $BINARY_NAME "$URL"

echo "[+] Making executable..."
chmod +x $BINARY_NAME

echo "[+] Installing to $INSTALL_DIR..."
sudo mv $BINARY_NAME $INSTALL_DIR/

echo "[+] Installed successfully!"
echo "[+] Run: runxguard watch"
