#!/bin/bash

# =========================================
# RuntimeGuard Full Setup Script for Linux
# =========================================
# Author: Antonio Kione
# Purpose: One-shot installation and setup for RuntimeGuard CLI
# =========================================

set -e

echo "🔹 Starting RuntimeGuard setup..."

# =========================================
# 1️⃣ Install Go
# =========================================

GO_VERSION="1.26.1"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

echo "➡️ Installing Go ${GO_VERSION}..."

wget -q $GO_URL -O /tmp/$GO_TAR

sudo rm -rf /usr/local/go

sudo tar -C /usr/local -xzf /tmp/$GO_TAR

if ! grep -q "/usr/local/go/bin" ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
fi

export PATH=$PATH:/usr/local/go/bin

echo "✅ Go installed:"
go version

# =========================================
# 2️⃣ Clone RuntimeGuard Repository
# =========================================

REPO_DIR="$HOME/scripts/projects/runxguardstucli"

if [ ! -d "$REPO_DIR" ]; then

    echo "➡️ Cloning RuntimeGuard repository..."

    mkdir -p "$(dirname "$REPO_DIR")"

    git clone https://github.com/<your-user>/runxguardstucli.git "$REPO_DIR"

else

    echo "➡️ RuntimeGuard directory exists, pulling latest updates..."

    cd "$REPO_DIR"

    git pull
fi

cd "$REPO_DIR"

# =========================================
# 3️⃣ Build RuntimeGuard
# =========================================

echo "➡️ Building RuntimeGuard..."

go mod tidy

go build -o runtimeguard .

echo "✅ Build complete"

# =========================================
# 4️⃣ Create RuntimeGuard Config
# =========================================

echo "➡️ Creating RuntimeGuard config..."

mkdir -p ~/.runtimeguard

CONFIG_FILE="$HOME/.runtimeguard/runtimeguard.json"

if [ ! -f "$CONFIG_FILE" ]; then

cat > "$CONFIG_FILE" <<EOF
{
  "watch_dirs": [
    "/tmp",
    "/home"
  ],

  "suspicious_extensions": [
    ".sh",
    ".py",
    ".elf",
    ".bin",
    ".ps1"
  ],

  "suspicious_processes": [
    "nc",
    "netcat",
    "ncat",
    "hydra"
  ],

  "ignored_paths": [
    "/proc",
    "/sys",
    "/dev"
  ]
}
EOF

echo "✅ Default config created"

else

    echo "ℹ️ Config already exists"

fi

# =========================================
# 5️⃣ Create HELP.md
# =========================================

HELP_FILE="$HOME/.runtimeguard/HELP.md"

if [ ! -f "$HELP_FILE" ]; then

cat > "$HELP_FILE" <<EOF
# RuntimeGuard Configuration Guide

## watch_dirs
Directories monitored for filesystem activity.

Examples:
- /tmp
- /home

---

## suspicious_extensions
Common extensions associated with malware or scripts.

Examples:
- .sh   (shell scripts)
- .elf  (Linux binaries)
- .ps1  (PowerShell malware)
- .bin  (payloads/loaders)

---

## suspicious_processes
Potentially suspicious tools/processes.

Examples:
- nc
- netcat
- hydra
- ncat

---

## ignored_paths
Directories excluded from monitoring.

Examples:
- /proc
- /sys
- /dev
EOF

echo "✅ HELP.md created"

fi

# =========================================
# 6️⃣ Setup Baseline
# =========================================

echo "➡️ Setting up baseline..."

if [ -f "$REPO_DIR/runtimeguard_baseline.json" ]; then

    cp "$REPO_DIR/runtimeguard_baseline.json" ~/.runtimeguard/baseline.json

    echo "✅ Baseline file copied"

else

    echo "⚠️ No baseline file found"
    echo "➡️ Generate one using:"
    echo "   runtimeguard init"

fi

# =========================================
# 7️⃣ Install Globally
# =========================================

echo "➡️ Installing RuntimeGuard globally..."

sudo cp runtimeguard /usr/local/bin/runtimeguard

sudo chmod +x /usr/local/bin/runtimeguard

echo "✅ RuntimeGuard installed globally"

# =========================================
# 8️⃣ Test Installation
# =========================================

echo "➡️ Testing RuntimeGuard..."

runtimeguard help

echo ""
echo "🎉 RuntimeGuard setup completed successfully!"
echo ""
echo "Start monitoring with:"
echo "runtimeguard monitor"
