#!/bin/bash

set -e

VERSION="v1.0.0"
APP="tymley"

BUILD_DIR="$HOME/scripts/projects/tymley/build"
mkdir -p "$BUILD_DIR"

echo "======================================"
echo " Building $APP $VERSION"
echo "======================================"

echo "Cleaning old builds..."
rm -f "$BUILD_DIR"/* || true

# Ensure dependencies are clean
go mod tidy

# Linux
echo "Building Linux..."
GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/${APP}-${VERSION}-linux" .

# Windows
echo "Building Windows..."
GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/${APP}-${VERSION}-windows.exe" .

# macOS (Intel)
echo "Building macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/${APP}-${VERSION}-mac-amd64" .

# macOS (Apple Silicon)
echo "Building macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -o "$BUILD_DIR/${APP}-${VERSION}-mac-arm64" .

echo ""
echo "Creating checksums..."

cd "$BUILD_DIR"
sha256sum * > checksums.txt

echo ""
echo "Build complete:"
ls -lh "$BUILD_DIR"
