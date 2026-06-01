#!/bin/bash

set -e

VERSION="v1.0.0"
APP="runtimeguard"

BUILD_DIR="$HOME/scripts/projects/runxguardstucli/build"
mkdir -p "$BUILD_DIR"

echo "======================================"
echo " Building $APP $VERSION"
echo "======================================"

# Linux
echo "Building Linux..."
GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/${APP}-${VERSION}-linux" .

# Windows
echo "Building Windows..."
GOOS=windows GOARCH=amd64 go build -o "$BUILD_DIR/${APP}-${VERSION}-windows.exe" .

# Mac
echo "Building macOS..."
GOOS=darwin GOARCH=amd64 go build -o "$BUILD_DIR/${APP}-${VERSION}-mac" .

echo ""
echo "Creating checksums..."

cd "$BUILD_DIR"
sha256sum * > checksums.txt

echo ""
echo "Build complete:"
ls -lh "$BUILD_DIR"
