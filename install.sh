#!/usr/bin/env bash
set -e

REPO="${GITHUB_REPOSITORY:-Morendais/mcp-audit}"
VERSION="0.2.0"

echo -e "\033[1;36m==>\033[0m Installing \033[1mmcpaudit\033[0m v${VERSION}..."

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    ARCH="amd64"
    ;;
  arm64|aarch64)
    ARCH="arm64"
    ;;
  *)
    echo "Unsupported architecture: $ARCH"
    exit 1
    ;;
esac

case "$OS" in
  linux|darwin)
    ;;
  *)
    echo "Unsupported operating system: $OS"
    exit 1
    ;;
esac

DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/mcpaudit_v${VERSION}_${OS}_${ARCH}.tar.gz"

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "\033[1;34m-->\033[0m Fetching ${OS}/${ARCH} release package..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/mcpaudit.tar.gz"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$TMP_DIR/mcpaudit.tar.gz" "$DOWNLOAD_URL"
else
  echo "Error: curl or wget required"
  exit 1
fi

tar -xzf "$TMP_DIR/mcpaudit.tar.gz" -C "$TMP_DIR"
install -m 755 "$TMP_DIR/mcpaudit" "$INSTALL_DIR/mcpaudit"

echo -e "\033[1;32m✔ Successfully installed mcpaudit to ${INSTALL_DIR}/mcpaudit\033[0m"

# Verify PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  echo -e "\033[33mWarning: ${INSTALL_DIR} is not in your \$PATH.\033[0m"
  echo "Add it to your shell profile:"
  echo "  export PATH=\"\$PATH:${INSTALL_DIR}\""
fi

echo
echo -e "\033[1;37mRun zero-config audit:\033[0m"
echo "  mcpaudit"
