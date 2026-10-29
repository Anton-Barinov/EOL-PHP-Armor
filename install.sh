#!/usr/bin/env bash
# ==============================================================================
# EOL-PHP-Armor: 1-Line Autonomous Installer
# 
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Anton-Barinov/EOL-PHP-Armor/main/install.sh | bash
#   curl -sSL https://raw.githubusercontent.com/Anton-Barinov/EOL-PHP-Armor/main/install.sh | bash -s -- --auto-protect
# ==============================================================================

set -uo pipefail

REPO="Anton-Barinov/EOL-PHP-Armor"
BRANCH="main"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/${BRANCH}"

C_RESET="\033[0m"
C_RED="\033[1;31m"
C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"
C_BLUE="\033[1;34m"
C_CYAN="\033[1;36m"
C_BOLD="\033[1m"

echo -e "\n${C_CYAN}  🛡️  EOL-PHP-Armor: Universal Security Hub & Hotpatching Engine${C_RESET}"
echo -e "  Maintainer: ${C_YELLOW}Anton Barinov${C_RESET} | GitHub: ${C_BLUE}https://github.com/${REPO}${C_RESET}\n"

# Check root or user mode
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/etc/php-armor"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "  ${C_YELLOW}Notice: Non-root user detected. Installing to user directory (~/.local/bin)...${C_RESET}"
    INSTALL_DIR="${HOME}/.local/bin"
    DATA_DIR="${HOME}/.php-armor"
    mkdir -p "${INSTALL_DIR}" "${DATA_DIR}"
fi

# Download or copy php-armor files
TMP_DIR=$(mktemp -d -t php_armor_inst_XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "  ${C_BOLD}[1/3] Downloading EOL-PHP-Armor package...${C_RESET}"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${RAW_BASE}/bin/php-armor" -o "${TMP_DIR}/php-armor" || true
    curl -fsSL "${RAW_BASE}/guard/runtime-armor.php" -o "${TMP_DIR}/runtime-armor.php" || true
    curl -fsSL "${RAW_BASE}/feed/sec-feed.json" -o "${TMP_DIR}/sec-feed.json" || true
elif command -v wget >/dev/null 2>&1; then
    wget -q "${RAW_BASE}/bin/php-armor" -O "${TMP_DIR}/php-armor" || true
    wget -q "${RAW_BASE}/guard/runtime-armor.php" -O "${TMP_DIR}/runtime-armor.php" || true
    wget -q "${RAW_BASE}/feed/sec-feed.json" -O "${TMP_DIR}/sec-feed.json" || true
fi

# If running locally from repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
if [ -n "$SCRIPT_DIR" ] && [ -f "${SCRIPT_DIR}/bin/php-armor" ]; then
    cp "${SCRIPT_DIR}/bin/php-armor" "${TMP_DIR}/php-armor"
    cp "${SCRIPT_DIR}/guard/runtime-armor.php" "${TMP_DIR}/runtime-armor.php"
    cp "${SCRIPT_DIR}/feed/sec-feed.json" "${TMP_DIR}/sec-feed.json"
fi

if [ ! -s "${TMP_DIR}/php-armor" ]; then
    echo -e "${C_RED}❌ Failed to download EOL-PHP-Armor. Check your internet connection.${C_RESET}"
    exit 1
fi

echo -e "  ${C_BOLD}[2/3] Installing CLI binary and runtime guard...${C_RESET}"
mkdir -p "${INSTALL_DIR}" "${DATA_DIR}/feed" "${DATA_DIR}/guard"
cp "${TMP_DIR}/php-armor" "${INSTALL_DIR}/php-armor"
chmod 755 "${INSTALL_DIR}/php-armor"

cp "${TMP_DIR}/runtime-armor.php" "${DATA_DIR}/guard/runtime-armor.php"
chmod 644 "${DATA_DIR}/guard/runtime-armor.php"

cp "${TMP_DIR}/sec-feed.json" "${DATA_DIR}/feed/sec-feed.json"
chmod 644 "${DATA_DIR}/feed/sec-feed.json"

echo -e "  ✓ Installed binary to: ${C_GREEN}${INSTALL_DIR}/php-armor${C_RESET}"
echo -e "  ✓ Installed runtime shield to: ${C_GREEN}${DATA_DIR}/guard/runtime-armor.php${C_RESET}"

# Ensure ~/.local/bin is in PATH if non-root
if [ "$(id -u)" -ne 0 ] && [[ ":$PATH:" != *":${INSTALL_DIR}:"* ]]; then
    echo -e "  ${C_YELLOW}Tip: Add export PATH=\"\$PATH:${INSTALL_DIR}\" to your ~/.bashrc or ~/.zshrc${C_RESET}"
fi

echo -e "\n  ${C_BOLD}[3/3] Running initial security scan...${C_RESET}\n"
"${INSTALL_DIR}/php-armor" scan

# Auto-protect if requested
if [[ "${*:-}" == *"--auto-protect"* ]] || [[ "${*:-}" == *"-y"* ]]; then
    echo -e "\n${C_BOLD}🚀 Executing automated protection...${C_RESET}"
    "${INSTALL_DIR}/php-armor" protect
fi

echo -e "\n${C_GREEN}${C_BOLD}🎉 EOL-PHP-Armor installation complete!${C_RESET}"
echo -e "Run ${C_CYAN}php-armor help${C_RESET} to view all available commands.\n"
