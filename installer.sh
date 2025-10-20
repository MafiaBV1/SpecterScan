#!/usr/bin/env bash
set -euo pipefail

echo "[*] SpecterScan installer — Kali/Ubuntu/Debian"

# --- 0) location sanity
ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT_DIR"

# --- 1) packages
if command -v apt >/dev/null 2>&1; then
  echo "[*] Using apt..."
  sudo apt update -y
  sudo apt install -y \
    python3 python3-venv python3-pip git curl \
    nmap whatweb nikto gobuster ffuf masscan hydra sqlmap wpscan \
    dnsutils # dig
else
  echo "[!] apt not found. Please install deps manually for your distro."
  exit 1
fi

# --- 2) optional venv (comment out if you prefer system python)
if [ ! -d ".venv" ]; then
  echo "[*] Creating Python venv ./.venv"
  python3 -m venv .venv
fi
echo "[*] Upgrading pip"
. .venv/bin/activate
pip install --upgrade pip

# --- 3) wordlists (curated SecLists snippets)
mkdir -p wordlists
download() {
  local out="$1" url="$2"
  if [ -s "wordlists/$out" ]; then
    echo "[=] wordlists/$out exists"
  else
    echo "[*] downloading $out"
    curl -sSL -o "wordlists/$out" "$url"
  fi
}

download "subdomains-top1k.txt" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1k.txt"
download "usernames-top1k.txt"  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt"
download "passwords-10k.txt"    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"

echo "[*] Wordlists ready:"
ls -lh wordlists

# --- 4) final tips
echo
echo "[+] Install complete."
echo "   • Activate venv:   source .venv/bin/activate"
echo "   • Enable aggressive: export ADVSCAN_ALLOW_AGGRESSIVE=1"
echo "   • Run:              python3 specterscan.py"
