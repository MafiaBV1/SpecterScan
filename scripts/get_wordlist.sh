#!/usr/bin/env bash
set -euo pipefail
OUT="wordlists"
mkdir -p "$OUT"
echo "[*] Downloading curated wordlists into $OUT ..."

curl -sSL -o "$OUT/subdomains-top1k.txt" \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1k.txt"

curl -sSL -o "$OUT/usernames-top1k.txt" \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt"

curl -sSL -o "$OUT/passwords-10k.txt" \
  "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt"

echo "[+] Done. Wordlists saved to $OUT"
ls -lh "$OUT"
