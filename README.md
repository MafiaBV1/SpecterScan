![SpecterScan Banner](./banner.svg)

# SpecterScan

**Safe, lab-first reconnaissance toolkit — non-destructive by default.**

SpecterScan is a modular reconnaissance helper designed for **ethical hacking labs**, **CTF environments**, and **authorized penetration testing**.  
Built initially under WSL, it runs seamlessly on **Kali Linux**, **Ubuntu**, and other Debian-based distributions.

> ⚠️ **Important:** Only run SpecterScan against targets you have explicit written permission to test.  
> Unauthorized scanning is illegal and unethical. Always operate within your local laws and testing agreements.

---

## 🧠 Features

- 🕵️ **Recon Automation** – Automates common enumeration steps using trusted CLI tools (`nmap`, `whois`, `sublist3r`, etc.).
- 🧩 **Cross-Platform** – Works on WSL, Kali Linux, and most Debian-based systems.
- ⚙️ **Modular Design** – Easily expand with new commands or scanning modules.
- 🧱 **Safe by Default** – `--dry-run` mode and non-destructive defaults prevent accidental impact.
- 🧰 **Tool Awareness** – Detects which scanning tools are installed and adjusts behavior automatically.
- 🖥️ **Readable Output** – Creates organized log files and clearly labeled results in the `outputs/` folder.
- 🪶 **Lightweight** – No heavy frameworks or dependencies; pure Python and system binaries.

---

## 🚀 Quick Start

### 🔧 Install Required Tools
Make sure the common recon utilities are installed and accessible in your `$PATH`.

```bash 
sudo apt update && sudo apt install -y nmap whois dig sublist3r
# Optional extras
sudo apt install -y masscan nikto dirb whatweb

## Quick setup

# one-time
./installer.sh
source .venv/bin/activate

# run (non-aggressive)
python3 specterscan.py

# run aggressive: you must have authorization
export ADVSCAN_ALLOW_AGGRESSIVE=1
python3 specterscan.py
# when asked for wordlists, just press Enter — SpecterScan will auto-select from ./wordlists


---

## sanity checklist

- ✅ `installer.sh` exists in repo root and is executable.  
- ✅ running it on Kali creates `.venv/` and `wordlists/` with 3 curated lists.  
- ✅ after the user types the **consent phrase**, `ensure_curated_wordlists()` runs once if the folder is empty.  
- ✅ at each prompt (gobuster/ffuf/dirbuster/hydra), pressing **Enter** auto-selects a sensible file—no path hunting.  
- ✅ tools installed: nmap, whatweb, nikto, gobuster, ffuf, masscan, hydra, sqlmap, wpscan, dig.

if you want, paste the specific prompt lines from your `specterscan.py` and I’ll reply with the **exact replacements** for those spots so you can copy/paste without hunting.
::contentReference[oaicite:0]{index=0}


