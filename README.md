<div align="center">
  <img src="https://raw.githubusercontent.com/rokibulroni/Databreach-Finder/main/sss.png" alt="Databreach Finder Logo" width="200" />
  <h1>🔍 Databreach Finder Pro</h1>
  
  <p><b>Next-Generation, Fully Automated OSINT Engine for Deep & Surface Web Leaks</b></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.11+-blue.svg?style=for-the-badge&logo=python" alt="Python Version">
    <img src="https://img.shields.io/badge/Status-Active-success.svg?style=for-the-badge" alt="Status">
    <img src="https://img.shields.io/badge/Docker-Supported-2496ED.svg?style=for-the-badge&logo=docker" alt="Docker Supported">
    <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License">
  </p>
</div>

<br/>

## 📖 Overview

**Databreach Finder Pro (v4.0)** is an enterprise-grade open-source intelligence (OSINT) tool engineered for security researchers, penetration testers, and threat intelligence analysts. It completely automates the process of dorking, scraping, downloading, and extracting highly sensitive data from dozens of paste sites simultaneously.

Built on top of a lightning-fast asynchronous `aiohttp` engine, it features real-time webhooks, Tor network anonymization, and smart deduplication via SQLite.

<details>
<summary><b>📑 Table of Contents (Click to expand)</b></summary>

- [✨ Enterprise Features](#-enterprise-features)
- [🛠️ Installation](#️-installation)
- [💻 Usage Guide](#-usage-guide)
- [🧠 Advanced Configuration](#-advanced-configuration)
- [⚠️ Disclaimer](#️-disclaimer)

</details>

---

## ✨ Enterprise Features

| Feature | Description |
| :--- | :--- |
| ⚡ **Asynchronous Engine** | Powered by `asyncio` and `aiohttp`. Scrape and download dozens of URLs concurrently without CPU blocking. |
| 🗄️ **SQLite Persistence** | All findings are permanently stored in a local `databreach.db`. |
| 🧠 **Smart De-duplication** | Filters out duplicate records across multiple scans to eliminate alert fatigue. |
| 🐳 **Dockerized** | Spin up the tool and an isolated Tor proxy with a single `docker-compose` command. |
| 🕵️ **Tor Anonymization** | Use `--tor` to route traffic through SOCKS5, preventing IP bans. |
| 🔔 **Real-Time Webhooks** | Get instant notifications on **Discord** or **Telegram** when leaks are found. |
| 📊 **HTML Reporting** | Generate pristine, client-ready HTML reports using `--report html`. |

### 🧬 Advanced Regex Engine
Automatically extracts and flags the following targets out of the box:
> `Emails` • `Credit Cards` • `IPv4` • `BTC/ETH Wallets` • `AWS API Keys` • `JWT Tokens` • `RSA Private Keys`

---

## 🛠️ Installation

### 🐳 Option 1: Docker (Recommended)
The cleanest way to run the tool without polluting your local environment.
```bash
# Start the Tor Proxy in the background
docker-compose up -d tor

# Run the Databreach Finder
docker-compose run databreach-finder -q "target_company" --extract emails --tor
```

### 💻 Option 2: Native Python
Ensure you have Python 3.11+ installed.
```bash
git clone https://github.com/rokibulroni/Databreach-Finder.git
cd Databreach-Finder

# Create a virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage Guide

The tool comes with a beautiful CLI interface powered by `rich`. 

### Basic Search
Hunt for a keyword and extract any lines containing it:
```bash
python3 databreach_finder.py --query "example.com"
```

### Targeted Regex Extraction
Find specific data patterns (e.g., AWS Keys) related to your target:
```bash
python3 databreach_finder.py --query "company dump" --extract aws_key
```

### Stealth Mode (Tor Routing)
*Requires Tor running locally on port 9050, or via Docker.*
```bash
python3 databreach_finder.py --query "target" --extract btc --tor
```

### Generate HTML Report
```bash
python3 databreach_finder.py --query "example.com" --extract emails --report html
```

---

## 🧠 Advanced Configuration

Databreach Finder Pro supports zero-code customization. Simply rename `config.json.example` to `config.json` to:
1. **Add Custom Paste Sites:** Append specific deep web or surface web URLs.
2. **Add Custom Regex Patterns:** Hunt for your own proprietary keys.
3. **Configure Webhooks:** Add your Discord Webhook URL or Telegram Bot Token for real-time alerting.

---

## ⚠️ Disclaimer

<div align="center">
  <b>This tool is built for educational purposes and authorized security research ONLY.</b><br>
  The author is not responsible for any misuse, damage, or illegal activities conducted with this tool. Do not use this tool to access or exploit data you do not own.
</div>

<br>

<div align="center">
  Made with ❤️ by <a href="https://chat.rokibulroni.com">Rokibul Roni</a>
</div>
