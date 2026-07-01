<div align="center">
  <h1>🔍 Databreach Finder Pro [Enterprise]</h1>
  <p><b>An Advanced OSINT Tool for discovering leaked data across the Surface and Deep Web.</b></p>
</div>

## 📖 Overview
Databreach Finder Pro is an enterprise-grade automation tool designed for security researchers and penetration testers. It automates the process of finding, downloading, and extracting leaked sensitive data from various paste sites using Google Dorking.

## 🚀 Enterprise Features
- **All-in-One Python Tool:** Cross-platform support without any bash dependencies.
- **Advanced Regex Extraction:** Built-in pattern recognition for:
  - `emails`, `cards` (Credit Cards), `ipv4`
  - `btc` (Bitcoin Wallets), `eth` (Ethereum Wallets)
  - `aws_key` (Amazon AWS API Keys)
  - `jwt` (JSON Web Tokens)
  - `rsa_private` (RSA Private Keys)
- **Tor Network Routing:** Use the `--tor` flag to route all scraper traffic through the Tor network (prevents IP bans and allows anonymous scraping).
- **Custom Configuration:** Use `config.json` to add custom paste sites, your own Regex patterns, and webhook keys.
- **Real-Time Alerts:** Get notified instantly on **Discord** or **Telegram** when leaked data is found.
- **Professional Reporting:** Generate clean HTML reports (`--report html`) to present findings to clients or teams.

## 🛠️ Prerequisites
- Python 3.x
- `pip` package manager
- Tor Service (Optional, but required if you want to use the `--tor` flag)

## ⚙️ Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/rialms/dataleaks.git
cd dataleaks
pip install -r requirements.txt
```

### Configuration (Optional)
To use custom sites or webhooks, rename `config.json.example` to `config.json` and edit it:
```bash
cp config.json.example config.json
nano config.json
```

## 💻 Usage

### Basic Usage:
Search for a specific keyword and extract any matching lines:
```bash
python3 databreach_finder.py --query "example.com"
```

### Advanced Extraction (Regex):
Search for a target and extract AWS keys from the dumps found:
```bash
python3 databreach_finder.py --query "company dump" --extract aws_key
```

### Anonymous Scraping (Tor):
Route traffic through Tor (Ensure Tor is running on port `9050`):
```bash
python3 databreach_finder.py --query "target" --extract btc --tor
```

### Report Generation:
Generate a professional HTML report:
```bash
python3 databreach_finder.py --query "example.com" --extract emails --report html
```

## 📋 Arguments
| Argument | Short | Description |
|---|---|---|
| `--query` | `-q` | **(Required)** The target keyword or company name to search for. |
| `--extract` | `-e` | **(Optional)** Extract specific data patterns (e.g., `emails`, `btc`, `aws_key`). |
| `--threads` | `-t` | **(Optional)** Number of concurrent threads for downloading (Default: 10). |
| `--tor` | | **(Optional)** Route traffic through local Tor SOCKS5 proxy (`127.0.0.1:9050`). |
| `--report`| | **(Optional)** Generate a report (Options: `html`). |
| `--config`| `-c`| **(Optional)** Path to custom config file (Default: `config.json`). |

## ⚠️ Disclaimer
This tool is built for **educational purposes and authorized security research only**. The author is not responsible for any misuse or illegal activities conducted with this tool. Do not use this tool to access or exploit data you do not own.

## 📞 Contact
- [Author](https://tawk.to/rialms)
