<div align="center">
  <h1>🔍 Databreach Finder Pro [Enterprise]</h1>
  <p><b>An Advanced OSINT Tool for discovering leaked data across the Surface and Deep Web.</b></p>
</div>

## 📖 Overview
Databreach Finder Pro is an enterprise-grade automation tool designed for security researchers and penetration testers. It automates the process of finding, downloading, and extracting leaked sensitive data from various paste sites using Google Dorking.

## 🚀 Enterprise Features (v4.0 Async Edition)
- **Asynchronous Engine:** Built with `aiohttp` and `asyncio` for lightning-fast, non-blocking concurrent downloads.
- **Persistent Database:** Integrates `SQLite` to persistently store and track all findings (`databreach.db`).
- **Smart De-duplication:** Automatically filters out duplicate records across multiple scans, ensuring only *new* leaks trigger alerts.
- **Dockerized:** Includes a `Dockerfile` and `docker-compose.yml` for isolated execution with a built-in Tor proxy.
- **Advanced Logging:** Background processes and errors are logged to `databreach_app.log` for production debugging.
- **CI/CD Pipeline:** Includes GitHub Actions workflows for automated testing and linting.
- **Advanced Regex Extraction:** Built-in pattern recognition for `emails`, `cards`, `btc`, `eth`, `aws_key`, `jwt`, `rsa_private`.
- **Tor Network Routing:** Use the `--tor` flag to route all scraper traffic through the Tor network.
- **Real-Time Alerts:** Get notified instantly on **Discord** or **Telegram** when leaked data is found.
- **Professional Reporting:** Generate clean HTML reports (`--report html`).

## 🛠️ Prerequisites
- Python 3.x OR Docker
- Tor Service (Optional, but required if you want to use the `--tor` flag locally without Docker)

## ⚙️ Installation

### Option 1: Native Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/rialms/dataleaks.git
cd dataleaks
pip install -r requirements.txt
```

### Option 2: Docker (Recommended)
You can run the tool in an isolated container along with a Tor proxy service using Docker Compose:
```bash
docker-compose up -d tor
docker-compose run databreach-finder -q "target" --extract emails --tor
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
- [Author](https://chat.rokibulroni.com)
