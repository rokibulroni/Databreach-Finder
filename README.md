<div align="center">
  <img src="https://raw.githubusercontent.com/rokibulroni/professor-osint/main/docs/posint.png" alt="Professor OSINT Logo">
  <h1>Professor OSINT</h1>
  <p><b>The Ultimate Enterprise OSINT & Attack Surface Discovery Framework</b></p>

<p>
  <a href="https://github.com/rokibulroni/professor-osint/releases">
    <img src="https://img.shields.io/github/v/release/rokibulroni/professor-osint?color=brightgreen&label=Version&style=for-the-badge" alt="Version">
  </a>
  <a href="https://github.com/rokibulroni/professor-osint/stargazers">
    <img src="https://img.shields.io/github/stars/rokibulroni/professor-osint?color=blue&style=for-the-badge" alt="Stars">
  </a>
  <a href="https://github.com/rokibulroni/professor-osint/network/members">
    <img src="https://img.shields.io/github/forks/rokibulroni/professor-osint?color=yellow&style=for-the-badge" alt="Forks">
  </a>
  <a href="https://github.com/rokibulroni/professor-osint/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/rokibulroni/professor-osint?style=for-the-badge" alt="License">
  </a>
</p>

  <p><i>Fast. Native. Dependency-Free. Enterprise-Ready.</i></p>
</div>

---

## ⚡ Unprecedented Intelligence Gathering

**Professor OSINT** is a next-generation Open-Source Intelligence (OSINT) and Active Reconnaissance framework. Built entirely in Python, it consolidates over 15+ advanced cybersecurity capabilities into a single, lightning-fast execution engine. From passive attack surface mapping to active asynchronous port scanning, deep dossier extraction, and live threat monitoring, Professor OSINT provides a comprehensive view of any target—**without requiring a single API key.**

## 🔥 Key Enterprise Features

- **🌐 Domain Intelligence Engine**: Instantly enumerate subdomains and exposed corporate emails through certificate transparency logs and search scraping.
- **🕸️ Attack Surface Mapping**: Passively resolve IPs and map out open ports, cloud hostnames, CDN tags, and known vulnerabilities (CVEs) without alerting the target.
- **⚡ Ultra-Fast Active Port Scanner**: Harness the power of asynchronous Python (`asyncio`) to actively sweep thousands of common ports in mere seconds.
- **💼 Enterprise Workspace OSINT**: Hunt for sensitive documents exposed in Google Drive, Docs, Trello boards, and Notion workspaces.
- **👤 Social Recon & Deep Dossier**: Map a target's digital footprint across hundreds of social platforms. Generate detailed dossiers including bios, real names, and profile pictures.
- **📞 Telecom Intelligence Engine**: Perform carrier, regional, and time-zone lookups on international phone numbers, coupled with automated footprint dorking.
- **⭐ Resource Discovery Engine**: Dynamically query GitHub's public APIs to instantly discover and recommend the top-rated open-source hacking tools for any specific vulnerability or technology.
- **🧰 The Professor's Toolbox**: Access a built-in interactive encyclopedia of curated hacking tools, complete with exact terminal installation commands.
- **📰 Global Threat Monitor**: Stay ahead of the curve by scanning live global cybersecurity news and threat intelligence feeds.
- **💻 Terminal Attack Playbook**: Dynamically inject ready-to-run terminal commands directly into your CLI based on your target's infrastructure.
- **🎯 Advanced Regex Extraction**: Seamlessly carve out IPv4 addresses, Credit Cards, Crypto Wallets (BTC/ETH), AWS Keys, JWTs, and RSA Private Keys from raw data dumps.
- **🧅 Dark Web / Tor Support**: Route all reconnaissance traffic through the Tor network for absolute anonymity.
- **📊 Pro-Level HTML Reporting**: Generate stunning, executive-ready HTML reports of all gathered intelligence.
- **🧠 AI Threat Intelligence Analysis**: Hand off raw OSINT dumps to a Large Language Model (local **Ollama**/**LM Studio** or cloud **OpenAI**, **Gemini**, **Anthropic**, **DeepSeek**) to auto-generate a polished analyst report with prioritized risks and mitigation steps.

---

## 🚀 Quick Start

### ⚡ One-Click Web Installer (Recommended)

Run the following command in your terminal. It works on macOS, Linux, and Windows (via Git Bash/WSL) and will automatically guide you through the setup:

```bash
curl -sL https://posint.rokibulroni.com/install | bash
```

### 📦 Pip Installation
```bash
pip install git+https://github.com/rokibulroni/professor-osint.git
```
Then run from anywhere: `professor-osint --help`

### 🛠️ Manual Setup

```bash
git clone https://github.com/rokibulroni/professor-osint.git
cd professor-osint
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 🗑️ Uninstallation

**1. Standard Uninstallation (Tool Only)**
If you installed via the one-click web installer or `install.sh`, you can remove the tool and its isolated Python virtual environment by running the global command:
```bash
professor-osint-uninstall
```
*(If you installed globally via pip, run `pip uninstall professor-osint`)*

**2. Complete Eradication (Tool + System Dependencies)**
To remove the tool AND all third-party system packages it relies on (Tor, Nmap, RustScan), run the uninstaller above, then use your package manager:
```bash
# macOS (Homebrew)
brew uninstall tor nmap rustscan

# Debian / Ubuntu (APT)
sudo apt-get remove --purge tor nmap rustscan
sudo apt-get autoremove

# Arch Linux (Pacman)
sudo pacman -Rns tor nmap rustscan
```

### Basic Usage

Search a target company or domain:
```bash
python3 professor_osint.py --query "tesla.com"
```

## 📚 A-Z Command Reference

Here is a brief, detailed A-Z list of all available commands and flags:

| Command / Flag | Description |
|---|---|
| `--ai-analyze` | AI Threat Intelligence Analysis. Feeds the gathered OSINT dumps to a configured LLM and appends an analyst report (risks + mitigation). |
| `-a, --analyzer` | Perform Social Analyzer permutations and confidence scoring. |
| `--awesome` | Resource Discovery Engine (Discover Top Curated GitHub Tools). |
| `-c, --config` | Path to custom config file (default: config.json). |
| `--config-ai` | Interactive setup wizard for the AI analyst (provider, model, endpoint) with live validation. |
| `--config-api` | Interactive setup wizard for OSINT API keys (Shodan, VirusTotal, Hunter.io). |
| `-x, --dossier` | Generate Deep Dossier for username. |
| `-e, --extract` | Specific data pattern to extract from dumps. Choices: `emails`, `cards`, `ipv4`, `btc`, `eth`, `aws_key`, `jwt`, `rsa_private`. |
| `--extract-comments` | Force the Social X-Ray engine to also scrape public comments under the target. |
| `--harvester` | Domain Intelligence Engine (Rapid Subdomain and Email Enumeration). |
| `--i-am-authorized` | Confirm authorized use and skip the Social X-Ray consent prompt. |
| `--limit LIMIT` | Cap the number of posts/comments extracted by Social X-Ray (default: 200). |
| `-m, --monitor` | Global Threat Monitor (Live OSINT News Integration). |
| `--phone` | Telecom Intelligence Profile (Carrier, Region, and Footprint Dorking). |
| `-p, --playbook` | Fetch ready-to-run Terminal commands for your target. |
| `-q, --query` | Target search keyword/query (Domain or Company). |
| `-r, --recommend` | Fetch OSINT tool recommendations from your Live API ecosystem. |
| `--report` | Generate a professional HTML report. Choice: `html`. |
| `--rustscan` | RustScan Engine (Ultra-Fast Asynchronous Port Scanner). |
| `--social-xray URL` | Deep Social Media Intelligence: extract public posts/comments from a YouTube or Reddit link. |
| `--spider` | Attack Surface Mapping Engine (Ports, CVEs). |
| `-t, --threads` | Number of concurrent connections (default: 10). |
| `--toolbox` | The Professor's Toolbox (Built-in Installer Menu). Search categories: `phishing`, `wireless`, `osint`, `exploitation`, `anonymity`. |
| `--tor` | Route traffic through local Tor SOCKS5 proxy (127.0.0.1:9050). |
| `-u, --username` | Target username to hunt across social media (Social Recon feature). |
| `-w, --webcheck` | Live Domain Intelligence (DNS, SSL, Headers). |
| `--workspace` | Enterprise Workspace Intelligence (Google Drive, Docs, Trello, Notion). |

## 🛠️ Module Examples

### Domain Intelligence & Attack Surface
Footprint subdomains, emails, and passively map vulnerabilities:
```bash
python3 professor_osint.py --query "example.com" --harvester --spider
```

### Active Asynchronous Port Scan
Rapidly sweep a target for open ports using the active engine:
```bash
python3 professor_osint.py --query "scanme.nmap.org" --rustscan
```

### Social Recon & Deep Dossier
Hunt a username across the web and extract their public biography:
```bash
python3 professor_osint.py --username "target_user" --analyzer --dossier
```

### Enterprise Workspace Hunt
Look for exposed Trello boards and Google Docs:
```bash
python3 professor_osint.py --query "target_company" --workspace
```

### Tool Discovery & Encyclopedia
Find the best curated tools for a specific attack vector:
```bash
python3 professor_osint.py --query "phishing" --awesome --toolbox
```

### AI Threat Intelligence Analysis
First configure a provider once (local or cloud), then let the AI turn raw findings into an analyst report:
```bash
python3 professor_osint.py --config-ai
python3 professor_osint.py --query "example.com" --harvester --spider --ai-analyze
```

### The Ultimate Executive Scan
Run every module, add AI analysis, and generate a beautiful HTML report:
```bash
python3 professor_osint.py --query "target@gmail.com" --workspace --monitor --webcheck --recommend --playbook --phone --harvester --spider --awesome --toolbox --rustscan --ai-analyze --report html
```

---

## 📝 License & Disclaimer

**Disclaimer:** Professor OSINT is designed exclusively for authorized security auditing, threat intelligence research, and educational purposes. The authors are not responsible for any misuse or damage caused by this program.

Distributed under the MIT License. See `LICENSE` for more information.

<div align="center">
  <sub>Built with ❤️ by <b>Rokibul Roni</b> | <a href="https://posint.rokibulroni.com">posint.rokibulroni.com</a></sub>
</div>
