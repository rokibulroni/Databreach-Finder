"""Static data tables and API endpoint configuration."""
import os

POSINT_DIR = os.path.join(os.path.expanduser("~"), "POSINT")
POSINT_LOGS_DIR = os.path.join(POSINT_DIR, "logs")
POSINT_REPORTS_DIR = os.path.join(POSINT_DIR, "reports")
POSINT_CONFIG_DIR = os.path.join(POSINT_DIR, "config")
POSINT_VPN_DIR = os.path.join(POSINT_DIR, "wireguard")

# Ensure the directories exist when constants is loaded
for d in [POSINT_DIR, POSINT_LOGS_DIR, POSINT_REPORTS_DIR, POSINT_CONFIG_DIR, POSINT_VPN_DIR]:
    os.makedirs(d, exist_ok=True)

PATTERNS = {
    'emails': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    'cards': r'\b(?:\d[ -]*?){13,16}\b',
    'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'btc': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    'eth': r'\b0x[a-fA-F0-9]{40}\b',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'jwt': r'eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
    'rsa_private': r'-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----'
}

HACKING_TOOLBOX = {
    "phishing": [
        {"name": "Setoolkit", "desc": "Social-Engineer Toolkit for Phishing", "install": "sudo apt install set"},
        {"name": "Zphisher", "desc": "Automated Phishing Tool with 30+ Templates", "install": "git clone https://github.com/htr-tech/zphisher.git"},
        {"name": "AdvPhishing", "desc": "Phishing tool with OTP capture", "install": "git clone https://github.com/Ignitetechnologies/AdvPhishing.git"}
    ],
    "wireless": [
        {"name": "Aircrack-ng", "desc": "WiFi network security assessment suite", "install": "sudo apt install aircrack-ng"},
        {"name": "Wifite", "desc": "Automated wireless attack tool", "install": "sudo apt install wifite"},
        {"name": "Fluxion", "desc": "WPA/WPA2 wireless network auditor", "install": "git clone https://github.com/FluxionNetwork/fluxion.git"}
    ],
    "osint": [
        {"name": "SocialRecon", "desc": "Hunt down social media accounts by username", "install": "git clone https://github.com/sherlock-project/sherlock.git"},
        {"name": "DomainRecon", "desc": "E-mails, subdomains and names Harvester", "install": "sudo apt install theharvester"},
        {"name": "AttackSurface", "desc": "Automated OSINT framework", "install": "git clone https://github.com/smicallef/spiderfoot.git"}
    ],
    "exploitation": [
        {"name": "Metasploit", "desc": "Penetration testing framework", "install": "sudo apt install metasploit-framework"},
        {"name": "SQLMap", "desc": "Automatic SQL injection and database takeover tool", "install": "sudo apt install sqlmap"},
        {"name": "Routersploit", "desc": "Exploitation Framework for Embedded Devices", "install": "git clone https://github.com/threat9/routersploit"}
    ],
    "anonymity": [
        {"name": "Anonmurf", "desc": "Hide your IP & Mac Address", "install": "git clone https://github.com/UndeadSec/Anonmurf.git"},
        {"name": "TorGhost", "desc": "Route all traffic through Tor", "install": "git clone https://github.com/SusmithKrishnan/torghost.git"}
    ]
}

DEFAULT_PASTE_SITES = [
    'pastespot.com', 'cl1p.net', 'dpaste.com', 'slexy.org', 'dumpz.org', 
    'hastebin.com', 'ideone.com', 'pastebin.com', 'gist.github.com',
    'heypasteit.com', 'ivpaste.com', 'mysticpaste.com', 'paste.org.ru', 
    'paste2.org', 'sebsauvage.net', 'squadedit.com', 'wklej.se', 'textsnip.com'
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
]

OSINT_API_URL = "https://osint.rokibulroni.com/api/v1/tools.json"

CATEGORY_MAP = {
    'emails': 'Email OSINT Tools',
    'ipv4': 'Domain & IP OSINT',
    'username': 'Username & Social Media OSINT',
    'cards': 'Financial & Corporate Intelligence',
    'btc': 'Financial & Corporate Intelligence',
    'eth': 'Financial & Corporate Intelligence',
    'aws_key': 'Web Application OSINT & Scanning',
    'jwt': 'Web Application OSINT & Scanning',
    'rsa_private': 'Web Application OSINT & Scanning'
}

TERMINAL_API_BASE = "https://terminal.rokibulroni.com/jsons"

PLAYBOOK_MAP = {
    'ipv4': f"{TERMINAL_API_BASE}/network/nmap.json",
    'webcheck': f"{TERMINAL_API_BASE}/web/nuclei.json",
    'username': f"{TERMINAL_API_BASE}/osint/domainrecon.json",
    'emails': f"{TERMINAL_API_BASE}/osint/recon-ng.json",
    'cards': f"{TERMINAL_API_BASE}/utilities/curl.json",
    'default': f"{TERMINAL_API_BASE}/utilities/curl.json"
}
