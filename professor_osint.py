import os
import re
import json
import argparse
import requests
import random
import datetime
import sqlite3
import logging
import asyncio
import aiohttp
import socket
from urllib.error import HTTPError
from googlesearch import search
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from aiohttp_socks import ProxyConnector

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    HAS_PHONENUMBERS = True
except ImportError:
    HAS_PHONENUMBERS = False

console = Console()

# Configure Logging
logging.basicConfig(
    filename='databreach_app.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# Predefined Regex Patterns for extraction
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

# The Professor's Toolbox Database (Enterprise Edition)
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

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

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

# OSINT API Configuration
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

# Terminal API Configuration
TERMINAL_API_BASE = "https://terminal.rokibulroni.com/jsons"
PLAYBOOK_MAP = {
    'ipv4': f"{TERMINAL_API_BASE}/network/nmap.json",
    'webcheck': f"{TERMINAL_API_BASE}/web/nuclei.json",
    'username': f"{TERMINAL_API_BASE}/osint/domainrecon.json",
    'emails': f"{TERMINAL_API_BASE}/osint/recon-ng.json",
    'cards': f"{TERMINAL_API_BASE}/utilities/curl.json",
    'default': f"{TERMINAL_API_BASE}/utilities/curl.json"
}

class ProfessorOSINT:
    def __init__(self, query=None, extract_type=None, threads=10, use_tor=False, report_format=None, config_path="config.json", username=None, monitor=False, dossier=False, webcheck=False, recommend=False, playbook=False, analyzer=False, workspace=False, phone=False, harvester=False, spider=False, awesome=False, toolbox=False, rustscan=False):
        self.query = query
        self.username = username
        self.extract_type = extract_type
        self.threads = threads
        self.use_tor = use_tor
        self.report_format = report_format
        self.monitor = monitor
        self.dossier = dossier
        self.webcheck = webcheck
        self.recommend = recommend
        self.playbook = playbook
        self.analyzer = analyzer
        self.workspace = workspace
        self.phone = phone
        self.harvester = harvester
        self.spider = spider
        self.awesome = awesome
        self.toolbox = toolbox
        self.rustscan = rustscan
        
        # Workspace Cross-Pollination (Email -> Username)
        if self.workspace and self.query and '@' in self.query:
            local_handle = self.query.split('@')[0]
            if not self.username:
                self.username = local_handle
                self.dossier = True
                self.analyzer = True
                
        self.target_usernames = [self.username] if self.username else []
        if self.analyzer and self.username:
            base = self.username
            mid = len(base) // 2
            perms = [
                f"{base}1",
                f"{base[:mid]}.{base[mid:]}",
                f"{base[:mid]}_{base[mid:]}",
                f"{base}official"
            ]
            for p in perms:
                if p not in self.target_usernames:
                    self.target_usernames.append(p)
        
        self.urls = []
        self.results = []
        self.social_results = []
        self.news_results = []
        self.webcheck_results = {}
        self.recommended_tools = []
        self.playbook_commands = []
        self.workspace_results = []
        self.phone_results = {}
        self.harvester_results = {'subdomains': set(), 'emails': set()}
        self.spider_results = {}
        self.awesome_results = []
        self.toolbox_results = []
        self.rustscan_results = []
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Load Configuration
        self.config = self.load_config(config_path)
        self.paste_sites = DEFAULT_PASTE_SITES + self.config.get('custom_paste_sites', [])
        
        # Load Data Sets
        self.social_sites = self.load_json('social_sites.json')
        self.news_feeds = self.load_json('news_feeds.json')
        
        # Merge custom regex patterns
        if 'custom_regex' in self.config:
            PATTERNS.update(self.config['custom_regex'])
            
        # Init Database
        self.init_db()

    def load_json(self, filepath):
        try:
            with open(filepath, 'r') as f:
                return json.load(f)
        except Exception as e:
            logging.warning(f"Could not load {filepath}: {e}")
            return {}

    def init_db(self):
        try:
            self.conn = sqlite3.connect('professor_osint.db', check_same_thread=False)
            self.cursor = self.conn.cursor()
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT,
                    url TEXT,
                    extracted_data TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(query, url, extracted_data)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS social_footprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    platform TEXT,
                    url TEXT,
                    bio TEXT,
                    image_url TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(username, platform)
                )
            ''')
            try:
                self.cursor.execute('ALTER TABLE social_footprints ADD COLUMN bio TEXT')
                self.cursor.execute('ALTER TABLE social_footprints ADD COLUMN image_url TEXT')
                self.cursor.execute('ALTER TABLE social_footprints ADD COLUMN confidence TEXT')
            except:
                pass
                
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS live_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    query TEXT,
                    source TEXT,
                    headline TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(query, source, headline)
                )
            ''')
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS web_infrastructure (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    ip_address TEXT,
                    location TEXT,
                    isp TEXT,
                    server_tech TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain, ip_address)
                )
            ''')
            self.conn.commit()
            logging.info("Database initialized successfully.")
        except Exception as e:
            logging.error(f"Database initialization failed: {e}")

    def is_duplicate(self, url, data):
        self.cursor.execute('SELECT 1 FROM findings WHERE query = ? AND url = ? AND extracted_data = ?', (self.query, url, data))
        return self.cursor.fetchone() is not None

    def save_to_db(self, url, data):
        try:
            self.cursor.execute('INSERT INTO findings (query, url, extracted_data) VALUES (?, ?, ?)', (self.query, url, data))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False 
        except Exception as e:
            logging.error(f"Error saving to DB: {e}")
            return False

    def save_social_to_db(self, username, platform, url, bio=None, image_url=None, confidence="100%"):
        try:
            # Check if columns exist first, handle dynamically if possible, or just catch error
            self.cursor.execute('INSERT INTO social_footprints (username, platform, url, bio, image_url, confidence) VALUES (?, ?, ?, ?, ?, ?)', (username, platform, url, bio, image_url, confidence))
            self.conn.commit()
        except sqlite3.OperationalError:
            try:
                self.cursor.execute('INSERT INTO social_footprints (username, platform, url, bio, image_url) VALUES (?, ?, ?, ?, ?)', (username, platform, url, bio, image_url))
                self.conn.commit()
            except sqlite3.IntegrityError:
                if bio or image_url:
                    self.cursor.execute('UPDATE social_footprints SET bio = ?, image_url = ? WHERE username = ? AND platform = ?', (bio, image_url, username, platform))
                    self.conn.commit()
        except sqlite3.IntegrityError:
            if bio or image_url:
                self.cursor.execute('UPDATE social_footprints SET bio = ?, image_url = ?, confidence = ? WHERE username = ? AND platform = ?', (bio, image_url, confidence, username, platform))
                self.conn.commit()
        except Exception as e:
            logging.error(f"Error saving social DB: {e}")

    def save_news_to_db(self, query, source, headline):
        try:
            self.cursor.execute('INSERT INTO live_intelligence (query, source, headline) VALUES (?, ?, ?)', (query, source, headline))
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass 
        except Exception as e:
            logging.error(f"Error saving news DB: {e}")
            
    def save_webcheck_to_db(self, domain, ip, location, isp, server_tech):
        try:
            self.cursor.execute('INSERT INTO web_infrastructure (domain, ip_address, location, isp, server_tech) VALUES (?, ?, ?, ?, ?)', (domain, ip, location, isp, server_tech))
            self.conn.commit()
        except sqlite3.IntegrityError:
            pass 
        except Exception as e:
            logging.error(f"Error saving webcheck DB: {e}")

    def load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    logging.info(f"Loaded config from {config_path}")
                    return json.load(f)
            except Exception as e:
                logging.error(f"Error loading config.json: {e}")
                console.print(f"[bold red][!] Error loading config.json: {e}[/bold red]")
        return {}

    def print_banner(self):
        ascii_art = r"""
[bold cyan]  _____           __                              ____   _____ ___ _   _ _____ [/bold cyan]
[bold cyan] |  __ \         / _|                            / __ \ / ____|_ _| \ | |_   _|[/bold cyan]
[bold cyan] | |__) | __ ___| |_ ___  ___ ___  ___  _ __    | |  | | (___  | ||  \| | | |  [/bold cyan]
[bold blue] |  ___/ '__/ _ \  _/ _ \/ __/ __|/ _ \| '__|   | |  | |\___ \ | || . ` | | |  [/bold blue]
[bold blue] | |   | | |  __/ ||  __/\__ \__ \ (_) | |      | |__| |____) || || |\  |_| |_ [/bold blue]
[bold blue] |_|   |_|  \___|_| \___||___/___/\___/|_|       \____/|_____/|___|_| \_|_____|[/bold blue]
        """
        
        status_lines = []
        if self.use_tor:
            status_lines.append("[bold magenta]🛡️  Tor Mode:[/bold magenta] ACTIVE")
        if self.monitor:
            status_lines.append("[bold red]🌐 Live Threat Monitoring:[/bold red] ACTIVE")
        if self.dossier:
            status_lines.append("[bold yellow]📂 Maigret Dossier Extraction:[/bold yellow] ACTIVE")
        if self.webcheck:
            status_lines.append("[bold yellow]📂 Deep Dossier Extraction:[/bold yellow] ACTIVE")
        if self.workspace:
            status_lines.append("[bold green]💼 Enterprise Workspace Intelligence:[/bold green] ACTIVE")
        if self.recommend:
            status_lines.append("[bold magenta]💡 OSINT Tool Recommender:[/bold magenta] ACTIVE")
        if self.playbook:
            status_lines.append("[bold red]💻 Terminal Attack Playbook:[/bold red] ACTIVE")
        if self.analyzer:
            status_lines.append("[bold bright_magenta]🧠 Social Analyzer (Permutations & Confidence):[/bold bright_magenta] ACTIVE")
        if self.phone:
            status_lines.append("[bold yellow]📞 Telecom Intelligence Engine:[/bold yellow] ACTIVE")
        if self.harvester:
            status_lines.append("[bold green]🌾 Domain Intelligence (Subdomains/Emails):[/bold green] ACTIVE")
        if self.spider:
            status_lines.append("[bold magenta]🕸️  Attack Surface Mapping Engine:[/bold magenta] ACTIVE")
        if self.awesome:
            status_lines.append("[bold yellow]⭐ Resource Discovery Engine:[/bold yellow] ACTIVE")
        if self.toolbox:
            status_lines.append("[bold bright_magenta]🧰 The Professor's Toolbox (Built-in Installers):[/bold bright_magenta] ACTIVE")
        if self.rustscan:
            status_lines.append("[bold red]⚡ Ultra-Fast Active Port Scanner:[/bold red] ACTIVE")
            
        status_text = "\n".join(status_lines) if status_lines else "[dim]No active modular flags set[/dim]"
        
        info_panel = (
            f"[bold white]Author:[/bold white] Rokibul Roni\n"
            f"[bold white]Version:[/bold white] 7.0 (API Ecosystem Edition)\n\n"
            f"[bold cyan]🔥 Active Modules:[/bold cyan]\n{status_text}"
        )
        
        console.print(Panel(ascii_art.strip(), border_style="cyan", expand=False))
        console.print(Panel(info_panel, title="[bold green]System Diagnostics[/bold green]", border_style="green", expand=False))

    def dork_search(self):
        if not self.query:
            return
            
        with console.status(f"[bold yellow]Searching Google for '{self.query}' on Paste Sites...[/bold yellow]", spinner="dots"):
            sites_dork = " OR ".join([f"site:{site}" for site in self.paste_sites])
            
            if hasattr(self, 'phone_perms') and self.phone_perms:
                target_search = " OR ".join([f'"{p}"' for p in self.phone_perms])
                advanced_query = f'({target_search}) ({sites_dork})'
            else:
                advanced_query = f'"{self.query}" ({sites_dork})'
            
            try:
                for url in search(advanced_query, num_results=30, lang="en"):
                    if url not in self.urls:
                        self.urls.append(url)
                logging.info(f"Found {len(self.urls)} URLs via Google Dorking.")
            except HTTPError as e:
                if e.code == 429:
                    msg = "Google Rate Limit Hit (429). Please use --tor or try again later."
                    console.print(f"[bold red][!] {msg}[/bold red]")
                else:
                    console.print(f"[bold red][!] Google Search Error: {e}[/bold red]")
            except Exception as e:
                console.print(f"[bold red][!] Google Search Error: {e}[/bold red]")

        if self.urls:
            console.print(f"[bold green][+] Found {len(self.urls)} potential dumps![/bold green]")
        elif self.query and not (self.monitor or self.webcheck or self.workspace):
            console.print("[bold red][-] No dumps found. Try a different query.[/bold red]")

    def workspace_search(self):
        if not self.workspace or not self.query or '@' not in self.query:
            return
            
        with console.status(f"[bold cyan]Hunting Enterprise Workspace (Google Drive/Docs) for '{self.query}'...[/bold cyan]", spinner="dots"):
            workspace_dork = f'site:drive.google.com OR site:docs.google.com "{self.query}"'
            try:
                for url in search(workspace_dork, num_results=10, lang="en"):
                    if url not in self.workspace_results:
                        self.workspace_results.append(url)
                logging.info(f"Found {len(self.workspace_results)} Workspace links.")
            except Exception as e:
                console.print(f"[bold red][!] Workspace Search Error: {e}[/bold red]")
                
        if self.workspace_results:
            console.print(f"[bold green][+] Found {len(self.workspace_results)} exposed Enterprise Workspace files![/bold green]")

    def phone_intelligence(self):
        if not self.phone or not self.query:
            return
        if not HAS_PHONENUMBERS:
            console.print("[bold red][!] python 'phonenumbers' module is missing. Please run: pip install phonenumbers[/bold red]")
            return
            
        with console.status(f"[bold yellow]📞 Telecom Intelligence Analysis for '{self.query}'...[/bold yellow]", spinner="dots"):
            try:
                parsed_number = phonenumbers.parse(self.query, None)
                self.phone_results['valid'] = phonenumbers.is_valid_number(parsed_number)
                self.phone_results['international'] = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
                self.phone_results['e164'] = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
                self.phone_results['location'] = geocoder.description_for_number(parsed_number, "en") or "Unknown"
                self.phone_results['carrier'] = carrier.name_for_number(parsed_number, "en") or "Unknown"
                self.phone_results['timezones'] = ", ".join(timezone.time_zones_for_number(parsed_number)) or "Unknown"
                
                # Generate Footprinting Dork Permutations
                self.phone_perms = [
                    self.phone_results['e164'],
                    self.phone_results['international'],
                    self.query,
                    self.phone_results['international'].replace(" ", "-")
                ]
                
                if self.phone_results['valid']:
                    console.print("[bold green][+] Successfully extracted Telecom Intelligence data![/bold green]")
                else:
                    console.print("[bold yellow][!] The provided phone number appears to be invalid or incomplete.[/bold yellow]")
            except Exception as e:
                console.print(f"[bold red][!] Telecom Extraction Error: {e}[/bold red]")

    async def harvester_search_async(self):
        if not self.harvester or not self.query or '.' not in self.query or '@' in self.query:
            return
            
        console.print(f"[bold cyan]🌾 Harvesting Subdomains & Emails for '{self.query}'...[/bold cyan]")
        try:
            async with aiohttp.ClientSession() as session:
                # Hackertarget Subdomain Search
                ht_url = f"https://api.hackertarget.com/hostsearch/?q={self.query}"
                async with session.get(ht_url) as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.split('\n'):
                            if ',' in line:
                                sub = line.split(',')[0]
                                self.harvester_results['subdomains'].add(sub)
                                
                # Crt.sh Subdomain Search (JSON)
                crt_url = f"https://crt.sh/?q=%25.{self.query}&output=json"
                async with session.get(crt_url) as response:
                    if response.status == 200:
                        try:
                            data = await response.json()
                            for item in data:
                                name = item.get('name_value', '').lower()
                                if name and '*' not in name:
                                    for sub in name.split('\n'):
                                        self.harvester_results['subdomains'].add(sub)
                        except:
                            pass
                            
                # Fast Email Scraping from Homepage
                try:
                    async with session.get(f"http://www.{self.query}", timeout=5) as response:
                        if response.status == 200:
                            text = await response.text()
                            import re
                            emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text))
                            for e in emails:
                                if self.query in e:
                                    self.harvester_results['emails'].add(e)
                except:
                    pass
                    
        except Exception as e:
            console.print(f"[bold red][!] Harvester Error: {e}[/bold red]")
            
        if self.harvester_results['subdomains'] or self.harvester_results['emails']:
            console.print(f"[bold green][+] Harvested {len(self.harvester_results['subdomains'])} Subdomains and {len(self.harvester_results['emails'])} Emails![/bold green]")

    async def spider_search_async(self):
        if not self.spider or not self.query:
            return
            
        console.print(f"[bold cyan]🕸️ Gathering Attack Surface Intelligence for '{self.query}'...[/bold cyan]")
        try:
            import socket
            # Resolve IP if it's a domain
            try:
                target_ip = socket.gethostbyname(self.query)
            except:
                target_ip = self.query
                
            async with aiohttp.ClientSession() as session:
                spider_url = f"https://internetdb.shodan.io/{target_ip}"
                async with session.get(spider_url, timeout=10) as response:
                    if response.status == 200:
                        self.spider_results = await response.json()
                        self.spider_results['resolved_ip'] = target_ip
                        console.print("[bold green][+] Attack Surface Intelligence gathered successfully![/bold green]")
                    elif response.status == 404:
                        console.print(f"[bold yellow][-] No Threat Intelligence found in Shodan InternetDB for {target_ip}[/bold yellow]")
                    else:
                        console.print(f"[bold red][!] Intelligence API Error: {response.status}[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Intelligence Execution Error: {e}[/bold red]")

    async def awesome_hacking_search_async(self):
        if not self.awesome or not self.query:
            return
            
        console.print(f"[bold cyan]⭐ Searching Awesome Hacking Toolkit for '{self.query}'...[/bold cyan]")
        try:
            import urllib.parse
            safe_query = urllib.parse.quote_plus(self.query)
            github_api_url = f"https://api.github.com/search/repositories?q={safe_query}+topic:hacking&sort=stars&order=desc"
            
            async with aiohttp.ClientSession() as session:
                headers = {"User-Agent": "ProfessorOSINT", "Accept": "application/vnd.github.v3+json"}
                async with session.get(github_api_url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        items = data.get('items', [])
                        # Grab Top 5
                        for item in items[:5]:
                            self.awesome_results.append({
                                'name': item.get('name', 'Unknown'),
                                'description': item.get('description', 'No description provided'),
                                'stars': item.get('stargazers_count', 0),
                                'url': item.get('html_url', '#')
                            })
                        if self.awesome_results:
                            console.print("[bold green][+] Awesome Hacking tools discovered successfully![/bold green]")
                        else:
                            console.print(f"[bold yellow][-] No Awesome Hacking tools found for '{self.query}'[/bold yellow]")
                    else:
                        console.print(f"[bold red][!] GitHub API Error: {response.status}[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Awesome Hacking Search Error: {e}[/bold red]")

    def search_toolbox(self):
        if not self.toolbox or not self.query:
            return
            
        console.print(f"[bold bright_magenta]🧰 Searching The Professor's Toolbox for '{self.query}'...[/bold bright_magenta]")
        q = self.query.lower()
        
        for category, tools in HACKING_TOOLBOX.items():
            if q in category:
                for tool in tools:
                    t = tool.copy()
                    t['category'] = category.capitalize()
                    self.toolbox_results.append(t)
            else:
                for tool in tools:
                    if q in tool['name'].lower() or q in tool['desc'].lower():
                        t = tool.copy()
                        t['category'] = category.capitalize()
                        self.toolbox_results.append(t)
                        
        if self.toolbox_results:
            console.print(f"[bold green][+] Found {len(self.toolbox_results)} curated hacking tools![/bold green]")
        else:
            console.print(f"[bold yellow][-] No tools found in the Toolbox for '{self.query}'. Try 'phishing', 'wireless', or 'osint'.[/bold yellow]")

    async def _scan_port(self, ip, port, timeout=0.5):
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            self.rustscan_results.append(port)
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def rustscan_async(self):
        if not self.rustscan or not self.query:
            return
            
        import socket
        try:
            target_ip = socket.gethostbyname(self.query)
            console.print(f"[bold red]⚡ Initializing Active Scanner Engine for '{self.query}' ({target_ip})...[/bold red]")
            
            # Common ports to scan rapidly
            common_ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                993, 995, 1723, 3306, 3389, 5900, 8000, 8080, 8443, 8888
            ]
            
            tasks = [self._scan_port(target_ip, port) for port in common_ports]
            await asyncio.gather(*tasks)
            
            self.rustscan_results.sort()
            
            if self.rustscan_results:
                console.print(f"[bold green][+] Active Sweep Complete! Found {len(self.rustscan_results)} open ports.[/bold green]")
            else:
                console.print(f"[bold yellow][-] Active Scanner found no open ports on the scanned range.[/bold yellow]")
                
        except socket.gaierror:
            console.print(f"[bold red][!] Scanner Error: Could not resolve '{self.query}'[/bold red]")
        except Exception as e:
            console.print(f"[bold red][!] Scanner Execution Error: {e}[/bold red]")

    async def fetch_and_extract(self, session, url, progress, task):
        try:
            if 'pastebin.com' in url and '/raw/' not in url:
                url = url.replace('pastebin.com/', 'pastebin.com/raw/')
                
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    extracted_data = []
                    
                    if self.extract_type and self.extract_type in PATTERNS:
                        matches = re.findall(PATTERNS[self.extract_type], text)
                        extracted_data = list(set(matches))
                    else:
                        lines = text.split('\n')
                        for line in lines:
                            if self.query.lower() in line.lower():
                                extracted_data.append(line.strip()[:200])
                    
                    new_data = []
                    for data in extracted_data:
                        if not self.is_duplicate(url, data):
                            self.save_to_db(url, data)
                            new_data.append(data)
                    
                    if new_data:
                        self.results.append({'url': url, 'data': new_data})
                        
        except Exception:
            pass
        finally:
            if progress:
                progress.advance(task)

    def extract_metadata(self, html):
        bio, image_url = None, None
        desc_match = re.search(r'<meta\s+(?:name|property)=[\'"](?:og:)?description[\'"]\s+content=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
        if desc_match:
            bio = desc_match.group(1).strip()
            
        img_match = re.search(r'<meta\s+(?:name|property)=[\'"](?:og:)?image[\'"]\s+content=[\'"]([^\'"]+)[\'"]', html, re.IGNORECASE)
        if img_match:
            image_url = img_match.group(1).strip()
            
        return bio, image_url

    async def check_social_profile(self, session, platform, url_template, target_user, progress, task):
        url = url_template.format(target_user)
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            async with session.get(url, headers=headers, timeout=10, allow_redirects=True) as response:
                if response.status == 200:
                    bio, image_url = None, None
                    confidence = "100%"
                    
                    html = ""
                    if self.dossier or self.analyzer:
                        html = await response.text()
                        
                    if self.dossier:
                        bio, image_url = self.extract_metadata(html)
                        
                    if self.analyzer:
                        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE)
                        title = title_match.group(1).lower() if title_match else ""
                        if target_user.lower() in title:
                            confidence = "100%"
                        elif target_user.lower() in html.lower():
                            confidence = "75%"
                        else:
                            confidence = "50%"
                            
                    self.social_results.append({
                        'username': target_user,
                        'platform': platform,
                        'url': url,
                        'bio': bio,
                        'image_url': image_url,
                        'confidence': confidence
                    })
                    self.save_social_to_db(target_user, platform, url, bio, image_url, confidence)
        except Exception:
            pass
        finally:
            if progress:
                progress.advance(task)

    async def fetch_news_feed(self, session, source, feed_url, progress, task):
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            async with session.get(feed_url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    text = await response.text()
                    titles = re.findall(r'<title[^>]*>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
                    
                    for title in titles:
                        clean_title = re.sub(r'<[^>]+>', '', title).strip()
                        clean_title = clean_title.replace('<![CDATA[', '').replace(']]>', '')
                        
                        if self.query.lower() in clean_title.lower() and clean_title not in [r[1] for r in self.news_results]:
                            self.news_results.append((source, clean_title))
                            self.save_news_to_db(self.query, source, clean_title)
        except Exception:
            pass
        finally:
            if progress:
                progress.advance(task)

    async def run_webcheck(self, session):
        domain = self.query.replace('https://', '').replace('http://', '').split('/')[0]
        self.webcheck_results['domain'] = domain
        
        try:
            ip = socket.gethostbyname(domain)
            self.webcheck_results['ip'] = ip
        except Exception:
            self.webcheck_results['ip'] = "Could not resolve"
            return
            
        try:
            async with session.get(f"http://ip-api.com/json/{self.webcheck_results['ip']}", timeout=5) as response:
                if response.status == 200:
                    data = await response.json()
                    self.webcheck_results['location'] = f"{data.get('city', '')}, {data.get('country', '')}"
                    self.webcheck_results['isp'] = data.get('isp', 'Unknown ISP')
                    self.webcheck_results['org'] = data.get('org', '')
        except Exception:
            self.webcheck_results['location'] = "Unknown Location"
            self.webcheck_results['isp'] = "Unknown ISP"
            
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            async with session.head(f"https://{domain}", headers=headers, timeout=10, allow_redirects=True) as response:
                resp_headers = response.headers
                self.webcheck_results['server'] = resp_headers.get('Server', 'Hidden/Unknown')
                self.webcheck_results['powered_by'] = resp_headers.get('X-Powered-By', 'Not specified')
                self.webcheck_results['x_frame_options'] = resp_headers.get('X-Frame-Options', 'Missing')
                self.webcheck_results['x_xss_protection'] = resp_headers.get('X-XSS-Protection', 'Missing')
        except Exception:
            self.webcheck_results['server'] = "Unreachable via HTTPS"
            
        self.save_webcheck_to_db(
            domain, 
            self.webcheck_results.get('ip'), 
            self.webcheck_results.get('location'), 
            self.webcheck_results.get('isp'), 
            self.webcheck_results.get('server')
        )
        
    async def fetch_tool_recommendations(self, session):
        target_category = None
        if self.extract_type and self.extract_type in CATEGORY_MAP:
            target_category = CATEGORY_MAP[self.extract_type]
        elif self.username:
            target_category = CATEGORY_MAP['username']
            
        if not target_category:
            return
            
        try:
            async with session.get(OSINT_API_URL, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    # Find category in children
                    for category in data.get('children', []):
                        if category.get('name') == target_category:
                            for tool in category.get('children', [])[:5]: # Get top 5 tools
                                self.recommended_tools.append({
                                    'name': tool.get('name'),
                                    'url': tool.get('url')
                                })
                            break
        except Exception as e:
            logging.error(f"Failed to fetch OSINT API recommendations: {e}")

    async def fetch_terminal_playbook(self, session):
        api_endpoint = PLAYBOOK_MAP.get('default')
        target_ip_domain = self.query
        
        if self.webcheck:
            api_endpoint = PLAYBOOK_MAP.get('webcheck')
        elif self.extract_type and self.extract_type in PLAYBOOK_MAP:
            api_endpoint = PLAYBOOK_MAP.get(self.extract_type)
        elif self.username:
            api_endpoint = PLAYBOOK_MAP.get('username')
            target_ip_domain = self.username
            
        try:
            async with session.get(api_endpoint, timeout=10) as response:
                if response.status == 200:
                    data = await response.json()
                    self.playbook_commands.append({"tool": data.get("tool", "Terminal"), "commands": []})
                    for cmd in data.get('commands', [])[:5]:
                        # Dynamically inject the target into the command!
                        command_str = cmd.get('command')
                        if target_ip_domain:
                            command_str = re.sub(r'192\.168\.\d+\.\d+|scanme\.nmap\.org|example\.com', target_ip_domain, command_str)
                            
                        self.playbook_commands[0]['commands'].append({
                            'command': command_str,
                            'explanation': cmd.get('explanation')
                        })
        except Exception as e:
            logging.error(f"Failed to fetch Terminal API playbook: {e}")

    async def process_urls_async(self):
        connector = None
        if self.use_tor:
            console.print("[bold yellow][!] Configuring Tor Network Routing (SOCKS5)...[/bold yellow]")
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')

        async with aiohttp.ClientSession(connector=connector) as session:
            # 1. Process Pastebin Dumps (if query provided)
            if self.urls:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
                    task = progress.add_task("[cyan]Downloading & Extracting...", total=len(self.urls))
                    tasks = [self.fetch_and_extract(session, url, progress, task) for url in self.urls]
                    await asyncio.gather(*tasks)
            
            # 2. Process Social Footprints (if username provided)
            if self.target_usernames and self.social_sites:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
                    task_msg = f"[magenta]Analyzing footprint & dossier for {len(self.target_usernames)} target variants..." if self.dossier else f"[magenta]Hunting footprint for {len(self.target_usernames)} target variants..."
                    total_scans = len(self.social_sites) * len(self.target_usernames)
                    task = progress.add_task(task_msg, total=total_scans)
                    tasks = []
                    for t_user in self.target_usernames:
                        for platform, url in self.social_sites.items():
                            tasks.append(self.check_social_profile(session, platform, url, t_user, progress, task))
                    await asyncio.gather(*tasks)
                    
            # 3. Process Live Intelligence (if monitor enabled and query provided)
            if self.monitor and self.query and self.news_feeds:
                with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), TaskProgressColumn(), console=console) as progress:
                    task = progress.add_task(f"[red]Monitoring live global threat feeds for '{self.query}'...", total=len(self.news_feeds))
                    tasks = [self.fetch_news_feed(session, source, url, progress, task) for source, url in self.news_feeds.items()]
                    await asyncio.gather(*tasks)
                    
            # 4. Process Web Infrastructure (if webcheck enabled and query provided)
            if self.webcheck and self.query:
                with console.status(f"[bold blue]Analyzing web infrastructure for '{self.query}'...[/bold blue]", spinner="dots"):
                    await self.run_webcheck(session)
                    
            # 5. Fetch API Tool Recommendations
            if self.recommend:
                with console.status(f"[bold bright_green]Fetching OSINT tool recommendations from API...[/bold bright_green]", spinner="dots"):
                    await self.fetch_tool_recommendations(session)
                    
            # 6. Fetch Terminal Playbook Commands
            if self.playbook:
                with console.status(f"[bold cyan]Generating terminal execution playbook...[/bold cyan]", spinner="dots"):
                    await self.fetch_terminal_playbook(session)

    def generate_html_report(self):
        html_content = f"""
        <html>
        <head>
            <title>OSINT Intelligence Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
                h1 {{ color: #333; border-bottom: 2px solid #3498db; padding-bottom: 10px; }}
                h2 {{ color: #2c3e50; margin-top: 30px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
                th, td {{ border: 1px solid #ccc; padding: 12px; text-align: left; vertical-align: top; }}
                th {{ background-color: #2c3e50; color: white; }}
                tr:nth-child(even) {{ background-color: #fff; }}
                tr:nth-child(odd) {{ background-color: #ecf0f1; }}
                .meta {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }}
                a {{ color: #2980b9; text-decoration: none; }}
                a:hover {{ text-decoration: underline; }}
                .alert-row {{ background-color: #ffeaa7 !important; border-left: 4px solid #d35400; }}
                .profile-img {{ width: 60px; height: 60px; border-radius: 50%; object-fit: cover; border: 2px solid #bdc3c7; }}
                .bio-text {{ font-size: 0.9em; color: #555; margin-top: 5px; }}
                .webcheck-box {{ background-color: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; margin-top: 15px; }}
                .webcheck-item {{ margin-bottom: 8px; }}
                .tool-card {{ background: #fff; border-left: 4px solid #2ecc71; padding: 10px; margin-bottom: 10px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
            </style>
        </head>
        <body>
            <h1>🔍 OSINT Intelligence Report</h1>
            <div class="meta">
                <p><strong>Target Query:</strong> {self.query or 'N/A'}</p>
                <p><strong>Target Username:</strong> {self.username or 'N/A'}</p>
                <p><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
        """
        
        if self.recommended_tools:
            html_content += """
            <h2>💡 Recommended OSINT Arsenal Tools (via API)</h2>
            <p>Based on your extraction type, the live OSINT API recommends investigating further with these tools:</p>
            """
            for tool in self.recommended_tools:
                html_content += f"<div class='tool-card'><strong>{tool['name']}</strong><br><a href='{tool['url']}' target='_blank'>{tool['url']}</a></div>"
                
        if self.playbook_commands:
            html_content += """
            <h2>🚀 Terminal Execution Playbook (via API)</h2>
            <p>Directly copy and paste these commands into your terminal to investigate this target further:</p>
            """
            for block in self.playbook_commands:
                for cmd in block['commands']:
                    html_content += f"<div class='tool-card'><strong>Terminal Command:</strong><br><pre><code>{cmd['command']}</code></pre><p class='bio-text'>{cmd['explanation']}</p></div>"
        
        if self.webcheck_results:
            html_content += f"""
            <h2>🌐 Web Infrastructure Analysis (Web-Check)</h2>
            <div class="webcheck-box">
                <div class="webcheck-item"><strong>Domain:</strong> {self.webcheck_results.get('domain')}</div>
                <div class="webcheck-item"><strong>Resolved IP:</strong> {self.webcheck_results.get('ip')}</div>
                <div class="webcheck-item"><strong>Geolocation:</strong> {self.webcheck_results.get('location')}</div>
                <div class="webcheck-item"><strong>Hosting/ISP:</strong> {self.webcheck_results.get('isp')} {self.webcheck_results.get('org')}</div>
                <div class="webcheck-item"><strong>Server Tech:</strong> {self.webcheck_results.get('server')}</div>
                <div class="webcheck-item"><strong>Backend Tech (X-Powered-By):</strong> {self.webcheck_results.get('powered_by', 'Hidden')}</div>
                <div class="webcheck-item"><strong>Security Header (X-Frame-Options):</strong> {self.webcheck_results.get('x_frame_options')}</div>
                <div class="webcheck-item"><strong>Security Header (X-XSS-Protection):</strong> {self.webcheck_results.get('x_xss_protection')}</div>
            </div>
            """
        
        if self.results:
            html_content += """
            <h2>🚨 Professor OSINT Findings</h2>
            <table>
                <tr>
                    <th width="30%">Source URL</th>
                    <th>Extracted Data Snippet (New Unique Findings)</th>
                </tr>
            """
            for res in self.results:
                data_snippet = "<br>".join(res['data'][:5])
                if len(res['data']) > 5:
                    data_snippet += f"<br><em>...and {len(res['data']) - 5} more</em>"
                html_content += f"<tr><td><a href='{res['url']}'>{res['url']}</a></td><td>{data_snippet}</td></tr>"
            html_content += "</table>"
            
        if self.workspace_results:
            html_content += """
            <h2>🏢 Enterprise Workspace Intelligence (Exposed Files)</h2>
            <p>The following corporate/personal Drive/Docs/Sheets links were found publicly exposed for the target:</p>
            <table>
                <tr><th>Public Workspace Asset URL</th></tr>
            """
            for url in self.workspace_results:
                html_content += f"<tr><td><a href='{url}'>{url}</a></td></tr>"
            html_content += "</table>"
            
        if self.phone_results:
            status_color = "#2ecc71" if self.phone_results.get('valid') else "#e74c3c"
            html_content += f"""
            <h2>📞 Telecom Intelligence Engine</h2>
            <div class="webcheck-box">
                <div class="webcheck-item"><strong>E164 Format:</strong> {self.phone_results.get('e164', 'N/A')}</div>
                <div class="webcheck-item"><strong>International Format:</strong> {self.phone_results.get('international', 'N/A')}</div>
                <div class="webcheck-item"><strong>Validity:</strong> <span style="color: {status_color}; font-weight: bold;">{self.phone_results.get('valid', 'False')}</span></div>
                <div class="webcheck-item"><strong>Location/Region:</strong> {self.phone_results.get('location', 'Unknown')}</div>
                <div class="webcheck-item"><strong>Carrier/ISP:</strong> {self.phone_results.get('carrier', 'Unknown')}</div>
                <div class="webcheck-item"><strong>Timezone(s):</strong> {self.phone_results.get('timezones', 'Unknown')}</div>
            </div>
            """
            
        if self.harvester_results.get('subdomains') or self.harvester_results.get('emails'):
            html_content += "<h2>🌾 Domain Intelligence (Subdomains & Emails)</h2>"
            if self.harvester_results['subdomains']:
                html_content += "<h3>Discovered Subdomains</h3><ul>"
                for sub in sorted(list(self.harvester_results['subdomains']))[:50]:
                    html_content += f"<li>{sub}</li>"
                html_content += "</ul>"
            if self.harvester_results['emails']:
                html_content += "<h3>Discovered Emails</h3><ul>"
                for em in self.harvester_results['emails']:
                    html_content += f"<li>{em}</li>"
                html_content += "</ul>"
                
        if self.spider_results:
            html_content += f"""
            <h2>🕸️ Attack Surface Mapping Engine</h2>
            <div class="webcheck-box">
                <div class="webcheck-item"><strong>Resolved IP:</strong> {self.spider_results.get('resolved_ip', 'N/A')}</div>
                <div class="webcheck-item"><strong>Open Ports:</strong> {', '.join(map(str, self.spider_results.get('ports', []))) or 'None Detected'}</div>
                <div class="webcheck-item"><strong>Hostnames:</strong> {', '.join(self.spider_results.get('hostnames', [])) or 'None Detected'}</div>
                <div class="webcheck-item"><strong>Tags:</strong> {', '.join(self.spider_results.get('tags', [])) or 'None Detected'}</div>
                <div class="webcheck-item"><strong>Vulnerabilities (CVEs):</strong> {', '.join(self.spider_results.get('vulns', [])) or 'No Known CVEs'}</div>
            </div>
            """
            
        if self.awesome_results:
            html_content += """
            <h2>⭐ Awesome Hacking Toolkit</h2>
            <table>
                <tr><th>Repository</th><th>Description</th><th>Stars</th><th>Link</th></tr>
            """
            for repo in self.awesome_results:
                desc = str(repo['description']).replace('<', '&lt;').replace('>', '&gt;')
                html_content += f"<tr><td>{repo['name']}</td><td>{desc}</td><td>⭐ {repo['stars']}</td><td><a href='{repo['url']}' target='_blank'>View</a></td></tr>"
            html_content += "</table>"
            
        if self.toolbox_results:
            html_content += """
            <h2>🧰 The Professor's Toolbox</h2>
            <table>
                <tr><th>Tool Name</th><th>Category</th><th>Description</th><th>Install Command</th></tr>
            """
            for tool in self.toolbox_results:
                html_content += f"<tr><td>{tool['name']}</td><td>{tool['category']}</td><td>{tool['desc']}</td><td><code>{tool['install']}</code></td></tr>"
            html_content += "</table>"
            
        if self.rustscan_results:
            html_content += """
            <h2>⚡ Active Port Scan Engine</h2>
            <div class="webcheck-grid">
                <div class="webcheck-item"><strong>Open Ports:</strong> """ + ", ".join(map(str, self.rustscan_results)) + """</div>
            </div>
            """
            
        if self.social_results:
            section_title = "👤 Deep Dossier Extraction" if self.dossier else "👤 Social Media Footprint"
            html_content += f"""
            <h2>{section_title}</h2>
            <table>
                <tr>
                    <th width="15%">Username</th>
                    <th width="15%">Platform</th>
                    <th width="30%">Profile URL</th>
                    <th>Extracted Metadata (Dossier)</th>
                    <th width="10%">Confidence</th>
                </tr>
            """
            for profile in self.social_results:
                platform = profile['platform']
                url = profile['url']
                bio = profile.get('bio')
                img = profile.get('image_url')
                conf = profile.get('confidence', '100%')
                uname = profile.get('username', self.username)
                
                meta_html = ""
                if img:
                    meta_html += f"<img src='{img}' class='profile-img' alt='Avatar'><br>"
                if bio:
                    meta_html += f"<div class='bio-text'><strong>Bio:</strong> {bio}</div>"
                if not meta_html:
                    meta_html = "<span style='color:#999'>No metadata extracted</span>"
                    
                conf_color = "#2ecc71" if conf == "100%" else "#f1c40f" if conf == "75%" else "#e74c3c"
                conf_html = f"<span style='font-weight:bold; color:{conf_color}'>{conf}</span>"
                    
                html_content += f"<tr><td>{uname}</td><td><strong>{platform}</strong></td><td><a href='{url}'>{url}</a></td><td>{meta_html}</td><td>{conf_html}</td></tr>"
            html_content += "</table>"
            
        if self.news_results:
            html_content += """
            <h2>📡 Live Threat Intelligence (WorldMonitor)</h2>
            <p style="color: #c0392b;"><strong>Warning:</strong> Target detected in recent global cyber/news feeds!</p>
            <table>
                <tr>
                    <th width="30%">Intelligence Source</th>
                    <th>Headline / Mention</th>
                </tr>
            """
            for source, headline in self.news_results:
                html_content += f"<tr class='alert-row'><td><strong>{source}</strong></td><td>{headline}</td></tr>"
            html_content += "</table>"
            
        html_content += """
        </body>
        </html>
        """
        
        filename = f'report_{self.timestamp}.html'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[bold green][+] Professional HTML report saved to {filename}[/bold green]")
        logging.info(f"Report generated: {filename}")

    def display_results(self):
        
        if self.recommended_tools:
            console.print(f"\n[bold bright_green]💡 OSINT API Ecosystem Recommendations[/bold bright_green]")
            console.print(f"[italic green]Based on your target, your OSINT website API recommends these tools to investigate further:[/italic green]")
            for tool in self.recommended_tools:
                console.print(f"  ➜ [bold]{tool['name']}[/bold] - [underline cyan]{tool['url']}[/underline cyan]")
            print()
            
        if self.playbook_commands:
            console.print(f"\n[bold cyan]🚀 Terminal Command Playbook[/bold cyan]")
            console.print(f"[italic cyan]Ready-to-run commands fetched from terminal.rokibulroni.com:[/italic cyan]")
            for block in self.playbook_commands:
                for cmd in block['commands']:
                    console.print(f"  [bold green]$ {cmd['command']}[/bold green]")
                    console.print(f"    [dim]{cmd['explanation']}[/dim]\n")
            
        alert_message = ""
        
        # Display Web-Check Results
        if self.webcheck and self.webcheck_results:
            table = Table(title=f"Infrastructure Analysis for '{self.webcheck_results.get('domain')}'", show_lines=True)
            table.add_column("Property", style="cyan", no_wrap=True)
            table.add_column("Details", style="yellow")
            
            table.add_row("Resolved IP", str(self.webcheck_results.get('ip')))
            table.add_row("Geolocation", str(self.webcheck_results.get('location')))
            table.add_row("Hosting / ISP", f"{self.webcheck_results.get('isp')} / {self.webcheck_results.get('org')}")
            table.add_row("Server Tech", str(self.webcheck_results.get('server')))
            table.add_row("X-Powered-By", str(self.webcheck_results.get('powered_by', 'Hidden')))
            table.add_row("Sec Header: Frame-Options", str(self.webcheck_results.get('x_frame_options')))
            table.add_row("Sec Header: XSS-Protection", str(self.webcheck_results.get('x_xss_protection')))
            
            console.print(table)
            
        # Display Databreach Results
        if self.query and self.urls:
            if not self.results:
                console.print("[bold red]No matching unique data found in the downloaded dumps.[/bold red]")
            else:
                table = Table(title="Extraction Results (Unique)", show_lines=True)
                table.add_column("Source URL", style="cyan", no_wrap=True)
                table.add_column(f"Extracted Data ({self.extract_type or 'Raw'})", style="magenta")

                total_extracted = 0
                for res in self.results:
                    data_str = "\n".join(res['data'][:10])
                    if len(res['data']) > 10:
                        data_str += f"\n... and {len(res['data']) - 10} more"
                    total_extracted += len(res['data'])
                    table.add_row(res['url'], data_str)
                    alert_message += f"Found in {res['url']} -> {len(res['data'])} new items\n"

                console.print(table)
                console.print(f"[bold green][+] Total UNIQUE extracted items: {total_extracted}[/bold green]")
                
        # Display Workspace Results
        if self.workspace and self.query and '@' in self.query:
            if not self.workspace_results:
                console.print(f"[bold red]No public Enterprise Workspace (Drive/Docs) files found for '{self.query}'.[/bold red]")
            else:
                table = Table(title=f"Enterprise Workspace Intelligence: Exposed Files", show_lines=True)
                table.add_column("Workspace Asset URL", style="cyan")
                for url in self.workspace_results:
                    table.add_row(url)
                console.print(table)
                console.print(f"[bold bright_red][!] Target has {len(self.workspace_results)} publicly exposed Enterprise Drive/Docs files![/bold bright_red]")

        # Display Phone Results
        if self.phone and self.phone_results:
            table = Table(title=f"Telecom Intelligence for '{self.query}'", show_lines=True)
            table.add_column("Property", style="cyan", no_wrap=True)
            table.add_column("Details", style="yellow")
            
            table.add_row("International Format", str(self.phone_results.get('international')))
            table.add_row("Validity", str(self.phone_results.get('valid')))
            table.add_row("Location/Region", str(self.phone_results.get('location')))
            table.add_row("Carrier / ISP", str(self.phone_results.get('carrier')))
            table.add_row("Timezone(s)", str(self.phone_results.get('timezones')))
            
            console.print(table)

        # Display Harvester Results
        if self.harvester and (self.harvester_results['subdomains'] or self.harvester_results['emails']):
            table = Table(title=f"Domain Intelligence for '{self.query}'", show_lines=True)
            table.add_column("Type", style="cyan")
            table.add_column("Findings", style="yellow")
            
            if self.harvester_results['subdomains']:
                subs = sorted(list(self.harvester_results['subdomains']))[:20]
                sub_str = "\n".join(subs)
                if len(self.harvester_results['subdomains']) > 20:
                    sub_str += f"\n...and {len(self.harvester_results['subdomains']) - 20} more"
                table.add_row("Subdomains", sub_str)
                
            if self.harvester_results['emails']:
                em_str = "\n".join(self.harvester_results['emails'])
                table.add_row("Emails", em_str)
                
            console.print(table)
            
        # Display Attack Surface Results
        if self.spider and self.spider_results:
            table = Table(title=f"Attack Surface Intelligence for '{self.query}'", show_lines=True)
            table.add_column("Property", style="cyan", no_wrap=True)
            table.add_column("Details", style="magenta")
            
            table.add_row("Resolved IP", str(self.spider_results.get('resolved_ip')))
            ports = ", ".join(map(str, self.spider_results.get('ports', [])))
            table.add_row("Open Ports", ports if ports else "None Detected")
            hosts = "\n".join(self.spider_results.get('hostnames', []))
            table.add_row("Hostnames", hosts if hosts else "None Detected")
            tags = ", ".join(self.spider_results.get('tags', []))
            table.add_row("Tags", tags if tags else "None Detected")
            vulns = "\n".join(self.spider_results.get('vulns', []))
            if len(self.spider_results.get('vulns', [])) > 10:
                vulns = "\n".join(self.spider_results.get('vulns', [])[:10]) + f"\n...and {len(self.spider_results.get('vulns')) - 10} more"
            table.add_row("Vulnerabilities (CVEs)", vulns if vulns else "No Known CVEs")
            
            console.print(table)
            
        # Display Awesome Hacking Results
        if self.awesome and self.awesome_results:
            table = Table(title=f"Awesome Hacking Tools for '{self.query}'", show_lines=True)
            table.add_column("Repository", style="cyan", no_wrap=True)
            table.add_column("Description", style="white")
            table.add_column("Stars", style="yellow", justify="right")
            table.add_column("URL", style="blue")
            
            for repo in self.awesome_results:
                table.add_row(
                    repo['name'],
                    str(repo['description'])[:100] + "..." if repo['description'] and len(repo['description']) > 100 else str(repo['description']),
                    f"⭐ {repo['stars']}",
                    repo['url']
                )
                
            console.print(table)
            
        # Display Toolbox Results
        if self.toolbox and self.toolbox_results:
            table = Table(title=f"The Professor's Toolbox for '{self.query}'", show_lines=True)
            table.add_column("Tool Name", style="bright_magenta", no_wrap=True)
            table.add_column("Category", style="cyan")
            table.add_column("Description", style="white")
            table.add_column("Install Command", style="green")
            
            for tool in self.toolbox_results:
                table.add_row(
                    tool['name'],
                    tool['category'],
                    tool['desc'],
                    tool['install']
                )
                
            console.print(table)
            
        # Display Port Scan Results
        if self.rustscan and self.rustscan_results:
            table = Table(title=f"Active Port Sweep for '{self.query}'", show_lines=True)
            table.add_column("Open Ports", style="red", justify="center")
            
            table.add_row(
                ", ".join(map(str, self.rustscan_results))
            )
            
            console.print(table)

        # Display Social Recon Results
        if self.username:
            if not self.social_results:
                console.print(f"[bold red]No social profiles found for '{self.username}'.[/bold red]")
            else:
                title = f"Social Analyzer Dossier for targets" if self.dossier else f"Social Analyzer Footprints"
                table = Table(title=title, show_lines=True)
                table.add_column("Username", style="cyan")
                table.add_column("Platform", style="blue")
                table.add_column("Profile URL", style="green")
                if self.analyzer:
                    table.add_column("Confidence", justify="right")
                if self.dossier:
                    table.add_column("Extracted Metadata", style="yellow")
                
                for profile in self.social_results:
                    uname = profile.get('username', self.username)
                    platform = profile['platform']
                    url = profile['url']
                    conf = profile.get('confidence', '100%')
                    
                    row = [uname, platform, url]
                    
                    if self.analyzer:
                        color = "green" if conf == "100%" else "yellow" if conf == "75%" else "red"
                        row.append(f"[{color}]{conf}[/{color}]")
                        
                    if self.dossier:
                        meta = []
                        if profile.get('bio'): meta.append(f"Bio: {profile['bio'][:100]}...")
                        if profile.get('image_url'): meta.append("[Avatar Extracted]")
                        meta_str = "\n".join(meta) if meta else "N/A"
                        row.append(meta_str)
                    
                    table.add_row(*row)
                    
                console.print(table)
                console.print(f"[bold magenta][+] Found profiles on {len(self.social_results)} platforms across {len(self.target_usernames)} target variations![/bold magenta]")
                
        # Display WorldMonitor Results
        if self.monitor and self.query:
            if not self.news_results:
                console.print(f"[bold green]No recent global threat alerts or news mentions found for '{self.query}'.[/bold green]")
            else:
                table = Table(title=f"Live Threat Intelligence Alerts for '{self.query}'", show_lines=True)
                table.add_column("Intelligence Source", style="red")
                table.add_column("Headline / Mention", style="yellow")
                
                for source, headline in self.news_results:
                    table.add_row(source, headline)
                    
                console.print(table)
                console.print(f"[bold red][!] WARNING: Target found in {len(self.news_results)} recent global reports![/bold red]")

        # Save to TXT
        txt_filename = f'download_results_{self.timestamp}.txt'
        with open(txt_filename, 'w', encoding='utf-8') as f:
            if self.recommended_tools:
                f.write("=== API ECOSYSTEM RECOMMENDATIONS ===\n")
                for tool in self.recommended_tools:
                    f.write(f"{tool['name']} -> {tool['url']}\n")
                f.write("-" * 50 + "\n")
            if self.playbook_commands:
                f.write("=== TERMINAL PLAYBOOK ===\n")
                for block in self.playbook_commands:
                    for cmd in block['commands']:
                        f.write(f"$ {cmd['command']}\n")
                        f.write(f"  {cmd['explanation']}\n\n")
                f.write("-" * 50 + "\n")
            if self.webcheck_results:
                f.write("=== WEB INFRASTRUCTURE ===\n")
                f.write(f"Domain: {self.webcheck_results.get('domain')}\n")
                f.write(f"IP: {self.webcheck_results.get('ip')}\n")
                f.write(f"Location: {self.webcheck_results.get('location')}\n")
                f.write(f"Hosting: {self.webcheck_results.get('isp')}\n")
                f.write("-" * 50 + "\n")
            if self.results:
                f.write("\n=== DATABREACH FINDINGS ===\n")
                for res in self.results:
                    f.write(f"URL: {res['url']}\n")
                    for item in res['data']:
                        f.write(f"{item}\n")
                    f.write("-" * 50 + "\n")
            if self.workspace_results:
                f.write("\n=== ENTERPRISE WORKSPACE EXPOSURES ===\n")
                for url in self.workspace_results:
                    f.write(f"Asset: {url}\n")
                f.write("-" * 50 + "\n")
            if self.phone_results:
                f.write("\n=== TELECOM INTELLIGENCE ===\n")
                f.write(f"Format: {self.phone_results.get('international')}\n")
                f.write(f"Validity: {self.phone_results.get('valid')}\n")
                f.write(f"Location: {self.phone_results.get('location')}\n")
                f.write(f"Carrier: {self.phone_results.get('carrier')}\n")
                f.write("-" * 50 + "\n")
            if self.harvester_results.get('subdomains') or self.harvester_results.get('emails'):
                f.write("\n=== DOMAIN INTELLIGENCE ===\n")
                for sub in self.harvester_results['subdomains']:
                    f.write(f"Subdomain: {sub}\n")
                for em in self.harvester_results['emails']:
                    f.write(f"Email: {em}\n")
                f.write("-" * 50 + "\n")
            if self.spider_results:
                f.write("\n=== ATTACK SURFACE MAPPING ===\n")
                f.write(f"Resolved IP: {self.spider_results.get('resolved_ip')}\n")
                f.write(f"Open Ports: {', '.join(map(str, self.spider_results.get('ports', [])))}\n")
                f.write(f"Hostnames: {', '.join(self.spider_results.get('hostnames', []))}\n")
                f.write(f"Tags: {', '.join(self.spider_results.get('tags', []))}\n")
                f.write(f"Vulnerabilities: {', '.join(self.spider_results.get('vulns', []))}\n")
                f.write("-" * 50 + "\n")
            if self.awesome_results:
                f.write("\n=== AWESOME HACKING TOOLKIT ===\n")
                for repo in self.awesome_results:
                    f.write(f"Repo: {repo['name']} (⭐ {repo['stars']})\n")
                    f.write(f"URL: {repo['url']}\n")
                    f.write(f"Description: {repo['description']}\n\n")
                f.write("-" * 50 + "\n")
            if self.toolbox_results:
                f.write("\n=== THE PROFESSOR'S TOOLBOX ===\n")
                for tool in self.toolbox_results:
                    f.write(f"Tool: {tool['name']} ({tool['category']})\n")
                    f.write(f"Description: {tool['desc']}\n")
                    f.write(f"Install: {tool['install']}\n\n")
                f.write("-" * 50 + "\n")
            if self.rustscan_results:
                f.write("\n=== ACTIVE PORT SCAN ENGINE ===\n")
                f.write(f"Open Ports: {', '.join(map(str, self.rustscan_results))}\n")
                f.write("-" * 50 + "\n")
            if self.social_results:
                f.write("\n=== TARGET DOSSIER ===\n")
                for profile in self.social_results:
                    f.write(f"{profile['platform']}: {profile['url']}\n")
                    if profile.get('bio'): f.write(f"  Bio: {profile['bio']}\n")
            if self.news_results:
                f.write("\n=== LIVE THREAT INTELLIGENCE ===\n")
                for source, headline in self.news_results:
                    f.write(f"[{source}] {headline}\n")
                    
        console.print(f"[bold green][+] Full text results saved to {txt_filename}[/bold green]")


def main():
    parser = argparse.ArgumentParser(description="Professor OSINT [Enterprise OSINT]")
    parser.add_argument("-q", "--query", help="Target search keyword/query (Domain or Company)")
    parser.add_argument("-u", "--username", help="Target username to hunt across social media (Social Recon feature)")
    parser.add_argument("-x", "--dossier", action="store_true", help="Generate Deep Dossier for username")
    parser.add_argument("-m", "--monitor", action="store_true", help="Global Threat Monitor (Live OSINT News Integration)")
    parser.add_argument("-w", "--webcheck", action="store_true", help="Live Domain Intelligence (DNS, SSL, Headers)")
    parser.add_argument("-a", "--analyzer", action="store_true", help="Perform Social Analyzer permutations and confidence scoring")
    parser.add_argument("--workspace", action="store_true", help="Enterprise Workspace Intelligence (Google Drive, Docs, Trello, Notion)")
    parser.add_argument("--phone", action="store_true", help="Telecom Intelligence Profile (Carrier, Region, and Footprint Dorking)")
    parser.add_argument("--harvester", action="store_true", help="Domain Intelligence Engine (Rapid Subdomain and Email Enumeration)")
    parser.add_argument("--spider", action="store_true", help="Attack Surface Mapping Engine (Ports, CVEs)")
    parser.add_argument("--awesome", action="store_true", help="Resource Discovery Engine (Discover Top Curated GitHub Tools)")
    parser.add_argument("--toolbox", action="store_true", help="The Professor's Toolbox (Built-in Installer Menu)")
    parser.add_argument("--rustscan", action="store_true", help="RustScan Engine (Ultra-Fast Asynchronous Port Scanner)")
    parser.add_argument("-r", "--recommend", action="store_true", help="Fetch OSINT tool recommendations from your Live API ecosystem")
    parser.add_argument("-p", "--playbook", action="store_true", help="Fetch ready-to-run Terminal commands for your target")
    parser.add_argument("-e", "--extract", choices=list(PATTERNS.keys()), help="Specific data pattern to extract from dumps")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent connections (default: 10)")
    parser.add_argument("--tor", action="store_true", help="Route traffic through local Tor SOCKS5 proxy (127.0.0.1:9050)")
    parser.add_argument("--report", choices=['html'], help="Generate a professional HTML report")
    parser.add_argument("-c", "--config", default="config.json", help="Path to custom config file (default: config.json)")
    
    args = parser.parse_args()
    
    if not args.query and not args.username:
        console.print("[bold red][!] You must provide either a --query (-q) or a --username (-u).[/bold red]")
        return

    finder = ProfessorOSINT(
        query=args.query,
        username=args.username,
        extract_type=args.extract, 
        threads=args.threads,
        use_tor=args.tor,
        report_format=args.report,
        config_path=args.config,
        monitor=args.monitor,
        dossier=args.dossier,
        webcheck=args.webcheck,
        recommend=args.recommend,
        playbook=args.playbook,
        analyzer=args.analyzer,
        workspace=args.workspace,
        phone=args.phone,
        harvester=args.harvester,
        spider=args.spider,
        awesome=args.awesome,
        toolbox=args.toolbox,
        rustscan=args.rustscan
    )
    finder.print_banner()
    finder.phone_intelligence()
    finder.search_toolbox()
    if finder.harvester:
        asyncio.run(finder.harvester_search_async())
    if finder.spider:
        asyncio.run(finder.spider_search_async())
    if finder.rustscan:
        asyncio.run(finder.rustscan_async())
    if finder.awesome:
        asyncio.run(finder.awesome_hacking_search_async())
    finder.dork_search()
    finder.workspace_search()
    asyncio.run(finder.process_urls_async())
    finder.display_results()

if __name__ == "__main__":
    main()
