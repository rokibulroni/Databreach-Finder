import os
import datetime
import asyncio

import aiohttp
from aiohttp_socks import ProxyConnector
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from ..common import console
from ..constants import PATTERNS, DEFAULT_PASTE_SITES
from .net import NetMixin
from ..reporting.database import DatabaseMixin
from ..reporting.html_report import HtmlReportMixin
from ..reporting.ai_analyzer import AiAnalyzerMixin
from ..scanners.domain import DomainScannersMixin
from ..scanners.people import PeopleScannersMixin
from ..scanners.discovery import DiscoveryScannersMixin


class ProfessorOSINT(
    NetMixin,
    DatabaseMixin,
    HtmlReportMixin,
    AiAnalyzerMixin,
    DomainScannersMixin,
    PeopleScannersMixin,
    DiscoveryScannersMixin,
):
    """Advanced Data Breach & Intelligence Gathering orchestrator."""

    def __init__(self, query=None, extract_type=None, threads=10, use_tor=False, report_format=None, config_path="config.json", username=None, monitor=False, dossier=False, webcheck=False, recommend=False, playbook=False, analyzer=False, workspace=False, phone=False, harvester=False, spider=False, awesome=False, toolbox=False, rustscan=False, ai_analyze=False):
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
        self.ai_analyze = ai_analyze
        self.ai_report = None

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

        # Optional API keys (env vars, or a .env file when python-dotenv is present).
        # When a key is supplied the tool upgrades from anonymous scraping to the
        # official API; when it is absent it falls back gracefully.
        self.api_keys = {
            'shodan': os.getenv('SHODAN_API_KEY'),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
            'hunter': os.getenv('HUNTER_API_KEY'),
        }

        # Concurrency limiter, created lazily inside the running event loop so it
        # binds to the correct loop across the tool's separate asyncio.run() calls.
        self.semaphore = None

        # Load Data Sets
        self.social_sites = self.load_json('social_sites.json')
        self.news_feeds = self.load_json('news_feeds.json')
        
        # Merge custom regex patterns
        if 'custom_regex' in self.config:
            PATTERNS.update(self.config['custom_regex'])
            
        # Init Database
        self.init_db()

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

    async def process_urls_async(self):
        # Bind the concurrency limiter to this event loop so large targets never
        # exhaust sockets/file descriptors (respects -t/--threads).
        self.semaphore = asyncio.Semaphore(max(1, self.threads))

        connector = None
        if self.use_tor:
            console.print("[bold yellow][!] Configuring Tor Network Routing (SOCKS5)...[/bold yellow]")
            connector = ProxyConnector.from_url('socks5://127.0.0.1:9050')

        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
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
                   # Check if we actually have any data to save
        has_data = any([
            self.recommended_tools, self.playbook_commands, self.webcheck_results,
            self.results, self.workspace_results, self.phone_results,
            self.harvester_results.get('subdomains'), self.harvester_results.get('emails'),
            self.spider_results, self.awesome_results, self.toolbox_results,
            self.rustscan_results, self.social_results, self.news_results
        ])

        if has_data:
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
                        
            # Read and print the final report to the console in a nice panel
            with open(txt_filename, 'r', encoding='utf-8') as f:
                report_content = f.read().strip()
                
            if report_content:
                console.print("\n")
                console.print(Panel(report_content, title="[bold yellow]📑 Final OSINT Report[/bold yellow]", border_style="yellow", expand=False))

            # AI Threat Intelligence hand-off: enrich the raw report with an
            # LLM-generated analyst write-up when --ai-analyze is set.
            if self.ai_analyze and report_content:
                self.ai_report = self.run_ai_analysis(report_content)
                if self.ai_report:
                    console.print("\n")
                    console.print(Panel(self.ai_report, title="[bold magenta]🧠 AI Threat Intelligence Analysis[/bold magenta]", border_style="magenta", expand=False))
                    with open(txt_filename, 'a', encoding='utf-8') as f:
                        f.write("\n\n=== AI THREAT INTELLIGENCE ANALYSIS ===\n")
                        f.write(self.ai_report + "\n")

            console.print(f"[bold green][+] Full text results saved to {txt_filename}[/bold green]")

            # Generate the HTML report last, so it captures every section
            # (including the AI analysis assembled just above).
            if self.report_format == 'html':
                self.generate_html_report()

        elif not has_data:
            # Do not print "saved to" if no data was found
            pass
