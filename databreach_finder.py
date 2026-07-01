import os
import re
import json
import argparse
import requests
import random
import datetime
from urllib.error import HTTPError
from concurrent.futures import ThreadPoolExecutor, as_completed
from googlesearch import search
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

console = Console()

# Predefined Regex Patterns for extraction
PATTERNS = {
    'emails': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
    'cards': r'\b(?:\d[ -]*?){13,16}\b', # basic credit card matching
    'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    'btc': r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b',
    'eth': r'\b0x[a-fA-F0-9]{40}\b',
    'aws_key': r'\bAKIA[0-9A-Z]{16}\b',
    'jwt': r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    'rsa_private': r'-----BEGIN RSA PRIVATE KEY-----'
}

DEFAULT_PASTE_SITES = [
    'pastespot.com', 'cl1p.net', 'dpaste.com', 'slexy.org', 'dumpz.org', 
    'hastebin.com', 'ideone.com', 'pastebin.com', 'gist.github.com',
    'heypasteit.com', 'ivpaste.com', 'mysticpaste.com', 'paste.org.ru', 
    'paste2.org', 'sebsauvage.net', 'squadedit.com', 'wklej.se', 'textsnip.com'
]

class DatabreachFinder:
    def __init__(self, query, extract_type=None, threads=10, use_tor=False, report_format=None, config_path="config.json"):
        self.query = query
        self.extract_type = extract_type
        self.threads = threads
        self.use_tor = use_tor
        self.report_format = report_format
        self.urls = []
        self.results = []
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Load Configuration
        self.config = self.load_config(config_path)
        self.paste_sites = DEFAULT_PASTE_SITES + self.config.get('custom_paste_sites', [])
        
        # Merge custom regex patterns
        if 'custom_regex' in self.config:
            PATTERNS.update(self.config['custom_regex'])
            
        self.session = requests.Session()
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
        ]
        self.session.headers.update({
            'User-Agent': random.choice(user_agents)
        })
        
        # Configure Tor Proxy if requested
        if self.use_tor:
            console.print("[bold yellow][!] Configuring Tor Network Routing (SOCKS5)...[/bold yellow]")
            self.session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

    def load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                console.print(f"[bold red][!] Error loading config.json: {e}[/bold red]")
        return {}

    def print_banner(self):
        banner = "[bold cyan]🔍 Databreach Finder Pro [Enterprise][/bold cyan]\n[bold green]Author:[/bold green] Elliot (Updated version)\n[bold green]Version:[/bold green] 3.0"
        if self.use_tor:
            banner += "\n[bold magenta]🛡️ Tor Mode:[/bold magenta] ACTIVE"
        console.print(Panel(banner, expand=False))

    def send_alert(self, title, message):
        alerts = self.config.get('alerts', {})
        discord_webhook = alerts.get('discord_webhook')
        telegram_token = alerts.get('telegram_bot_token')
        telegram_chat_id = alerts.get('telegram_chat_id')
        
        if discord_webhook and "YOUR_WEBHOOK" not in discord_webhook:
            try:
                data = {"content": f"**{title}**\n```\n{message}\n```"}
                requests.post(discord_webhook, json=data)
            except Exception:
                pass
                
        if telegram_token and telegram_chat_id and "YOUR_" not in telegram_token:
            try:
                url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"
                data = {"chat_id": telegram_chat_id, "text": f"{title}\n{message}"}
                requests.post(url, json=data)
            except Exception:
                pass

    def dork_search(self):
        with console.status(f"[bold yellow]Searching Google for '{self.query}' on Paste Sites...[/bold yellow]", spinner="dots"):
            sites_dork = " OR ".join([f"site:{site}" for site in self.paste_sites])
            advanced_query = f'"{self.query}" ({sites_dork})'
            
            try:
                for url in search(advanced_query, num_results=30, lang="en"):
                    if url not in self.urls:
                        self.urls.append(url)
            except HTTPError as e:
                if e.code == 429:
                    console.print(f"[bold red][!] Google Rate Limit Hit (429). Please use --tor or try again later.[/bold red]")
                else:
                    console.print(f"[bold red][!] Google Search Error: {e}[/bold red]")
            except Exception as e:
                console.print(f"[bold red][!] Google Search Error: {e}[/bold red]")

        if self.urls:
            console.print(f"[bold green][+] Found {len(self.urls)} potential dumps![/bold green]")
        else:
            console.print("[bold red][-] No dumps found. Try a different query.[/bold red]")

    def fetch_and_extract(self, url):
        try:
            if 'pastebin.com' in url and '/raw/' not in url:
                url = url.replace('pastebin.com/', 'pastebin.com/raw/')
                
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                text = response.text
                extracted_data = []
                
                if self.extract_type and self.extract_type in PATTERNS:
                    matches = re.findall(PATTERNS[self.extract_type], text)
                    extracted_data = list(set(matches))
                else:
                    lines = text.split('\n')
                    for line in lines:
                        if self.query.lower() in line.lower():
                            extracted_data.append(line.strip()[:200]) # Cap line length
                
                return url, extracted_data
            return url, []
        except Exception:
            return url, []

    def process_urls(self):
        if not self.urls:
            return

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Downloading & Extracting...", total=len(self.urls))
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {executor.submit(self.fetch_and_extract, url): url for url in self.urls}
                for future in as_completed(future_to_url):
                    url, data = future.result()
                    if data:
                        self.results.append({'url': url, 'data': data})
                    progress.advance(task)

    def generate_html_report(self):
        html_content = f"""
        <html>
        <head>
            <title>Databreach Finder Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f4f4f9; }}
                h1 {{ color: #333; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                th, td {{ border: 1px solid #ccc; padding: 10px; text-align: left; }}
                th {{ background-color: #2c3e50; color: white; }}
                tr:nth-child(even) {{ background-color: #fff; }}
                tr:nth-child(odd) {{ background-color: #ecf0f1; }}
                .meta {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <h1>🔍 Databreach Finder Report</h1>
            <div class="meta">
                <p><strong>Query:</strong> {self.query}</p>
                <p><strong>Extracted Type:</strong> {self.extract_type or 'Raw Query Match'}</p>
                <p><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            </div>
            <table>
                <tr>
                    <th>Source URL</th>
                    <th>Extracted Data Snippet</th>
                </tr>
        """
        for res in self.results:
            data_snippet = "<br>".join(res['data'][:5])
            if len(res['data']) > 5:
                data_snippet += f"<br><em>...and {len(res['data']) - 5} more</em>"
            html_content += f"<tr><td><a href='{res['url']}'>{res['url']}</a></td><td>{data_snippet}</td></tr>"
            
        html_content += """
            </table>
        </body>
        </html>
        """
        
        filename = f'report_{self.timestamp}.html'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[bold green][+] Professional HTML report saved to {filename}[/bold green]")

    def display_results(self):
        if not self.results:
            console.print("[bold red]No matching data found in the downloaded dumps.[/bold red]")
            return

        table = Table(title="Extraction Results", show_lines=True)
        table.add_column("Source URL", style="cyan", no_wrap=True)
        table.add_column(f"Extracted Data ({self.extract_type or 'Raw'})", style="magenta")

        total_extracted = 0
        alert_message = ""
        for res in self.results:
            data_str = "\n".join(res['data'][:10])
            if len(res['data']) > 10:
                data_str += f"\n... and {len(res['data']) - 10} more"
            total_extracted += len(res['data'])
            table.add_row(res['url'], data_str)
            alert_message += f"Found in {res['url']} -> {len(res['data'])} items\n"

        console.print(table)
        console.print(f"[bold green][+] Total extracted items: {total_extracted}[/bold green]")

        # Send Real-Time Alert
        if alert_message:
            self.send_alert(f"Databreach Finder Alert: {self.query}", alert_message)

        # Save to TXT
        txt_filename = f'download_results_{self.timestamp}.txt'
        with open(txt_filename, 'w', encoding='utf-8') as f:
            for res in self.results:
                f.write(f"URL: {res['url']}\n")
                for item in res['data']:
                    f.write(f"{item}\n")
                f.write("-" * 50 + "\n")
        console.print(f"[bold green][+] Full results saved to {txt_filename}[/bold green]")

        # Save to HTML if requested
        if self.report_format == 'html':
            self.generate_html_report()


def main():
    parser = argparse.ArgumentParser(description="Databreach Finder Pro [Enterprise]")
    parser.add_argument("-q", "--query", required=True, help="Target search keyword/query")
    parser.add_argument("-e", "--extract", choices=list(PATTERNS.keys()), help="Specific data pattern to extract from dumps")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--tor", action="store_true", help="Route traffic through local Tor SOCKS5 proxy (127.0.0.1:9050)")
    parser.add_argument("--report", choices=['html'], help="Generate a professional HTML report")
    parser.add_argument("-c", "--config", default="config.json", help="Path to custom config file (default: config.json)")
    
    args = parser.parse_args()

    finder = DatabreachFinder(
        query=args.query, 
        extract_type=args.extract, 
        threads=args.threads,
        use_tor=args.tor,
        report_format=args.report,
        config_path=args.config
    )
    finder.print_banner()
    finder.dork_search()
    finder.process_urls()
    finder.display_results()

if __name__ == "__main__":
    main()
