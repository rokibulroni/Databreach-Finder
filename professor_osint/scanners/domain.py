import re
import socket
import random
import asyncio

import aiohttp

from ..common import console
from ..constants import USER_AGENTS


class DomainScannersMixin:
    """Domain/infrastructure intelligence: harvester, spider, rustscan, webcheck."""

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
            # Resolve IP if it's a domain (non-blocking); fall back to the raw query.
            try:
                target_ip = await self._resolve_async(self.query)
            except Exception:
                target_ip = self.query

            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                data = None
                shodan_key = self.api_keys.get('shodan')

                # Authenticated Shodan host API when a key is available.
                if shodan_key:
                    api_url = f"https://api.shodan.io/shodan/host/{target_ip}?key={shodan_key}&minify=true"
                    try:
                        async with session.get(api_url) as response:
                            if response.status == 200:
                                data = await response.json()
                                console.print("[bold green][+] Attack Surface Intelligence gathered via authenticated Shodan API![/bold green]")
                            elif response.status in (401, 403):
                                console.print("[bold yellow][!] Shodan API key rejected — falling back to anonymous InternetDB.[/bold yellow]")
                            elif response.status == 404:
                                console.print(f"[bold yellow][-] No Shodan host data for {target_ip}[/bold yellow]")
                    except Exception:
                        pass

                # Anonymous InternetDB fallback (no key required).
                if data is None:
                    spider_url = f"https://internetdb.shodan.io/{target_ip}"
                    async with session.get(spider_url) as response:
                        if response.status == 200:
                            data = await response.json()
                            console.print("[bold green][+] Attack Surface Intelligence gathered successfully![/bold green]")
                        elif response.status == 404:
                            console.print(f"[bold yellow][-] No Threat Intelligence found in Shodan InternetDB for {target_ip}[/bold yellow]")
                        else:
                            console.print(f"[bold red][!] Intelligence API Error: {response.status}[/bold red]")

                if data:
                    self.spider_results = data
                    self.spider_results['resolved_ip'] = target_ip
        except Exception as e:
            console.print(f"[bold red][!] Intelligence Execution Error: {e}[/bold red]")

    async def _scan_port(self, ip, port, timeout=0.5):
        try:
            async with self._ensure_semaphore():
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
            
        try:
            target_ip = await self._resolve_async(self.query)
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

    async def run_webcheck(self, session):
        domain = self.query.replace('https://', '').replace('http://', '').split('/')[0]
        self.webcheck_results['domain'] = domain
        
        try:
            ip = await self._resolve_async(domain)
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
