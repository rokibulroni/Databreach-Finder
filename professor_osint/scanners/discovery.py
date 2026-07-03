import re
import random
import logging
import asyncio
from urllib.error import HTTPError

import aiohttp
from googlesearch import search

from ..common import console
from ..constants import (
    PATTERNS, USER_AGENTS, HACKING_TOOLBOX, OSINT_API_URL, CATEGORY_MAP, PLAYBOOK_MAP,
)


class DiscoveryScannersMixin:
    """Dorking, breach extraction, resource discovery and API playbooks."""

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
                for url in self._search_with_backoff(advanced_query, 30):
                    if url not in self.urls:
                        self.urls.append(url)
                logging.info(f"Found {len(self.urls)} URLs via Google Dorking.")
            except HTTPError as e:
                if e.code == 429:
                    msg = "Google Rate Limit Hit (429) after retries. Please use --tor or try again later."
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
                for url in self._search_with_backoff(workspace_dork, 10):
                    if url not in self.workspace_results:
                        self.workspace_results.append(url)
                logging.info(f"Found {len(self.workspace_results)} Workspace links.")
            except Exception as e:
                console.print(f"[bold red][!] Workspace Search Error: {e}[/bold red]")
                
        if self.workspace_results:
            console.print(f"[bold green][+] Found {len(self.workspace_results)} exposed Enterprise Workspace files![/bold green]")

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

    async def fetch_news_feed(self, session, source, feed_url, progress, task):
        sem = self._ensure_semaphore()
        await sem.acquire()
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
            sem.release()
            if progress:
                progress.advance(task)

    async def fetch_and_extract(self, session, url, progress, task):
        sem = self._ensure_semaphore()
        await sem.acquire()
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
            sem.release()
            if progress:
                progress.advance(task)

    async def fetch_tool_recommendations(self, session):
        target_category = None
        if self.extract_type and self.extract_type in CATEGORY_MAP:
            target_category = CATEGORY_MAP[self.extract_type]
        elif self.username:
            target_category = CATEGORY_MAP['username']
        elif self.query:
            target_category = CATEGORY_MAP['ipv4']
            
        if not target_category:
            return
            
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            async with session.get(OSINT_API_URL, headers=headers, timeout=10) as response:
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
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            async with session.get(api_endpoint, headers=headers, timeout=10) as response:
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
