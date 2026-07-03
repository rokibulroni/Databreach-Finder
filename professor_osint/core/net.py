import time
import random
import asyncio
from urllib.error import HTTPError
import requests

from googlesearch import search

from ..common import console


class NetMixin:
    """Network resilience helpers: backoff, async DNS, concurrency limiting."""

    def apply_network_config(self, cli_proxy=None, cli_wireguard=None, cli_openvpn=None):
        """Merges CLI args with POSINT saved config."""
        self.proxy_url = None
        self.wireguard_conf = None
        self.openvpn_conf = None
        
        # Load saved config
        if hasattr(self, 'get_network_config'):
            saved = self.get_network_config()
            saved_mode = saved.get("mode", "direct")
            if saved_mode == "tor":
                self.proxy_url = "socks5://127.0.0.1:9050"
            elif saved_mode == "proxy":
                self.proxy_url = saved.get("proxy_url")
            elif saved_mode == "wireguard":
                self.wireguard_conf = saved.get("wireguard_conf")
            elif saved_mode == "openvpn":
                self.openvpn_conf = saved.get("openvpn_conf")

        # CLI overrides
        if getattr(self, 'use_tor', False):
            self.proxy_url = "socks5://127.0.0.1:9050"
        if cli_proxy:
            self.proxy_url = cli_proxy
        if cli_wireguard:
            self.wireguard_conf = cli_wireguard
        if cli_openvpn:
            self.openvpn_conf = cli_openvpn
            
        # Check sudo requirement for VPN modes
        if (self.wireguard_conf or self.openvpn_conf):
            import os
            if hasattr(os, 'geteuid') and os.geteuid() != 0:
                console.print("[bold red][!] VPN modes (WireGuard/OpenVPN) require root privileges.[/bold red]")
                console.print("[bold yellow][i] Please run the tool using: sudo professor-osint[/bold yellow]")

    def get_ip_info(self):
        """Fetches the current public IP and metadata using the active proxy."""
        proxies = None
        if getattr(self, 'proxy_url', None):
            proxies = {
                "http": self.proxy_url,
                "https": self.proxy_url
            }
        
        try:
            # We use ip-api.com as it returns clean JSON with ISP, Country, IP
            resp = requests.get("http://ip-api.com/json/", proxies=proxies, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query"),
                        "country": data.get("country"),
                        "isp": data.get("isp")
                    }
        except Exception as e:
            console.print(f"[bold red][!] Network Error while checking IP: {e}[/bold red]")
            import logging
            logging.error(f"Failed to fetch IP info: {e}")
        
        return {"ip": "Unknown", "country": "Unknown", "isp": "Unknown"}

    def _search_with_backoff(self, advanced_query, num_results, max_retries=4):
        """Run googlesearch with exponential backoff + jitter on 429 rate limits."""
        import os
        delay = 2.0
        
        # googlesearch-python explicitly drops 'socks5://' from its proxy kwarg. 
        # We must set os.environ so the underlying requests library picks it up.
        old_http = os.environ.get("HTTP_PROXY")
        old_https = os.environ.get("HTTPS_PROXY")
        proxy_url = getattr(self, 'proxy_url', None)
        if proxy_url:
            os.environ["HTTP_PROXY"] = proxy_url
            os.environ["HTTPS_PROXY"] = proxy_url

        try:
            for attempt in range(max_retries):
                try:
                    return list(search(advanced_query, num_results=num_results, lang="en"))
                except HTTPError as e:
                    if e.code == 429 and attempt < max_retries - 1:
                        sleep_for = delay + random.uniform(0, 1.5)
                        console.print(
                            f"[bold yellow][!] Google 429 rate limit — backing off "
                            f"{sleep_for:.1f}s (attempt {attempt + 1}/{max_retries})...[/bold yellow]"
                        )
                        time.sleep(sleep_for)
                        delay *= 2
                        continue
                    raise
            return []
        finally:
            if getattr(self, 'proxy_url', None):
                if old_http is not None:
                    os.environ["HTTP_PROXY"] = old_http
                else:
                    os.environ.pop("HTTP_PROXY", None)
                if old_https is not None:
                    os.environ["HTTPS_PROXY"] = old_https
                else:
                    os.environ.pop("HTTPS_PROXY", None)

    async def _throttle(self, name, per_minute):
        """Space out calls to a named rate-limited API (e.g. VirusTotal: 4/min).

        Sleeps just enough so consecutive calls under the same ``name`` honor a
        minimum interval of ``60 / per_minute`` seconds. Timestamps live in a
        lazily-created dict so this works across the tool's separate
        ``asyncio.run()`` calls without touching ``__init__``.
        """
        if per_minute <= 0:
            return
        min_interval = 60.0 / per_minute
        if not hasattr(self, "_rl_times"):
            self._rl_times = {}
        last = self._rl_times.get(name)
        now = time.monotonic()
        if last is not None:
            wait = min_interval - (now - last)
            if wait > 0:
                await asyncio.sleep(wait)
        self._rl_times[name] = time.monotonic()

    async def _resolve_async(self, host):
        """Resolve a hostname to an IP without blocking the event loop.

        Raises socket.gaierror on genuine resolution failure so callers can
        distinguish a bad target from a valid one.
        """
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None)
        return infos[0][4][0]

    def _ensure_semaphore(self):
        """Lazily create the concurrency limiter inside the active event loop."""
        if self.semaphore is None:
            self.semaphore = asyncio.Semaphore(max(1, self.threads))
        return self.semaphore
