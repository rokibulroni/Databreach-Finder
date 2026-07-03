import time
import random
import asyncio
from urllib.error import HTTPError

from googlesearch import search

from ..common import console


class NetMixin:
    """Network resilience helpers: backoff, async DNS, concurrency limiting."""

    def _search_with_backoff(self, advanced_query, num_results, max_retries=4):
        """Run googlesearch with exponential backoff + jitter on 429 rate limits."""
        import os
        delay = 2.0
        
        # googlesearch-python explicitly drops 'socks5://' from its proxy kwarg. 
        # We must set os.environ so the underlying requests library picks it up.
        old_http = os.environ.get("HTTP_PROXY")
        old_https = os.environ.get("HTTPS_PROXY")
        if getattr(self, 'use_tor', False):
            os.environ["HTTP_PROXY"] = "socks5://127.0.0.1:9050"
            os.environ["HTTPS_PROXY"] = "socks5://127.0.0.1:9050"

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
            if getattr(self, 'use_tor', False):
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
