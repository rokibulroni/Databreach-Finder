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
        delay = 2.0
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
