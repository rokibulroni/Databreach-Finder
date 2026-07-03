"""Deep Social Media Intelligence engine (``--social-xray``).

Extends Professor OSINT beyond username footprinting (which only checks whether
an account exists) into deep extraction of public posts, comments, and metadata
from a specific social media link.

v1 targets the two highest-reliability, lowest-maintenance public sources:
  * YouTube — via the ``yt-dlp`` library (metadata + public comments).
  * Reddit  — via the anonymous ``.json`` endpoint (threads + subreddits).

Heavier headless-browser platforms (Facebook / LinkedIn / Instagram / X) are
intentionally deferred; see ``docs/SOCIAL-MEDIA-DEEP.md`` for the full blueprint
and the authorized-use / legal boundary this module enforces.
"""
import re
import random
import datetime
import hashlib
import asyncio
import logging

import aiohttp
from rich.panel import Panel

from ..common import console
from ..constants import USER_AGENTS


class SocialXrayMixin:
    """Adds the deep social-media extraction engine to the orchestrator."""

    # ---- Authorized-use gate ------------------------------------------

    def _social_xray_authorized(self):
        """Enforce the §0 authorized-use boundary before any scraping.

        Passing ``--i-am-authorized`` skips the interactive prompt (useful for
        automation); otherwise the user must confirm at the terminal.
        """
        if self.authorized:
            return True

        console.print(Panel(
            "[bold]This module extracts public posts and comments that may contain "
            "personal data (author names, timestamps, locations, and text that can "
            "include emails or phone numbers).[/bold]\n\n"
            "You are responsible for lawful, authorized use and for respecting the "
            "target platform's Terms of Service. Author identifiers are stored "
            "anonymized (hashed) in the local database by default.",
            title="[bold red]⚠️  Authorized Use Required[/bold red]",
            border_style="red", expand=False,
        ))
        try:
            answer = input("Do you confirm you are authorized to scan this target? [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer == "y":
            return True
        console.print("[yellow][!] Social X-Ray aborted — authorization not confirmed.[/yellow]")
        return False

    # ---- Small helpers ------------------------------------------------

    @staticmethod
    def _anon_author(author):
        """Return a stable, non-reversible identifier for a public author.

        Keeps raw PII out of the persisted database while still allowing the
        same author to be correlated across entries.
        """
        if not author or author in ("[deleted]", "None"):
            return "anonymous"
        return "usr_" + hashlib.sha256(author.encode("utf-8", "replace")).hexdigest()[:12]

    @staticmethod
    def _detect_platform(url):
        u = (url or "").lower()
        if re.search(r"(?:youtube\.com|youtu\.be)", u):
            return "youtube"
        if re.search(r"reddit\.com", u):
            return "reddit"
        return None

    @staticmethod
    def _fmt_epoch(created_utc):
        try:
            return datetime.datetime.utcfromtimestamp(float(created_utc)).strftime("%Y-%m-%d %H:%M UTC")
        except (ValueError, TypeError, OSError):
            return "Unknown"

    @staticmethod
    def _fmt_yt_date(raw):
        s = str(raw or "")
        if len(s) != 8 or not s.isdigit():
            return "Unknown"
        return f"{s[:4]}-{s[4:6]}-{s[6:]}"

    def _xray_connector(self):
        """Route through the local Tor SOCKS5 proxy when ``--tor`` is set."""
        if self.use_tor:
            from aiohttp_socks import ProxyConnector
            return ProxyConnector.from_url("socks5://127.0.0.1:9050")
        return None

    # ---- Orchestrator -------------------------------------------------

    async def social_xray_scan(self):
        """Entry point invoked from the CLI when ``--social-xray`` is set."""
        if not self.social_xray:
            return
        if not self._social_xray_authorized():
            return

        platform = self._detect_platform(self.social_xray)
        if platform is None:
            console.print(
                "[bold red][!] Unsupported target. Social X-Ray v1 supports YouTube "
                "and Reddit links only.[/bold red]"
            )
            return

        console.print(
            f"[bold cyan]🛰️  Social X-Ray engaging {platform.capitalize()} target "
            f"(limit {self.limit}, comments {'ON' if self.extract_comments else 'OFF'})...[/bold cyan]"
        )

        try:
            if platform == "reddit":
                result = await self._scan_reddit(self.social_xray)
            else:
                result = await self._scan_youtube(self.social_xray)
        except Exception as exc:  # never let a scraper failure crash the run
            logging.error("Social X-Ray failed for %s: %s", self.social_xray, exc)
            console.print(f"[bold red][!] Social X-Ray extraction error: {exc}[/bold red]")
            return

        if result and result.get("entries"):
            self.social_xray_results.append(result)
            self._persist_social_xray(result)
            console.print(
                f"[bold green][+] Social X-Ray extracted {len(result['entries'])} "
                f"item(s) from {result['platform']}.[/bold green]"
            )
        else:
            console.print("[bold yellow][!] Social X-Ray found no extractable public content.[/bold yellow]")

    # ---- Reddit (.json) -----------------------------------------------

    async def _reddit_fetch_json(self, session, url):
        """Fetch a Reddit ``.json`` endpoint with backoff on throttling.

        Reddit blocks anonymous requests both by rate limit (429) and, from
        datacenter / cloud IP ranges, by outright refusal (403). Both are
        transient-ish from a residential IP, so a browser-like User-Agent is
        used and blocks are retried with exponential backoff.
        """
        clean = url.split("?")[0].split("#")[0].rstrip("/")
        json_url = f"{clean}/.json?limit={int(self.limit)}&raw_json=1"

        for attempt in range(4):
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "application/json",
            }
            try:
                async with session.get(json_url, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status in (403, 429):
                        wait = 2 ** attempt
                        console.print(
                            f"[yellow][!] Reddit throttled the request ({resp.status}); "
                            f"backing off {wait}s...[/yellow]"
                        )
                        await asyncio.sleep(wait)
                        continue
                    resp.raise_for_status()
                    # Reddit occasionally serves an HTML interstitial with a 200;
                    # only accept genuine JSON payloads.
                    return await resp.json(content_type=None)
            except aiohttp.ClientResponseError as exc:
                logging.error("Reddit fetch failed (%s): %s", json_url, exc)
                return None
            except (aiohttp.ContentTypeError, ValueError) as exc:
                logging.error("Reddit returned non-JSON (%s): %s", json_url, exc)
                return None
        console.print(
            "[bold red][!] Reddit kept blocking the request (rate limit / IP block). "
            "Try again later, from a different network, or via [white]--tor[/white].[/bold red]"
        )
        return None

    async def _scan_reddit(self, url):
        connector = self._xray_connector()
        async with aiohttp.ClientSession(connector=connector) as session:
            with console.status("[bold blue]Extracting Reddit target via .json endpoint...[/bold blue]", spinner="dots"):
                data = await self._reddit_fetch_json(session, url)

        if not data:
            return None

        entries, title, author, ts = [], None, None, None

        if isinstance(data, list):
            # A specific post/thread: [post_listing, comments_listing]
            post_children = data[0].get("data", {}).get("children", []) if data else []
            if post_children:
                p = post_children[0].get("data", {})
                title = p.get("title")
                author = p.get("author")
                ts = self._fmt_epoch(p.get("created_utc"))
                entries.append({
                    "type": "post",
                    "author": author,
                    "timestamp": ts,
                    "text": (p.get("selftext") or p.get("url") or "").strip(),
                    "engagement": f"{p.get('score', 0)} pts / {p.get('num_comments', 0)} comments",
                })
            if self.extract_comments and len(data) > 1:
                self._collect_reddit_comments(
                    data[1].get("data", {}).get("children", []), entries
                )
        else:
            # A subreddit / listing: a single listing of posts.
            children = data.get("data", {}).get("children", [])
            subreddit = children[0].get("data", {}).get("subreddit") if children else None
            title = f"r/{subreddit}" if subreddit else "Reddit listing"
            for c in children:
                if len(entries) >= self.limit:
                    break
                p = c.get("data", {})
                entries.append({
                    "type": "post",
                    "author": p.get("author"),
                    "timestamp": self._fmt_epoch(p.get("created_utc")),
                    "text": (p.get("title") or "").strip(),
                    "engagement": f"{p.get('score', 0)} pts / {p.get('num_comments', 0)} comments",
                })

        return {
            "platform": "Reddit",
            "url": url,
            "title": title or "Reddit target",
            "author": author,
            "timestamp": ts,
            "entries": entries[: self.limit],
        }

    def _collect_reddit_comments(self, children, entries):
        """Recursively flatten a Reddit comment forest, honoring ``--limit``."""
        for c in children:
            if len(entries) >= self.limit:
                return
            if c.get("kind") != "t1":
                continue
            d = c.get("data", {})
            body = (d.get("body") or "").strip()
            if body:
                entries.append({
                    "type": "comment",
                    "author": d.get("author"),
                    "timestamp": self._fmt_epoch(d.get("created_utc")),
                    "text": body,
                    "engagement": f"{d.get('score', 0)} pts",
                })
            replies = d.get("replies")
            if isinstance(replies, dict):
                self._collect_reddit_comments(
                    replies.get("data", {}).get("children", []), entries
                )

    # ---- YouTube (yt-dlp) ---------------------------------------------

    async def _scan_youtube(self, url):
        try:
            import yt_dlp  # lazy import — part of the optional ``social`` extra
        except ImportError:
            console.print(
                "[bold yellow][!] yt-dlp is not installed. Install the social extra:\n"
                "    pip install 'professor-osint\\[social]'   (or: pip install yt-dlp)[/bold yellow]"
            )
            return None

        opts = {
            "quiet": True,
            "no_warnings": True,
            "skip_download": True,
            "extract_flat": False,
            "getcomments": bool(self.extract_comments),
            # Cap comment pagination so large videos don't run for many minutes.
            "extractor_args": {"youtube": {"max_comments": [str(int(self.limit))]}},
        }

        with console.status("[bold blue]Extracting YouTube metadata via yt-dlp...[/bold blue]", spinner="dots"):
            info = await asyncio.to_thread(self._yt_extract, yt_dlp, url, opts)

        if not info:
            return None

        entries = [{
            "type": "video",
            "author": info.get("uploader") or info.get("channel"),
            "timestamp": self._fmt_yt_date(info.get("upload_date")),
            "text": (info.get("description") or "").strip()[:2000],
            "engagement": f"{info.get('view_count', 0)} views / {info.get('like_count', 0)} likes",
        }]

        for c in (info.get("comments") or [])[: self.limit]:
            text = (c.get("text") or "").strip()
            if not text:
                continue
            entries.append({
                "type": "comment",
                "author": c.get("author"),
                "timestamp": self._fmt_epoch(c.get("timestamp")),
                "text": text,
                "engagement": f"{c.get('like_count', 0) or 0} likes",
            })

        return {
            "platform": "YouTube",
            "url": url,
            "title": info.get("title") or "YouTube target",
            "author": info.get("uploader") or info.get("channel"),
            "timestamp": self._fmt_yt_date(info.get("upload_date")),
            "entries": entries[: self.limit + 1],
        }

    @staticmethod
    def _yt_extract(yt_dlp, url, opts):
        """Blocking yt-dlp call, run in a worker thread via ``asyncio.to_thread``."""
        try:
            with yt_dlp.YoutubeDL(opts) as ydl:
                return ydl.extract_info(url, download=False)
        except Exception as exc:
            logging.error("yt-dlp extraction failed for %s: %s", url, exc)
            return None

    # ---- Persistence --------------------------------------------------

    def _persist_social_xray(self, result):
        platform, url = result["platform"], result["url"]
        for e in result["entries"]:
            self.save_social_xray_to_db(
                platform,
                url,
                e.get("type", "item"),
                self._anon_author(e.get("author")),
                e.get("timestamp"),
                e.get("text"),
                e.get("engagement"),
            )
