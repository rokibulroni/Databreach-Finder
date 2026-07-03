"""Deep Social Media Intelligence engine (``--social-xray``).

Extends Professor OSINT beyond username footprinting (which only checks whether
an account exists) into deep extraction of public posts, comments, and metadata
from a specific social media link.

Stable v1 sources (highest reliability, lowest maintenance):
  * YouTube — via the ``yt-dlp`` library (metadata + public comments).
  * Reddit  — via the anonymous ``.json`` endpoint (threads + subreddits).

Experimental sources (best-effort, opt-in, may break as platforms change):
  * Instagram — via ``instaloader`` using a user-supplied session id. Anonymous
    access is largely non-functional today, so a session is the primary path.
  * Facebook  — via headless ``Playwright`` Chromium (auto-scroll + DOM parse).

See ``docs/SOCIAL-MEDIA-DEEP.md`` for the full blueprint and the authorized-use /
legal boundary this module enforces. The heavy extraction deps (yt-dlp,
instaloader, playwright) ship as the optional ``[social]`` extra and are lazily
imported so the core install stays light.
"""
import os
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

# Platforms whose extraction is opt-in and best-effort — the user gets an extra
# heads-up before we engage them.
EXPERIMENTAL_PLATFORMS = {"instagram", "facebook"}


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
        if re.search(r"instagram\.com", u):
            return "instagram"
        if re.search(r"(?:facebook\.com|fb\.com|fb\.watch)", u):
            return "facebook"
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
                "[bold red][!] Unsupported target. Social X-Ray supports YouTube and "
                "Reddit (stable) plus Instagram and Facebook (experimental) links.[/bold red]"
            )
            return

        if platform in EXPERIMENTAL_PLATFORMS:
            console.print(
                f"[bold yellow][~] {platform.capitalize()} extraction is EXPERIMENTAL — "
                "it depends on the optional [white][social][/white] extra and may break "
                "as the platform changes. Best-effort only.[/bold yellow]"
            )

        console.print(
            f"[bold cyan]🛰️  Social X-Ray engaging {platform.capitalize()} target "
            f"(limit {self.limit}, comments {'ON' if self.extract_comments else 'OFF'})...[/bold cyan]"
        )

        # Dispatch to the platform-specific extractor.
        extractors = {
            "reddit": self._scan_reddit,
            "youtube": self._scan_youtube,
            "instagram": self._scan_instagram,
            "facebook": self._scan_facebook,
        }
        try:
            result = await extractors[platform](self.social_xray)
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

    # ---- Instagram (instaloader, session-based) — EXPERIMENTAL --------

    @staticmethod
    def _instagram_shortcode(url):
        """Return the post/reel shortcode from an Instagram URL, or None."""
        m = re.search(r"instagram\.com/(?:p|reel|tv)/([A-Za-z0-9_-]+)", url or "")
        return m.group(1) if m else None

    @staticmethod
    def _instagram_username(url):
        """Return a profile username from an Instagram URL, or None."""
        m = re.search(r"instagram\.com/([A-Za-z0-9_.]+)/?", url or "")
        if not m:
            return None
        handle = m.group(1)
        # Filter out non-profile path segments.
        if handle.lower() in {"p", "reel", "tv", "explore", "stories", "accounts"}:
            return None
        return handle

    async def _scan_instagram(self, url):
        """Extract an Instagram post or profile using a user-supplied session.

        Instagram blocks anonymous scraping aggressively, so the primary path is
        a logged-in session: set ``INSTAGRAM_SESSIONID`` (and ideally
        ``INSTAGRAM_USERNAME``) in your environment / .env. Using a session
        carries account-ban risk — use a throwaway/research account.
        """
        try:
            import instaloader  # lazy import — part of the optional ``social`` extra
        except ImportError:
            console.print(
                "[bold yellow][!] instaloader is not installed. Install the social extra:\n"
                "    pip install 'professor-osint\\[social]'   (or: pip install instaloader)[/bold yellow]"
            )
            return None

        sessionid = os.getenv("INSTAGRAM_SESSIONID")
        session_user = os.getenv("INSTAGRAM_USERNAME")
        if not sessionid:
            console.print(
                "[bold yellow][!] No INSTAGRAM_SESSIONID set. Anonymous Instagram access is "
                "largely blocked; set a session id in your .env (see docs) for reliable "
                "results. Attempting anonymous best-effort...[/bold yellow]"
            )

        # instaloader is fully blocking — run the whole job in a worker thread.
        return await asyncio.to_thread(
            self._instagram_extract, instaloader, url, sessionid, session_user
        )

    def _instagram_extract(self, instaloader, url, sessionid, session_user):
        """Blocking instaloader routine (posts or profiles). Returns a result dict."""
        L = instaloader.Instaloader(
            quiet=True, download_pictures=False, download_videos=False,
            download_comments=False, save_metadata=False, compress_json=False,
        )

        # Authenticate with the raw session cookie when provided.
        if sessionid:
            try:
                L.context._session.cookies.set(
                    "sessionid", sessionid, domain=".instagram.com"
                )
                verified = L.test_login()
                if verified:
                    L.context.username = verified
                    console.print(f"[bold green][+] Instagram session valid (as {verified}).[/bold green]")
                else:
                    console.print("[bold yellow][!] Instagram session id was rejected; continuing anonymously.[/bold yellow]")
            except Exception as exc:
                logging.error("Instagram session load failed: %s", exc)
                console.print("[bold yellow][!] Could not apply Instagram session; continuing anonymously.[/bold yellow]")

        shortcode = self._instagram_shortcode(url)
        try:
            if shortcode:
                return self._instagram_post(instaloader, L, url, shortcode)
            username = self._instagram_username(url)
            if username:
                return self._instagram_profile(instaloader, L, url, username)
        except Exception as exc:
            logging.error("Instagram extraction failed for %s: %s", url, exc)
            console.print(f"[bold red][!] Instagram extraction error: {exc}[/bold red]")
            return None

        console.print("[bold red][!] Could not parse an Instagram post or profile from that URL.[/bold red]")
        return None

    def _instagram_post(self, instaloader, L, url, shortcode):
        post = instaloader.Post.from_shortcode(L.context, shortcode)
        caption = (post.caption or "").strip()
        hashtags = " ".join(f"#{h}" for h in (post.caption_hashtags or []))
        location = getattr(post, "location", None)
        loc_name = location.name if location else None
        header = caption
        if hashtags:
            header = f"{header}\n{hashtags}".strip()
        if loc_name:
            header = f"{header}\n📍 {loc_name}".strip()

        entries = [{
            "type": "post",
            "author": post.owner_username,
            "timestamp": post.date_utc.strftime("%Y-%m-%d %H:%M UTC") if post.date_utc else "Unknown",
            "text": header[:2000],
            "engagement": f"{post.likes} likes / {post.comments} comments",
        }]

        if self.extract_comments:
            try:
                for c in post.get_comments():
                    if len(entries) > self.limit:
                        break
                    text = (c.text or "").strip()
                    if not text:
                        continue
                    entries.append({
                        "type": "comment",
                        "author": getattr(c.owner, "username", None),
                        "timestamp": c.created_at_utc.strftime("%Y-%m-%d %H:%M UTC") if getattr(c, "created_at_utc", None) else "Unknown",
                        "text": text,
                        "engagement": f"{getattr(c, 'likes_count', 0)} likes",
                    })
            except Exception as exc:
                logging.error("Instagram comment fetch failed (%s): %s", shortcode, exc)
                console.print("[bold yellow][!] Could not fetch Instagram comments (session/limit); keeping post data.[/bold yellow]")

        return {
            "platform": "Instagram",
            "url": url,
            "title": f"Post by @{post.owner_username}",
            "author": post.owner_username,
            "timestamp": entries[0]["timestamp"],
            "entries": entries[: self.limit + 1],
        }

    def _instagram_profile(self, instaloader, L, url, username):
        profile = instaloader.Profile.from_username(L.context, username)
        entries = [{
            "type": "profile",
            "author": profile.username,
            "timestamp": "Unknown",
            "text": (
                f"{profile.full_name or ''}\n{(profile.biography or '').strip()}"
            ).strip()[:2000],
            "engagement": f"{profile.followers} followers / {profile.followees} following / {profile.mediacount} posts",
        }]

        try:
            for post in profile.get_posts():
                if len(entries) > self.limit:
                    break
                caption = (post.caption or "").strip().replace("\n", " ")
                entries.append({
                    "type": "post",
                    "author": profile.username,
                    "timestamp": post.date_utc.strftime("%Y-%m-%d %H:%M UTC") if post.date_utc else "Unknown",
                    "text": caption[:500] or f"[media] {post.shortcode}",
                    "engagement": f"{post.likes} likes / {post.comments} comments",
                })
        except Exception as exc:
            logging.error("Instagram profile posts failed (%s): %s", username, exc)
            console.print("[bold yellow][!] Could not list profile posts (private/session); keeping bio.[/bold yellow]")

        return {
            "platform": "Instagram",
            "url": url,
            "title": f"Profile @{profile.username}",
            "author": profile.username,
            "timestamp": "Unknown",
            "entries": entries[: self.limit + 1],
        }

    # ---- Facebook (Playwright headless Chromium) — EXPERIMENTAL -------

    async def _scan_facebook(self, url):
        """Best-effort public Facebook extraction via headless Chromium.

        Facebook blocks aggressively and hides content behind login walls, so
        this is best-effort: it loads the public URL, auto-scrolls to trigger
        lazy loading, and parses visible ``role=article`` blocks. Requires
        ``playwright`` plus a one-time ``playwright install chromium``.
        """
        try:
            from playwright.async_api import async_playwright  # lazy — ``social`` extra
        except ImportError:
            console.print(
                "[bold yellow][!] playwright is not installed. Install the social extra and the browser:\n"
                "    pip install 'professor-osint\\[social]'\n"
                "    playwright install chromium[/bold yellow]"
            )
            return None

        entries = []
        try:
            async with async_playwright() as pw:
                try:
                    browser = await pw.chromium.launch(headless=True)
                except Exception as exc:
                    logging.error("Playwright chromium launch failed: %s", exc)
                    console.print(
                        "[bold yellow][!] Could not launch Chromium. Run "
                        "[white]playwright install chromium[/white] first.[/bold yellow]"
                    )
                    return None

                context = await browser.new_context(
                    user_agent=random.choice(USER_AGENTS),
                    locale="en-US",
                    viewport={"width": 1280, "height": 900},
                    proxy={"server": "socks5://127.0.0.1:9050"} if self.use_tor else None,
                )
                page = await context.new_page()
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
                await asyncio.sleep(random.uniform(2.0, 4.0))

                # Dismiss the most common cookie/login dialogs when present.
                for label in ("Allow all cookies", "Only allow essential cookies", "Decline optional cookies"):
                    try:
                        btn = page.get_by_role("button", name=label)
                        if await btn.count():
                            await btn.first.click(timeout=2500)
                            break
                    except Exception:
                        pass

                # Soft-block / login-wall detection.
                content_sample = (await page.content())[:5000].lower()
                if "you must log in to continue" in content_sample or "log into facebook" in content_sample:
                    console.print(
                        "[bold yellow][!] Facebook served a login wall — public extraction blocked "
                        "for this target. Try a public Page/post URL.[/bold yellow]"
                    )

                # Auto-scroll with randomized delays to trigger lazy loading.
                title = await page.title()
                seen = set()
                scrolls = max(3, min(12, self.limit // 5))
                for _ in range(scrolls):
                    articles = await page.locator('div[role="article"]').all_inner_texts()
                    for raw in articles:
                        text = " ".join((raw or "").split())
                        if not text or text in seen:
                            continue
                        seen.add(text)
                        entries.append({
                            "type": "post",
                            "author": None,  # FB obfuscates DOM; author left anonymous
                            "timestamp": "Unknown",
                            "text": text[:1500],
                            "engagement": "",
                        })
                        if len(entries) >= self.limit:
                            break
                    if len(entries) >= self.limit:
                        break
                    await page.mouse.wheel(0, random.randint(1500, 2600))
                    await asyncio.sleep(random.uniform(1.5, 3.0))

                await context.close()
                await browser.close()
        except Exception as exc:
            logging.error("Facebook extraction failed for %s: %s", url, exc)
            console.print(f"[bold red][!] Facebook extraction error: {exc}[/bold red]")
            return None

        if not entries:
            return None
        return {
            "platform": "Facebook",
            "url": url,
            "title": title or "Facebook target",
            "author": None,
            "timestamp": "Unknown",
            "entries": entries[: self.limit],
        }

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
