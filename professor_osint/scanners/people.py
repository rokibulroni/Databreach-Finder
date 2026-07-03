import re
import random

from ..common import (
    console, HAS_PHONENUMBERS, phonenumbers, geocoder, carrier, timezone,
)
from ..constants import USER_AGENTS


class PeopleScannersMixin:
    """People intelligence: telecom profiling and social footprinting."""

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
        sem = self._ensure_semaphore()
        await sem.acquire()
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
            sem.release()
            if progress:
                progress.advance(task)
