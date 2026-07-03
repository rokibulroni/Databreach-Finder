"""Shared runtime state: console, logging, optional dependencies."""
import os
import re
import logging

from rich.console import Console

console = Console()

# API keys frequently ride in query strings (?key=..., ?api_key=...). Scrub them
# before anything reaches the log file or the terminal.
_SECRET_QS_RE = re.compile(r"(?i)([?&](?:api[_-]?key|key|token|apikey)=)[^&\s]+")


def redact(text):
    """Return ``text`` with any key/token query-string values masked."""
    if not text:
        return text
    return _SECRET_QS_RE.sub(r"\1***REDACTED***", str(text))

# Configure Logging
logging.basicConfig(
    filename='databreach_app.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    HAS_PHONENUMBERS = True
except ImportError:
    phonenumbers = None
    geocoder = carrier = timezone = None
    HAS_PHONENUMBERS = False

try:
    # Optional: load API keys from a local .env file if python-dotenv is installed.
    from dotenv import load_dotenv
    # Project-level .env first (does not override real env vars), then a
    # user-global file written by `--config-api` as a cross-directory fallback.
    # load_dotenv never overrides already-set vars, so precedence is:
    #   real environment  >  project .env  >  ~/.professor_osint.env
    load_dotenv()
    load_dotenv(os.path.join(os.path.expanduser("~"), ".professor_osint.env"))
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False
