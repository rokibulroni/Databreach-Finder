"""Shared runtime state: console, logging, optional dependencies."""
import os
import logging

from rich.console import Console

console = Console()

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
    load_dotenv()
    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False
