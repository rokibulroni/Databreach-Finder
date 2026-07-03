"""Interactive setup wizard for the OSINT API keys (``--config-api``).

Mirrors the AI provider wizard in ``ai_analyzer.py`` but for the data-gathering
providers (Shodan, VirusTotal, Hunter.io). Keys are written to a user-global
env file, ``~/POSINT/config/api_keys.env``, which ``common.py`` loads on startup as a
fallback behind the project ``.env`` and real environment variables.

Design notes:
- Keys are the only secret written to disk, and the file is chmod 600.
- Each key gets a best-effort live validation ping so the user learns whether it
  actually works before relying on it mid-scan.
- Blank input keeps the existing value; the wizard never clobbers a key you
  don't re-enter.
"""
import os

import requests

from ..common import console
from ..constants import POSINT_CONFIG_DIR

# User-global env file loaded by common.py behind the project .env.
API_ENV_PATH = os.path.join(POSINT_CONFIG_DIR, "api_keys.env")

# (label, env var, validator-key) for each supported OSINT provider.
API_PROVIDERS = [
    ("Shodan", "SHODAN_API_KEY", "shodan"),
    ("VirusTotal", "VIRUSTOTAL_API_KEY", "virustotal"),
    ("Hunter.io", "HUNTER_API_KEY", "hunter"),
]


def _mask(value):
    """Return a masked preview of a secret (or 'not set')."""
    if not value:
        return "[dim]not set[/dim]"
    if len(value) <= 8:
        return "•" * len(value)
    return f"{value[:4]}…{value[-4:]}"


class ApiConfigMixin:
    """Adds the interactive OSINT API-key setup wizard to the orchestrator."""

    def _read_api_env_file(self):
        """Return the {KEY: value} pairs currently saved in the env file."""
        data = {}
        try:
            with open(API_ENV_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip()
        except (FileNotFoundError, OSError):
            pass
        return data

    def _write_api_env_file(self, values):
        """Persist {KEY: value} to the env file with 600 perms."""
        lines = [
            "# Professor OSINT API keys — written by `professor-osint --config-api`.",
            "# This file is loaded automatically on startup. Keep it private.",
            "",
        ]
        for _, env_var, _ in API_PROVIDERS:
            lines.append(f"{env_var}={values.get(env_var, '')}")
        with open(API_ENV_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        try:
            os.chmod(API_ENV_PATH, 0o600)
        except OSError:
            pass

    def _validate_api_key(self, kind, key):
        """Best-effort live validation ping. Returns True/False/None(unknown)."""
        try:
            if kind == "shodan":
                r = requests.get(
                    f"https://api.shodan.io/api-info?key={key}", timeout=15
                )
                return r.status_code == 200
            if kind == "virustotal":
                r = requests.get(
                    "https://www.virustotal.com/api/v3/users/current",
                    headers={"x-apikey": key}, timeout=15,
                )
                return r.status_code == 200
            if kind == "hunter":
                r = requests.get(
                    f"https://api.hunter.io/v2/account?api_key={key}", timeout=15
                )
                return r.status_code == 200
        except requests.exceptions.RequestException:
            return None
        return None

    def config_api_wizard(self):
        """Interactive setup + live validation for the OSINT API keys."""
        console.print(
            "\n[bold bright_green]🔑 Professor OSINT — API Key Setup[/bold bright_green]"
        )
        console.print(
            "[dim]Leave a prompt blank to keep the current value. Keys are saved to "
            f"{API_ENV_PATH} (chmod 600).[/dim]\n"
        )

        # Seed with whatever is already active (env / project .env / this file).
        saved = self._read_api_env_file()
        values = {}
        for label, env_var, kind in API_PROVIDERS:
            current = os.getenv(env_var) or saved.get(env_var, "")
            console.print(f"[cyan]{label}[/cyan] — current: {_mask(current)}")
            try:
                entered = input(f"Enter {label} API Key (blank = keep/skip): ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\n[yellow]Setup aborted. Nothing was saved.[/yellow]")
                return

            key = entered or current
            values[env_var] = key

            if entered:
                console.print("[cyan]Validating key...[/cyan]")
                ok = self._validate_api_key(kind, key)
                if ok is True:
                    console.print(f"[bold green][+] {label} key is valid.[/bold green]\n")
                elif ok is False:
                    console.print(
                        f"[bold red][!] {label} key was rejected by the provider. "
                        f"Saving anyway — re-run to fix.[/bold red]\n"
                    )
                else:
                    console.print(
                        f"[yellow][!] Could not reach {label} to validate "
                        f"(offline?). Saving anyway.[/yellow]\n"
                    )
            else:
                console.print("")

        self._write_api_env_file(values)
        console.print(f"[bold green][+] API keys saved to {API_ENV_PATH}[/bold green]")
        console.print(
            "[dim]These load automatically on your next scan. A project-level .env "
            "or a real environment variable still takes precedence.[/dim]"
        )
