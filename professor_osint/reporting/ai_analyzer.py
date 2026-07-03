"""AI Threat Intelligence layer.

Turns raw OSINT dumps into a polished analyst report by handing the assembled
findings to a Large Language Model. Providers are fully modular: privacy-first
local engines (Ollama, LM Studio, any OpenAI-compatible endpoint) and cloud
engines (OpenAI, DeepSeek, Gemini, Anthropic).

Design notes:
- Provider / model / endpoint preferences live in ``~/.professor_osint_config.json``.
- API keys are read from the environment (or a local ``.env`` via python-dotenv),
  matching how the rest of the tool handles secrets — they are never written to
  the plaintext config file.
- Every network call is wrapped so a missing key, an offline local model, or a
  bad response degrades gracefully and never crashes an in-progress scan.
"""
import os
import json
import logging

import requests

from ..common import console

CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".professor_osint_config.json")

# Engines that speak the OpenAI /chat/completions schema.
OPENAI_COMPATIBLE = {"openai", "deepseek", "ollama", "lmstudio", "local"}

# provider -> (env var for the API key, needs_key)
PROVIDER_KEYS = {
    "openai": ("OPENAI_API_KEY", True),
    "deepseek": ("DEEPSEEK_API_KEY", True),
    "gemini": ("GEMINI_API_KEY", True),
    "anthropic": ("ANTHROPIC_API_KEY", True),
    "ollama": (None, False),
    "lmstudio": (None, False),
    "local": (None, False),
}

# Sensible default endpoints suggested during the setup wizard.
DEFAULT_BASE_URLS = {
    "openai": "https://api.openai.com/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "ollama": "http://localhost:11434/v1",
    "lmstudio": "http://localhost:1234/v1",
    "local": "http://localhost:11434/v1",
}

DEFAULT_MODELS = {
    "openai": "gpt-4o",
    "deepseek": "deepseek-chat",
    "gemini": "gemini-1.5-pro",
    "anthropic": "claude-3-5-sonnet-latest",
    "ollama": "llama3",
    "lmstudio": "local-model",
    "local": "llama3",
}

SYSTEM_PROMPT = (
    "You are an elite Cybersecurity Threat Intelligence Analyst. You will be given "
    "raw OSINT data gathered from a target. Ignore the noise and produce a professional, "
    "concise threat intelligence report.\n\n"
    "Instructions:\n"
    "1. Identify any critical leaked credentials or data breaches.\n"
    "2. Analyze open ports and highlight high-risk attack vectors (e.g. exposed RDP or "
    "unpatched SSH).\n"
    "3. Summarize the exposed attack surface (subdomains, emails, cloud assets).\n"
    "4. Provide a prioritized 'Next Steps' mitigation plan.\n"
    "5. Do NOT hallucinate data; only analyze the provided footprint. If a section has "
    "no data, say so briefly.\n"
)


class AiAnalyzerMixin:
    """Adds LLM-powered analysis and an interactive provider setup wizard."""

    # ---- Configuration persistence -------------------------------------

    def _load_ai_config(self):
        """Return the saved AI config dict, or {} if none/unreadable."""
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f).get("ai", {})
        except (FileNotFoundError, ValueError, OSError):
            return {}

    def _save_ai_config(self, ai_config):
        """Persist the AI config, preserving any other top-level keys."""
        data = {}
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (FileNotFoundError, ValueError, OSError):
            data = {}
        data["ai"] = ai_config
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _resolve_ai_key(self, provider):
        """Fetch the API key for a provider from the environment (or None)."""
        env_var, _ = PROVIDER_KEYS.get(provider, (None, False))
        return os.getenv(env_var) if env_var else None

    # ---- LLM transport -------------------------------------------------

    def _call_llm(self, provider, model, base_url, key, system_prompt, user_data, timeout=90):
        """Dispatch a chat request to the selected provider.

        Returns the assistant's text on success, or None on any failure (the
        caller is expected to surface a friendly message).
        """
        try:
            if provider in OPENAI_COMPATIBLE:
                return self._call_openai_compatible(
                    model, base_url, key, system_prompt, user_data, timeout
                )
            if provider == "gemini":
                return self._call_gemini(model, key, system_prompt, user_data, timeout)
            if provider == "anthropic":
                return self._call_anthropic(model, key, system_prompt, user_data, timeout)
            console.print(f"[bold red][!] Unknown AI provider: {provider}[/bold red]")
            return None
        except requests.exceptions.RequestException as exc:
            logging.error("AI call failed (%s): %s", provider, exc)
            console.print(f"[bold red][!] AI request failed: {exc}[/bold red]")
            return None
        except (KeyError, IndexError, ValueError) as exc:
            logging.error("AI response parse failed (%s): %s", provider, exc)
            console.print(f"[bold red][!] Could not parse AI response: {exc}[/bold red]")
            return None

    def _call_openai_compatible(self, model, base_url, key, system_prompt, user_data, timeout):
        url = f"{base_url.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_data},
            ],
            "temperature": 0.2,
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    def _call_gemini(self, model, key, system_prompt, user_data, timeout):
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={key}"
        )
        payload = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_data}]}],
        }
        resp = requests.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()

    def _call_anthropic(self, model, key, system_prompt, user_data, timeout):
        url = "https://api.anthropic.com/v1/messages"
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": 2048,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_data}],
        }
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
        resp.raise_for_status()
        return resp.json()["content"][0]["text"].strip()

    # ---- High-level analysis -------------------------------------------

    def run_ai_analysis(self, report_content):
        """Analyze an assembled OSINT report and return the analyst write-up.

        Returns the AI text, or None if AI is not configured / the call failed.
        """
        cfg = self._load_ai_config()
        provider = cfg.get("provider")
        if not provider:
            console.print(
                "[bold yellow][!] AI analysis requested but no provider is configured. "
                "Run [white]professor-osint --config-ai[/white] to set one up.[/bold yellow]"
            )
            return None

        model = cfg.get("model") or DEFAULT_MODELS.get(provider, "")
        base_url = cfg.get("base_url") or DEFAULT_BASE_URLS.get(provider, "")
        key = self._resolve_ai_key(provider)
        _, needs_key = PROVIDER_KEYS.get(provider, (None, False))

        if needs_key and not key:
            env_var = PROVIDER_KEYS[provider][0]
            console.print(
                f"[bold yellow][!] No API key found for {provider}. Set {env_var} in your "
                f".env / environment and try again.[/bold yellow]"
            )
            return None

        console.print(
            f"\n[bold cyan]🧠 Handing off {len(report_content)} chars of intel to "
            f"{provider} ({model})...[/bold cyan]"
        )
        return self._call_llm(provider, model, base_url, key, SYSTEM_PROMPT, report_content)

    # ---- Interactive setup wizard --------------------------------------

    def config_ai_wizard(self):
        """Interactive setup + live validation for the AI provider."""
        console.print(
            "\n[bold bright_green]🧠 Professor OSINT — AI Analyst Setup[/bold bright_green]"
        )
        providers = ["ollama", "lmstudio", "openai", "deepseek", "gemini", "anthropic", "local"]
        console.print("[cyan]Available providers:[/cyan]")
        for i, p in enumerate(providers, 1):
            _, needs_key = PROVIDER_KEYS[p]
            tag = "cloud, needs API key" if needs_key else "local, no key"
            console.print(f"  [bold]{i}[/bold]) {p} [dim]({tag})[/dim]")

        while True:
            choice = input("\nSelect a provider [1-7]: ").strip()
            if choice.isdigit() and 1 <= int(choice) <= len(providers):
                provider = providers[int(choice) - 1]
                break
            console.print("[red]Invalid selection, try again.[/red]")

        _, needs_key = PROVIDER_KEYS[provider]

        default_model = DEFAULT_MODELS.get(provider, "")
        model = input(f"Model name [{default_model}]: ").strip() or default_model

        base_url = ""
        if provider in OPENAI_COMPATIBLE:
            default_url = DEFAULT_BASE_URLS.get(provider, "")
            base_url = input(f"API endpoint [{default_url}]: ").strip() or default_url

        key = self._resolve_ai_key(provider)
        if needs_key and not key:
            env_var = PROVIDER_KEYS[provider][0]
            console.print(
                f"[yellow][!] {env_var} is not set in your environment. Add it to your "
                f".env file. You can still save this config now.[/yellow]"
            )

        # Live validation with a tiny prompt.
        console.print("[cyan]Validating configuration (sending a test prompt)...[/cyan]")
        result = self._call_llm(
            provider, model, base_url, key,
            "You are a health check. Reply with the single word: OK.",
            "Hello", timeout=30,
        )
        if result is None:
            console.print(
                "[bold red][!] Validation failed. Check your key / endpoint / that the "
                "local model is running.[/bold red]"
            )
            retry = input("Save this config anyway? [y/N]: ").strip().lower()
            if retry != "y":
                console.print("[yellow]Setup aborted. Nothing was saved.[/yellow]")
                return
        else:
            console.print(f"[bold green][+] Provider responded successfully: {result[:60]}[/bold green]")

        self._save_ai_config({"provider": provider, "model": model, "base_url": base_url})
        console.print(f"[bold green][+] AI config saved to {CONFIG_PATH}[/bold green]")
