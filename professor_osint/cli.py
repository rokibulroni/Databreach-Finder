import asyncio
import argparse

from .common import console
from .constants import PATTERNS, POSINT_CONFIG_DIR
from .core.finder import ProfessorOSINT
import os


def main():
    epilog_text = """
Usage Examples:
  1. Attack Surface & Port Scan:
     professor-osint -q "tesla.com" --spider --rustscan

  2. Social Media Recon (Deep Dossier):
     professor-osint -u "target_username" --analyzer --dossier

  3. Enterprise Workspace Hunt (Google Docs, Trello, Notion):
     professor-osint -q "company_name" --workspace

  4. Network Security & IP Masking:
     professor-osint -q "target.com" --spider --proxy socks5://127.0.0.1:9050

  5. Social X-Ray (Extract YouTube/Reddit data):
     professor-osint --social-xray "https://youtube.com/watch?v=..." --extract-comments

  6. AI Threat Intelligence Report:
     professor-osint -q "example.com" --spider --ai-analyze
"""
    parser = argparse.ArgumentParser(
        description="Professor OSINT [Enterprise OSINT]",
        epilog=epilog_text,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("-q", "--query", help="Target search keyword/query (Domain or Company)")
    parser.add_argument("-u", "--username", help="Target username to hunt across social media (Social Recon feature)")
    parser.add_argument("-x", "--dossier", action="store_true", help="Generate Deep Dossier for username")
    parser.add_argument("-m", "--monitor", action="store_true", help="Global Threat Monitor (Live OSINT News Integration)")
    parser.add_argument("-w", "--webcheck", action="store_true", help="Live Domain Intelligence (DNS, SSL, Headers)")
    parser.add_argument("-a", "--analyzer", action="store_true", help="Perform Social Analyzer permutations and confidence scoring")
    parser.add_argument("--workspace", action="store_true", help="Enterprise Workspace Intelligence (Google Drive, Docs, Trello, Notion)")
    parser.add_argument("--phone", action="store_true", help="Telecom Intelligence Profile (Carrier, Region, and Footprint Dorking)")
    parser.add_argument("--harvester", action="store_true", help="Domain Intelligence Engine (Rapid Subdomain and Email Enumeration)")
    parser.add_argument("--spider", action="store_true", help="Attack Surface Mapping Engine (Ports, CVEs)")
    parser.add_argument("--awesome", action="store_true", help="Resource Discovery Engine (Discover Top Curated GitHub Tools)")
    parser.add_argument("--toolbox", action="store_true", help="The Professor's Toolbox (Built-in Installer Menu)")
    parser.add_argument("--rustscan", action="store_true", help="RustScan Engine (Ultra-Fast Asynchronous Port Scanner)")
    parser.add_argument("--social-xray", dest="social_xray", metavar="URL", help="Deep Social Media Intelligence: extract public posts/comments from a YouTube or Reddit link")
    parser.add_argument("--extract-comments", dest="extract_comments", action="store_true", help="Force the Social X-Ray engine to also scrape public comments under the target")
    parser.add_argument("--ai-analyze", dest="ai_analyze", action="store_true", help="AI Threat Intelligence Analysis (turn raw OSINT dumps into an analyst report)")
    parser.add_argument("--config-ai", dest="config_ai", action="store_true", help="Interactive setup wizard for the AI analyst (provider, model, endpoint)")
    parser.add_argument("--config-api", action="store_true", help="Launch interactive wizard to configure OSINT API keys (Shodan, VT, etc.)")
    parser.add_argument("-r", "--recommend", action="store_true", help="Fetch OSINT tool recommendations from your Live API ecosystem")
    parser.add_argument("-p", "--playbook", action="store_true", help="Fetch ready-to-run Terminal commands for your target")
    parser.add_argument("-e", "--extract", choices=list(PATTERNS.keys()), help="Specific data pattern to extract from dumps")
    parser.add_argument("--limit", type=int, default=200, help="Maximum number of items to extract (e.g., comments) (default: 200)")
    parser.add_argument("--i-am-authorized", dest="authorized", action="store_true", help="Acknowledge you have permission to perform this scan (Required)")
    
    # Network Security Arguments
    parser.add_argument("--ip-info", action="store_true", help="Display current public IP, Country, and ISP information before scanning")
    parser.add_argument("--proxy", metavar="URL", help="Route traffic through a custom proxy (e.g. socks5://127.0.0.1:9050)")
    parser.add_argument("--wireguard", metavar="CONF", help="Path to a WireGuard .conf file to connect VPN before scanning")
    parser.add_argument("--openvpn", metavar="CONF", help="Path to an OpenVPN .ovpn file to connect VPN before scanning")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent connections (default: 10)")
    parser.add_argument("--tor", action="store_true", help="Legacy alias for --proxy socks5://127.0.0.1:9050")
    parser.add_argument("--report", choices=['html'], help="Generate a professional HTML report")
    
    default_config = os.path.join(POSINT_CONFIG_DIR, "config.json")
    parser.add_argument("-c", "--config", default=default_config, help=f"Path to custom config file (default: {default_config})")
    
    args = parser.parse_args()

    # Setup command: launch the AI provider wizard and exit before scanning.
    if args.config_ai:
        ProfessorOSINT(config_path=args.config).config_ai_wizard()
        return

    # Setup command: launch the OSINT API-key wizard and exit before scanning.
    if args.config_api:
        ProfessorOSINT(config_path=args.config).config_api_wizard()
        return

    if not args.query and not args.username and not args.social_xray:
        console.print("[bold red][!] You must provide a --query (-q), a --username (-u), or a --social-xray URL.[/bold red]")
        return

    finder = ProfessorOSINT(
        query=args.query,
        username=args.username,
        extract_type=args.extract, 
        threads=args.threads,
        use_tor=args.tor,
        report_format=args.report,
        config_path=args.config,
        monitor=args.monitor,
        dossier=args.dossier,
        webcheck=args.webcheck,
        recommend=args.recommend,
        playbook=args.playbook,
        analyzer=args.analyzer,
        workspace=args.workspace,
        phone=args.phone,
        harvester=args.harvester,
        spider=args.spider,
        awesome=args.awesome,
        toolbox=args.toolbox,
        rustscan=args.rustscan,
        ai_analyze=args.ai_analyze,
        social_xray=args.social_xray,
        extract_comments=args.extract_comments,
        limit=args.limit,
        authorized=args.authorized,
        cli_proxy=args.proxy,
        cli_wireguard=args.wireguard,
        cli_openvpn=args.openvpn,
        ip_info=args.ip_info
    )
    finder.print_banner()
    finder.phone_intelligence()
    finder.search_toolbox()
    if finder.harvester:
        asyncio.run(finder.harvester_search_async())
    if finder.spider:
        asyncio.run(finder.spider_search_async())
    if finder.rustscan:
        asyncio.run(finder.rustscan_async())
    if finder.awesome:
        asyncio.run(finder.awesome_hacking_search_async())
    finder.dork_search()
    finder.workspace_search()
    asyncio.run(finder.process_urls_async())
    if finder.social_xray:
        asyncio.run(finder.social_xray_scan())
    finder.display_results()


if __name__ == "__main__":
    main()
