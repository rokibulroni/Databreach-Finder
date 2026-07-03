import datetime
import logging

from ..common import console


class HtmlReportMixin:
    """Renders the modern responsive HTML intelligence report."""

    def generate_html_report(self):
        html_content = f"""<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>OSINT Intelligence Report</title>
            <style>
                :root {{
                    --bg: #0d1117; --panel: #161b22; --panel-alt: #1c2330;
                    --border: #30363d; --text: #e6edf3; --muted: #8b949e;
                    --accent: #58a6ff; --accent-2: #2ecc71; --danger: #f85149;
                }}
                * {{ box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                    margin: 0; padding: 0; background: var(--bg); color: var(--text); line-height: 1.55;
                }}
                .container {{ max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }}
                header.report-header {{
                    background: linear-gradient(135deg, #161b22 0%, rgba(31,111,235,0.15) 100%);
                    border: 1px solid var(--border); border-radius: 14px; padding: 28px 32px; margin-bottom: 12px;
                }}
                header.report-header h1 {{ margin: 0 0 6px; font-size: 1.9rem; }}
                .meta {{ color: var(--muted); font-size: 0.92rem; }}
                .meta p {{ margin: 2px 0; }}
                h2 {{ margin: 40px 0 14px; font-size: 1.3rem; border-left: 4px solid var(--accent); padding-left: 12px; }}
                h3 {{ color: var(--muted); margin: 18px 0 8px; }}
                a {{ color: var(--accent); text-decoration: none; word-break: break-all; }}
                a:hover {{ text-decoration: underline; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 12px; background: var(--panel); border-radius: 10px; overflow: hidden; }}
                th, td {{ border-bottom: 1px solid var(--border); padding: 12px 14px; text-align: left; vertical-align: top; }}
                th {{ background: var(--panel-alt); font-weight: 600; letter-spacing: .02em; }}
                tr:last-child td {{ border-bottom: none; }}
                tr:hover td {{ background: #1b2230; }}
                .alert-row td {{ background: #3d1f14 !important; border-left: 3px solid var(--danger); }}
                .profile-img {{ width: 60px; height: 60px; border-radius: 50%; object-fit: cover; border: 2px solid var(--border); }}
                .bio-text {{ font-size: 0.9rem; color: var(--muted); margin-top: 5px; }}
                .webcheck-box, .webcheck-grid {{ background: var(--panel); border: 1px solid var(--border); padding: 18px 20px; border-radius: 10px; margin-top: 12px; }}
                .webcheck-item {{ margin-bottom: 8px; }}
                .webcheck-item strong {{ color: var(--muted); font-weight: 600; }}
                .tool-card {{ background: var(--panel); border-left: 4px solid var(--accent-2); padding: 12px 16px; margin-bottom: 10px; border-radius: 8px; }}
                pre {{ background: #010409; border: 1px solid var(--border); border-radius: 8px; padding: 12px; overflow-x: auto; }}
                code {{ font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; font-size: 0.85rem; }}
                @media (max-width: 640px) {{
                    .container {{ padding: 18px 12px 40px; }}
                    header.report-header {{ padding: 20px; }}
                    th, td {{ padding: 9px 10px; }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
            <header class="report-header">
                <h1>🔍 OSINT Intelligence Report</h1>
                <div class="meta">
                    <p><strong>Target Query:</strong> {self.query or 'N/A'}</p>
                    <p><strong>Target Username:</strong> {self.username or 'N/A'}</p>
                    <p><strong>Date:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                </div>
            </header>
        """
        
        if self.recommended_tools:
            html_content += """
            <h2>💡 Recommended OSINT Arsenal Tools (via API)</h2>
            <p>Based on your extraction type, the live OSINT API recommends investigating further with these tools:</p>
            """
            for tool in self.recommended_tools:
                html_content += f"<div class='tool-card'><strong>{tool['name']}</strong><br><a href='{tool['url']}' target='_blank'>{tool['url']}</a></div>"
                
        if self.playbook_commands:
            html_content += """
            <h2>🚀 Terminal Execution Playbook (via API)</h2>
            <p>Directly copy and paste these commands into your terminal to investigate this target further:</p>
            """
            for block in self.playbook_commands:
                for cmd in block['commands']:
                    html_content += f"<div class='tool-card'><strong>Terminal Command:</strong><br><pre><code>{cmd['command']}</code></pre><p class='bio-text'>{cmd['explanation']}</p></div>"
        
        if self.webcheck_results:
            html_content += f"""
            <h2>🌐 Web Infrastructure Analysis (Web-Check)</h2>
            <div class="webcheck-box">
                <div class="webcheck-item"><strong>Domain:</strong> {self.webcheck_results.get('domain')}</div>
                <div class="webcheck-item"><strong>Resolved IP:</strong> {self.webcheck_results.get('ip')}</div>
                <div class="webcheck-item"><strong>Geolocation:</strong> {self.webcheck_results.get('location')}</div>
                <div class="webcheck-item"><strong>Hosting/ISP:</strong> {self.webcheck_results.get('isp')} {self.webcheck_results.get('org')}</div>
                <div class="webcheck-item"><strong>Server Tech:</strong> {self.webcheck_results.get('server')}</div>
                <div class="webcheck-item"><strong>Backend Tech (X-Powered-By):</strong> {self.webcheck_results.get('powered_by', 'Hidden')}</div>
                <div class="webcheck-item"><strong>Security Header (X-Frame-Options):</strong> {self.webcheck_results.get('x_frame_options')}</div>
                <div class="webcheck-item"><strong>Security Header (X-XSS-Protection):</strong> {self.webcheck_results.get('x_xss_protection')}</div>
            </div>
            """
        
        if self.results:
            html_content += """
            <h2>🚨 Professor OSINT Findings</h2>
            <table>
                <tr>
                    <th width="30%">Source URL</th>
                    <th>Extracted Data Snippet (New Unique Findings)</th>
                </tr>
            """
            for res in self.results:
                data_snippet = "<br>".join(res['data'][:5])
                if len(res['data']) > 5:
                    data_snippet += f"<br><em>...and {len(res['data']) - 5} more</em>"
                html_content += f"<tr><td><a href='{res['url']}'>{res['url']}</a></td><td>{data_snippet}</td></tr>"
            html_content += "</table>"
            
        if self.workspace_results:
            html_content += """
            <h2>🏢 Enterprise Workspace Intelligence (Exposed Files)</h2>
            <p>The following corporate/personal Drive/Docs/Sheets links were found publicly exposed for the target:</p>
            <table>
                <tr><th>Public Workspace Asset URL</th></tr>
            """
            for url in self.workspace_results:
                html_content += f"<tr><td><a href='{url}'>{url}</a></td></tr>"
            html_content += "</table>"
            
        if self.phone_results:
            status_color = "#2ecc71" if self.phone_results.get('valid') else "#e74c3c"
            html_content += f"""
            <h2>📞 Telecom Intelligence Engine</h2>
            <div class="webcheck-box">
                <div class="webcheck-item"><strong>E164 Format:</strong> {self.phone_results.get('e164', 'N/A')}</div>
                <div class="webcheck-item"><strong>International Format:</strong> {self.phone_results.get('international', 'N/A')}</div>
                <div class="webcheck-item"><strong>Validity:</strong> <span style="color: {status_color}; font-weight: bold;">{self.phone_results.get('valid', 'False')}</span></div>
                <div class="webcheck-item"><strong>Location/Region:</strong> {self.phone_results.get('location', 'Unknown')}</div>
                <div class="webcheck-item"><strong>Carrier/ISP:</strong> {self.phone_results.get('carrier', 'Unknown')}</div>
                <div class="webcheck-item"><strong>Timezone(s):</strong> {self.phone_results.get('timezones', 'Unknown')}</div>
            </div>
            """
            
        if self.harvester_results.get('subdomains') or self.harvester_results.get('emails'):
            html_content += "<h2>🌾 Domain Intelligence (Subdomains & Emails)</h2>"
            if self.harvester_results['subdomains']:
                html_content += "<h3>Discovered Subdomains</h3><ul>"
                for sub in sorted(list(self.harvester_results['subdomains']))[:50]:
                    html_content += f"<li>{sub}</li>"
                html_content += "</ul>"
            if self.harvester_results['emails']:
                html_content += "<h3>Discovered Emails</h3><ul>"
                for em in self.harvester_results['emails']:
                    html_content += f"<li>{em}</li>"
                html_content += "</ul>"
                
        if self.spider_results:
            html_content += f"""
            <h2>🕸️ Attack Surface Mapping Engine</h2>
            <div class="webcheck-box">
                <div class="webcheck-item"><strong>Resolved IP:</strong> {self.spider_results.get('resolved_ip', 'N/A')}</div>
                <div class="webcheck-item"><strong>Open Ports:</strong> {', '.join(map(str, self.spider_results.get('ports', []))) or 'None Detected'}</div>
                <div class="webcheck-item"><strong>Hostnames:</strong> {', '.join(self.spider_results.get('hostnames', [])) or 'None Detected'}</div>
                <div class="webcheck-item"><strong>Tags:</strong> {', '.join(self.spider_results.get('tags', [])) or 'None Detected'}</div>
                <div class="webcheck-item"><strong>Vulnerabilities (CVEs):</strong> {', '.join(self.spider_results.get('vulns', [])) or 'No Known CVEs'}</div>
            </div>
            """
            
        if self.awesome_results:
            html_content += """
            <h2>⭐ Awesome Hacking Toolkit</h2>
            <table>
                <tr><th>Repository</th><th>Description</th><th>Stars</th><th>Link</th></tr>
            """
            for repo in self.awesome_results:
                desc = str(repo['description']).replace('<', '&lt;').replace('>', '&gt;')
                html_content += f"<tr><td>{repo['name']}</td><td>{desc}</td><td>⭐ {repo['stars']}</td><td><a href='{repo['url']}' target='_blank'>View</a></td></tr>"
            html_content += "</table>"
            
        if self.toolbox_results:
            html_content += """
            <h2>🧰 The Professor's Toolbox</h2>
            <table>
                <tr><th>Tool Name</th><th>Category</th><th>Description</th><th>Install Command</th></tr>
            """
            for tool in self.toolbox_results:
                html_content += f"<tr><td>{tool['name']}</td><td>{tool['category']}</td><td>{tool['desc']}</td><td><code>{tool['install']}</code></td></tr>"
            html_content += "</table>"
            
        if self.rustscan_results:
            html_content += """
            <h2>⚡ Active Port Scan Engine</h2>
            <div class="webcheck-grid">
                <div class="webcheck-item"><strong>Open Ports:</strong> """ + ", ".join(map(str, self.rustscan_results)) + """</div>
            </div>
            """
            
        if self.social_results:
            section_title = "👤 Deep Dossier Extraction" if self.dossier else "👤 Social Media Footprint"
            html_content += f"""
            <h2>{section_title}</h2>
            <table>
                <tr>
                    <th width="15%">Username</th>
                    <th width="15%">Platform</th>
                    <th width="30%">Profile URL</th>
                    <th>Extracted Metadata (Dossier)</th>
                    <th width="10%">Confidence</th>
                </tr>
            """
            for profile in self.social_results:
                platform = profile['platform']
                url = profile['url']
                bio = profile.get('bio')
                img = profile.get('image_url')
                conf = profile.get('confidence', '100%')
                uname = profile.get('username', self.username)
                
                meta_html = ""
                if img:
                    meta_html += f"<img src='{img}' class='profile-img' alt='Avatar'><br>"
                if bio:
                    meta_html += f"<div class='bio-text'><strong>Bio:</strong> {bio}</div>"
                if not meta_html:
                    meta_html = "<span style='color:#999'>No metadata extracted</span>"
                    
                conf_color = "#2ecc71" if conf == "100%" else "#f1c40f" if conf == "75%" else "#e74c3c"
                conf_html = f"<span style='font-weight:bold; color:{conf_color}'>{conf}</span>"
                    
                html_content += f"<tr><td>{uname}</td><td><strong>{platform}</strong></td><td><a href='{url}'>{url}</a></td><td>{meta_html}</td><td>{conf_html}</td></tr>"
            html_content += "</table>"
            
        if self.news_results:
            html_content += """
            <h2>📡 Live Threat Intelligence (WorldMonitor)</h2>
            <p style="color: #c0392b;"><strong>Warning:</strong> Target detected in recent global cyber/news feeds!</p>
            <table>
                <tr>
                    <th width="30%">Intelligence Source</th>
                    <th>Headline / Mention</th>
                </tr>
            """
            for source, headline in self.news_results:
                html_content += f"<tr class='alert-row'><td><strong>{source}</strong></td><td>{headline}</td></tr>"
            html_content += "</table>"
            
        html_content += """
            <footer style="margin-top:48px; padding-top:18px; border-top:1px solid #30363d; color:#8b949e; font-size:0.82rem; text-align:center;">
                Generated by Professor OSINT &middot; Enterprise Intelligence Report
            </footer>
            </div>
        </body>
        </html>
        """

        filename = f'report_{self.timestamp}.html'
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        console.print(f"[bold green][+] Professional HTML report saved to {filename}[/bold green]")
        logging.info(f"Report generated: {filename}")
