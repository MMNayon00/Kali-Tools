"""
Report Generator Module
Aggregate results and generate structured reports
Supports CLI, JSON, HTML, and PDF formats
"""

import json
import html as _html
from datetime import datetime
from pathlib import Path
from typing import Dict
from colorama import Fore, Style

# Reuse the JS Hidden Document Intelligence HTML renderer when available
try:
    from modules.js_hidden_doc_intel import _generate_html_section as _js_html_section
except Exception:  # pragma: no cover - fallback when run as a loose script
    try:
        from js_hidden_doc_intel import _generate_html_section as _js_html_section
    except Exception:
        _js_html_section = None


def _esc(value) -> str:
    """HTML-escape any value, rendering None/empty as a dash."""
    if value is None or value == "" or value == []:
        return "&mdash;"
    return _html.escape(str(value))


def _safe_filename(target: str) -> str:
    """Turn a target into a filesystem-safe slug for report filenames."""
    slug = "".join(c if (c.isalnum() or c in "-_") else "_" for c in str(target or "unknown"))
    slug = slug.strip("_") or "unknown"
    return slug[:80]

# PDF generation imports
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.platypus import Image as RLImage
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


def generate_cli_report(all_results: Dict) -> None:
    """
    Generate formatted CLI output report
    
    Args:
        all_results: Dictionary containing all reconnaissance results
    """
    print(f"\n\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{' '*25}RECONNAISSANCE REPORT{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    # Target Information
    print(f"{Fore.YELLOW}TARGET INFORMATION{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Target: {all_results.get('target', 'Unknown')}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Scan Date: {all_results.get('timestamp', 'Unknown')}{Style.RESET_ALL}\n")
    
    # Target Expansion Summary
    if 'expansion' in all_results:
        expansion = all_results['expansion']
        print(f"{Fore.YELLOW}TARGET EXPANSION{Style.RESET_ALL}")
        if expansion.get('ip_addresses'):
            print(f"{Fore.WHITE}  IP Addresses: {', '.join(expansion['ip_addresses'])}{Style.RESET_ALL}")
        if expansion.get('reverse_dns'):
            print(f"{Fore.WHITE}  Reverse DNS: {expansion['reverse_dns']}{Style.RESET_ALL}")
        if (expansion.get('hosting_provider') or {}).get('provider'):
            print(f"{Fore.WHITE}  Hosting Provider: {expansion['hosting_provider']['provider']}{Style.RESET_ALL}")
        print()
    
    # Footprinting Summary
    if 'footprinting' in all_results:
        footprint = all_results['footprinting']
        print(f"{Fore.YELLOW}FOOTPRINTING SUMMARY{Style.RESET_ALL}")
        
        if (footprint.get('whois') or {}).get('registrar'):
            print(f"{Fore.WHITE}  Registrar: {footprint['whois']['registrar']}{Style.RESET_ALL}")
        
        if (footprint.get('ssl_certificate') or {}).get('issuer'):
            issuer = footprint['ssl_certificate']['issuer'].get('organizationName', 'Unknown')
            print(f"{Fore.WHITE}  SSL Issuer: {issuer}{Style.RESET_ALL}")
        
        if (footprint.get('http_headers') or {}).get('server'):
            print(f"{Fore.WHITE}  Web Server: {footprint['http_headers']['server']}{Style.RESET_ALL}")
        
        security_headers = (footprint.get('http_headers') or {}).get('security_headers', {}) or {}
        print(f"{Fore.WHITE}  Security Headers: {len(security_headers)}/5{Style.RESET_ALL}")
        print()
    
    # Subdomain Summary
    if 'subdomains' in all_results:
        subdomains = all_results['subdomains']
        print(f"{Fore.YELLOW}SUBDOMAIN DISCOVERY{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Subdomains Found: {len(subdomains)}{Style.RESET_ALL}")
        if subdomains:
            print(f"{Fore.WHITE}  Sample: {', '.join(subdomains[:5])}{Style.RESET_ALL}")
        print()
    
    # Open Ports Summary
    if 'ports' in all_results:
        ports = all_results['ports']
        print(f"{Fore.YELLOW}OPEN PORTS{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Total Open Ports: {len(ports)}{Style.RESET_ALL}")
        for port_info in ports[:10]:  # Show first 10
            print(f"{Fore.GREEN}  • Port {port_info['port']}: {port_info['service']} "
                  f"({port_info['product']} {port_info['version']}){Style.RESET_ALL}")
        if len(ports) > 10:
            print(f"{Fore.YELLOW}  ... and {len(ports) - 10} more{Style.RESET_ALL}")
        print()
    
    # Technology Stack
    if 'technologies' in all_results:
        tech = all_results['technologies']
        technologies_list = tech.get('technologies', [])
        print(f"{Fore.YELLOW}TECHNOLOGY STACK{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Technologies Identified: {len(technologies_list)}{Style.RESET_ALL}")
        for t in technologies_list[:10]:
            print(f"{Fore.GREEN}  • {t['name']} ({t['category']}){Style.RESET_ALL}")
        print()
    
    # CVE Summary
    if 'cve_report' in all_results:
        cve_report = all_results['cve_report']
        print(f"{Fore.YELLOW}VULNERABILITY SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Total Services Analyzed: {cve_report.get('total_services', 0)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Vulnerable Services: {cve_report.get('vulnerable_services', 0)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  Total CVEs: {cve_report.get('total_cves', 0)}{Style.RESET_ALL}")
        
        severity_counts = cve_report.get('severity_counts', {})
        if severity_counts.get('CRITICAL', 0) > 0:
            print(f"{Fore.RED}  CRITICAL: {severity_counts['CRITICAL']}{Style.RESET_ALL}")
        if severity_counts.get('HIGH', 0) > 0:
            print(f"{Fore.RED}  HIGH: {severity_counts['HIGH']}{Style.RESET_ALL}")
        if severity_counts.get('MEDIUM', 0) > 0:
            print(f"{Fore.YELLOW}  MEDIUM: {severity_counts['MEDIUM']}{Style.RESET_ALL}")
        print()
    
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")


def generate_json_report(all_results: Dict, output_dir: str = "reports") -> str:
    """
    Generate JSON report file
    
    Args:
        all_results: Dictionary containing all reconnaissance results
        output_dir: Directory to save report
        
    Returns:
        Path to generated report file
    """
    # Ensure reports directory exists
    Path(output_dir).mkdir(exist_ok=True)
    
    # Generate filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = _safe_filename(all_results.get('target', 'unknown'))
    filename = f"{output_dir}/mmn_report_{target}_{timestamp}.json"
    
    # Write JSON report
    try:
        with open(filename, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        
        print(f"{Fore.GREEN}[✓] JSON report saved: {filename}{Style.RESET_ALL}")
        return filename
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to save JSON report: {str(e)}{Style.RESET_ALL}")
        return ""


def _stat_cards(all_results: Dict) -> str:
    """Build the summary dashboard cards from whatever data is present."""
    exp = all_results.get('expansion', {}) or {}
    fp = all_results.get('footprinting', {}) or {}
    cve = all_results.get('cve_report', {}) or {}
    js = all_results.get('js_intelligence', {}) or {}

    ip_count = len(exp.get('ip_addresses', []) or [])
    sub_count = len(all_results.get('subdomains', []) or [])
    port_count = len(all_results.get('ports', []) or [])
    tech_count = len((all_results.get('technologies', {}) or {}).get('technologies', []) or [])
    cve_count = cve.get('total_cves', 0)
    sec_headers = len((fp.get('http_headers', {}) or {}).get('security_headers', {}) or {})
    js_findings = len(js.get('endpoints_discovered', []) or []) + len(js.get('hidden_documents_found', []) or [])

    critical = (cve.get('severity_counts', {}) or {}).get('CRITICAL', 0)
    js_risk = (js.get('risk_summary', {}) or {})
    critical += js_risk.get('critical', 0)

    cards = [
        ('IP Addresses', ip_count, '#3282b8'),
        ('Subdomains', sub_count, '#3282b8'),
        ('Open Ports', port_count, '#2ed573'),
        ('Technologies', tech_count, '#3282b8'),
        ('CVEs Found', cve_count, '#ff6348' if cve_count else '#3282b8'),
        ('Security Headers', f"{sec_headers}/5", '#2ed573' if sec_headers >= 4 else '#ffa502'),
        ('JS Findings', js_findings, '#ffa502' if js_findings else '#3282b8'),
        ('Critical Risks', critical, '#ff4757' if critical else '#2ed573'),
    ]
    html = '<div class="cards">'
    for label, value, color in cards:
        html += (f'<div class="card"><div class="card-value" style="color:{color}">{_esc(value)}</div>'
                 f'<div class="card-label">{_esc(label)}</div></div>')
    html += '</div>'
    return html


def generate_html_report(all_results: Dict, output_dir: str = "reports") -> str:
    """
    Generate a comprehensive HTML report covering every module's findings.

    Args:
        all_results: Dictionary containing all reconnaissance results
        output_dir: Directory to save report

    Returns:
        Path to generated report file
    """
    Path(output_dir).mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = _safe_filename(all_results.get('target', 'unknown'))
    filename = f"{output_dir}/mmn_report_{target}_{timestamp}.html"

    parts = []

    # ── Head + styles ───────────────────────────────────────────────
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MMN Reconnaissance Report - {_esc(all_results.get('target', 'Unknown'))}</title>
    <style>
        * {{ box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #1a1a2e; color: #eee; padding: 20px; line-height: 1.6; margin: 0;
        }}
        .container {{
            max-width: 1200px; margin: 0 auto; background-color: #16213e;
            padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }}
        h1 {{ color: #3282b8; text-align: center; border-bottom: 3px solid #3282b8; padding-bottom: 10px; }}
        h2 {{ color: #3282b8; margin-top: 30px; border-left: 4px solid #3282b8; padding-left: 10px; }}
        h3 {{ color: #bbe1fa; margin-top: 20px; }}
        .subtitle {{ text-align:center; color:#aaa; margin-top:-8px; }}
        .section {{ background-color: #0f3460; padding: 20px; margin: 20px 0; border-radius: 5px; }}
        .critical {{ color: #ff4757; font-weight: bold; }}
        .high {{ color: #ff6348; font-weight: bold; }}
        .medium {{ color: #ffa502; }}
        .low {{ color: #1e90ff; }}
        .ok {{ color: #2ed573; font-weight: bold; }}
        .miss {{ color: #ff6348; font-weight: bold; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #26568a; vertical-align: top; }}
        th {{ background-color: #0f4c75; color: white; }}
        tr:hover td {{ background-color: rgba(50,130,184,0.12); }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 15px; margin: 20px 0; }}
        .card {{ background-color: #0f3460; border-radius: 8px; padding: 18px; text-align: center; border: 1px solid #26568a; }}
        .card-value {{ font-size: 2em; font-weight: bold; }}
        .card-label {{ color: #bbe1fa; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }}
        .nav {{ text-align:center; margin: 15px 0; }}
        .nav a {{ color:#bbe1fa; margin:0 8px; text-decoration:none; font-size:0.9em; }}
        .nav a:hover {{ text-decoration:underline; }}
        .badge {{ display:inline-block; padding:2px 8px; border-radius:10px; font-size:0.8em; }}
        code, .mono {{ font-family: 'Courier New', monospace; word-break: break-all; }}
        .empty {{ color:#888; font-style: italic; }}
        .timestamp {{ text-align: center; color: #aaa; margin-top: 30px; border-top:1px solid #26568a; padding-top:15px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>&#128737;&#65039; MMN Reconnaissance Report</h1>
        <p class="subtitle">Target: <strong>{_esc(all_results.get('target', 'Unknown'))}</strong> &middot; {_esc(all_results.get('scan_type', 'Assessment'))}</p>
""")

    # ── Nav ─────────────────────────────────────────────────────────
    nav_items = [('overview', 'Overview')]
    if all_results.get('expansion'): nav_items.append(('expansion', 'Expansion'))
    if all_results.get('footprinting'): nav_items.append(('footprinting', 'Footprinting'))
    if all_results.get('subdomains'): nav_items.append(('subdomains', 'Subdomains'))
    if all_results.get('os_detection'): nav_items.append(('os', 'OS'))
    if all_results.get('ports'): nav_items.append(('ports', 'Ports'))
    if all_results.get('technologies'): nav_items.append(('tech', 'Technologies'))
    if 'cve_report' in all_results: nav_items.append(('cve', 'Vulnerabilities'))
    if all_results.get('js_intelligence'): nav_items.append(('js-intel', 'JS Intel'))
    parts.append('<div class="nav">' + ' | '.join(
        f'<a href="#{i}">{_esc(l)}</a>' for i, l in nav_items) + '</div>')

    # ── Overview ────────────────────────────────────────────────────
    parts.append(f"""
        <div class="section" id="overview">
            <h2>Overview</h2>
            {_stat_cards(all_results)}
            <table>
                <tr><th>Target</th><td>{_esc(all_results.get('target', 'Unknown'))}</td></tr>
                <tr><th>Scan Type</th><td>{_esc(all_results.get('scan_type', 'Unknown'))}</td></tr>
                <tr><th>Scan Date</th><td>{_esc(all_results.get('timestamp', 'Unknown'))}</td></tr>
            </table>
        </div>
""")

    # ── Target Expansion ────────────────────────────────────────────
    if all_results.get('expansion'):
        exp = all_results['expansion']
        parts.append('<div class="section" id="expansion"><h2>Target Expansion</h2><table>')
        parts.append(f"<tr><th>Target Type</th><td>{_esc(exp.get('target_type'))}</td></tr>")
        if exp.get('ip_addresses'):
            parts.append(f"<tr><th>IP Addresses</th><td class='mono'>{_esc(', '.join(exp['ip_addresses']))}</td></tr>")
        parts.append(f"<tr><th>Reverse DNS</th><td class='mono'>{_esc(exp.get('reverse_dns'))}</td></tr>")
        hp = exp.get('hosting_provider', {}) or {}
        if hp:
            parts.append(f"<tr><th>Hosting Provider</th><td>{_esc(hp.get('provider'))} ({_esc(hp.get('type'))})</td></tr>")
        parts.append('</table>')

        dns_records = exp.get('dns_records', {}) or {}
        if any(dns_records.values()):
            parts.append('<h3>DNS Records</h3><table><tr><th>Type</th><th>Records</th></tr>')
            for rtype, recs in dns_records.items():
                if recs:
                    vals = '<br>'.join(_esc(r) for r in recs)
                    parts.append(f"<tr><td><strong>{_esc(rtype)}</strong></td><td class='mono'>{vals}</td></tr>")
            parts.append('</table>')
        parts.append('</div>')

    # ── Footprinting ────────────────────────────────────────────────
    if all_results.get('footprinting'):
        fp = all_results['footprinting']
        parts.append('<div class="section" id="footprinting"><h2>Footprinting</h2>')

        whois = fp.get('whois', {}) or {}
        if any(whois.values()):
            parts.append('<h3>WHOIS</h3><table>')
            for label, key in [('Domain', 'domain_name'), ('Registrar', 'registrar'),
                               ('Created', 'creation_date'), ('Expires', 'expiration_date'),
                               ('Status', 'status'), ('Country', 'country')]:
                parts.append(f"<tr><th>{label}</th><td>{_esc(whois.get(key))}</td></tr>")
            if whois.get('name_servers'):
                ns = '<br>'.join(_esc(n) for n in whois['name_servers'])
                parts.append(f"<tr><th>Name Servers</th><td class='mono'>{ns}</td></tr>")
            if whois.get('emails'):
                em = ', '.join(_esc(e) for e in whois['emails'])
                parts.append(f"<tr><th>Emails</th><td class='mono'>{em}</td></tr>")
            parts.append('</table>')

        ssl = fp.get('ssl_certificate', {}) or {}
        if any(ssl.values()):
            parts.append('<h3>SSL / TLS Certificate</h3><table>')
            issuer = (ssl.get('issuer', {}) or {}).get('organizationName') or (ssl.get('issuer', {}) or {}).get('commonName')
            subject = (ssl.get('subject', {}) or {}).get('commonName')
            parts.append(f"<tr><th>Subject CN</th><td>{_esc(subject)}</td></tr>")
            parts.append(f"<tr><th>Issuer</th><td>{_esc(issuer)}</td></tr>")
            parts.append(f"<tr><th>Valid From</th><td>{_esc(ssl.get('not_before'))}</td></tr>")
            parts.append(f"<tr><th>Valid Until</th><td>{_esc(ssl.get('not_after'))}</td></tr>")
            parts.append(f"<tr><th>Version</th><td>{_esc(ssl.get('version'))}</td></tr>")
            parts.append(f"<tr><th>Signature Algorithm</th><td>{_esc(ssl.get('signature_algorithm'))}</td></tr>")
            parts.append(f"<tr><th>Serial Number</th><td class='mono'>{_esc(ssl.get('serial_number'))}</td></tr>")
            if ssl.get('sans'):
                sans = ', '.join(_esc(s) for s in ssl['sans'])
                parts.append(f"<tr><th>SANs</th><td class='mono'>{sans}</td></tr>")
            parts.append('</table>')

        hh = fp.get('http_headers', {}) or {}
        if hh.get('status_code') is not None:
            parts.append('<h3>HTTP Response</h3><table>')
            parts.append(f"<tr><th>Status Code</th><td>{_esc(hh.get('status_code'))}</td></tr>")
            parts.append(f"<tr><th>Protocol</th><td>{_esc(hh.get('protocol'))}</td></tr>")
            parts.append(f"<tr><th>Server</th><td>{_esc(hh.get('server'))}</td></tr>")
            parts.append(f"<tr><th>X-Powered-By</th><td>{_esc(hh.get('powered_by'))}</td></tr>")
            parts.append(f"<tr><th>Content-Type</th><td>{_esc(hh.get('content_type'))}</td></tr>")
            parts.append('</table>')

            # Security headers: show present AND missing
            present = hh.get('security_headers', {}) or {}
            all_sec = ['Strict-Transport-Security', 'Content-Security-Policy',
                       'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection']
            parts.append('<h3>Security Headers</h3><table><tr><th>Header</th><th>Status</th><th>Value</th></tr>')
            for h in all_sec:
                if h in present:
                    parts.append(f"<tr><td>{_esc(h)}</td><td class='ok'>PRESENT</td><td class='mono'>{_esc(present[h])}</td></tr>")
                else:
                    parts.append(f"<tr><td>{_esc(h)}</td><td class='miss'>MISSING</td><td>&mdash;</td></tr>")
            parts.append('</table>')

            if hh.get('all_headers'):
                parts.append('<h3>All Response Headers</h3><table><tr><th>Header</th><th>Value</th></tr>')
                for k, v in hh['all_headers'].items():
                    parts.append(f"<tr><td>{_esc(k)}</td><td class='mono'>{_esc(v)}</td></tr>")
                parts.append('</table>')
        parts.append('</div>')

    # ── Subdomains ──────────────────────────────────────────────────
    if all_results.get('subdomains'):
        subs = all_results['subdomains']
        parts.append(f'<div class="section" id="subdomains"><h2>Subdomains ({len(subs)})</h2>')
        parts.append('<table><tr><th>#</th><th>Subdomain</th></tr>')
        for i, s in enumerate(subs, 1):
            parts.append(f"<tr><td>{i}</td><td class='mono'>{_esc(s)}</td></tr>")
        parts.append('</table></div>')

    # ── OS Detection ────────────────────────────────────────────────
    if all_results.get('os_detection'):
        os_info = all_results['os_detection']
        parts.append('<div class="section" id="os"><h2>Operating System Detection</h2><table>')
        parts.append(f"<tr><th>OS Guess</th><td>{_esc(os_info.get('os_guess'))}</td></tr>")
        parts.append(f"<tr><th>Confidence</th><td>{_esc(os_info.get('confidence'))}</td></tr>")
        if os_info.get('indicators'):
            ind = '<br>'.join(_esc(i) for i in os_info['indicators'])
            parts.append(f"<tr><th>Indicators</th><td>{ind}</td></tr>")
        parts.append('</table></div>')

    # ── Open Ports ──────────────────────────────────────────────────
    if all_results.get('ports'):
        ports = all_results['ports']
        parts.append(f'<div class="section" id="ports"><h2>Open Ports &amp; Services ({len(ports)})</h2>')
        parts.append('<table><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>Banner</th></tr>')
        for p in ports:
            parts.append(
                f"<tr><td>{_esc(p.get('port'))}</td><td>{_esc(p.get('service'))}</td>"
                f"<td>{_esc(p.get('product'))}</td><td>{_esc(p.get('version'))}</td>"
                f"<td class='mono'>{_esc(p.get('banner'))}</td></tr>")
        parts.append('</table></div>')

    # ── Technologies ────────────────────────────────────────────────
    if all_results.get('technologies'):
        tech = all_results['technologies']
        techs = tech.get('technologies', []) or []
        parts.append(f'<div class="section" id="tech"><h2>Technology Stack ({len(techs)})</h2>')
        if techs:
            parts.append('<table><tr><th>Technology</th><th>Category</th><th>Confidence</th></tr>')
            for t in techs:
                parts.append(
                    f"<tr><td>{_esc(t.get('name'))}</td><td>{_esc(t.get('category'))}</td>"
                    f"<td>{_esc(t.get('confidence'))}</td></tr>")
            parts.append('</table>')
        else:
            parts.append('<p class="empty">No technologies identified.</p>')
        parts.append('</div>')

    # ── Vulnerabilities / CVEs ──────────────────────────────────────
    if 'cve_report' in all_results:
        cve = all_results['cve_report']
        parts.append('<div class="section" id="cve"><h2>Vulnerability Assessment</h2><table>')
        parts.append(f"<tr><th>Services Analyzed</th><td>{_esc(cve.get('total_services', 0))}</td></tr>")
        parts.append(f"<tr><th>Vulnerable Services</th><td>{_esc(cve.get('vulnerable_services', 0))}</td></tr>")
        parts.append(f"<tr><th>Total CVEs</th><td>{_esc(cve.get('total_cves', 0))}</td></tr>")
        parts.append('</table>')

        sev = cve.get('severity_counts', {}) or {}
        if any(sev.values()):
            parts.append('<h3>Severity Distribution</h3><table><tr>')
            for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
                parts.append(f"<th>{s}</th>")
            parts.append('</tr><tr>')
            for s, cls in [('CRITICAL', 'critical'), ('HIGH', 'high'), ('MEDIUM', 'medium'),
                           ('LOW', 'low'), ('INFORMATIONAL', '')]:
                parts.append(f"<td class='{cls}'>{_esc(sev.get(s, 0))}</td>")
            parts.append('</tr></table>')

        for finding in (cve.get('findings', []) or []):
            cves = finding.get('cves', []) or []
            if not cves:
                continue
            parts.append(f"<h3>Port {_esc(finding.get('port'))}: {_esc(finding.get('product'))} {_esc(finding.get('version'))} ({len(cves)} CVEs)</h3>")
            parts.append('<table><tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Summary</th></tr>')
            for c in cves:
                sclass = str(c.get('severity', '')).lower()
                parts.append(
                    f"<tr><td class='mono'>{_esc(c.get('cve_id'))}</td><td>{_esc(c.get('cvss'))}</td>"
                    f"<td class='{sclass}'>{_esc(c.get('severity'))}</td><td>{_esc(c.get('summary'))}</td></tr>")
            parts.append('</table>')
        parts.append('</div>')

    # ── JS Hidden Document Intelligence ─────────────────────────────
    if all_results.get('js_intelligence'):
        js = all_results['js_intelligence']
        if _js_html_section is not None:
            try:
                parts.append(_js_html_section(js))
            except Exception:
                pass
        # PDF metadata (not covered by the JS module's own section)
        pdf_meta = js.get('pdf_metadata_extracted', []) or []
        if pdf_meta:
            parts.append('<div class="section"><h2>PDF Metadata Extracted</h2>'
                         '<table><tr><th>Risk</th><th>URL</th><th>Author</th><th>Producer</th><th>Created</th><th>Pages</th></tr>')
            for m in pdf_meta:
                sclass = str(m.get('risk', '')).lower()
                parts.append(
                    f"<tr><td class='{sclass}'>{_esc(str(m.get('risk','')).upper())}</td>"
                    f"<td class='mono'>{_esc(m.get('url'))}</td><td>{_esc(m.get('author'))}</td>"
                    f"<td>{_esc(m.get('producer'))}</td><td>{_esc(m.get('creation_date'))}</td>"
                    f"<td>{_esc(m.get('pages'))}</td></tr>")
            parts.append('</table></div>')

    # ── Footer ──────────────────────────────────────────────────────
    parts.append(f"""
        <div class="timestamp">
            <p>Generated by MMN Reconnaissance Framework v{all_results.get('framework_version', '2.0.0')}</p>
            <p>Report Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &middot; FOR AUTHORIZED USE ONLY</p>
        </div>
    </div>
</body>
</html>
""")

    html_content = '\n'.join(parts)

    try:
        with open(filename, 'w') as f:
            f.write(html_content)
        print(f"{Fore.GREEN}[✓] HTML report saved: {filename}{Style.RESET_ALL}")
        return filename
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to save HTML report: {str(e)}{Style.RESET_ALL}")
        return ""


def generate_pdf_report(all_results: Dict, filename: str = None) -> str:
    """
    Generate PDF format report with professional styling
    
    Args:
        all_results: Dictionary containing all reconnaissance results
        filename: Optional custom filename
        
    Returns:
        Path to saved PDF file
    """
    if not PDF_AVAILABLE:
        print(f"{Fore.RED}[!] PDF generation requires reportlab library{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Install with: pip install reportlab{Style.RESET_ALL}")
        return ""

    
    # Create reports directory
    Path("reports").mkdir(exist_ok=True)
    
    # Generate filename
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/mmn_report_{timestamp}.pdf"
    
    try:
        # Create PDF document
        doc = SimpleDocTemplate(filename, pagesize=letter,
                              rightMargin=72, leftMargin=72,
                              topMargin=72, bottomMargin=18)
        
        # Container for PDF elements
        elements = []
        
        # Define styles
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#0f4c75'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#1b262c'),
            spaceAfter=12,
            spaceBefore=12,
            fontName='Helvetica-Bold'
        )
        
        # Title
        title = Paragraph("🛡️ MMN Reconnaissance Report", title_style)
        elements.append(title)
        elements.append(Spacer(1, 0.3*inch))
        
        # Target Information
        elements.append(Paragraph("Target Information", heading_style))
        target_data = [
            ['Target:', all_results.get('target', 'Unknown')],
            ['Scan Date:', all_results.get('timestamp', 'Unknown')],
            ['Framework:', 'MMN v1.0.0']
        ]
        target_table = Table(target_data, colWidths=[2*inch, 4*inch])
        target_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f4f8')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        elements.append(target_table)
        elements.append(Spacer(1, 0.3*inch))
        
        # Target Expansion
        if 'expansion' in all_results:
            expansion = all_results['expansion']
            elements.append(Paragraph("Target Expansion", heading_style))
            exp_data = []
            if expansion.get('ip_addresses'):
                exp_data.append(['IP Addresses:', ', '.join(expansion['ip_addresses'])])
            if expansion.get('reverse_dns'):
                exp_data.append(['Reverse DNS:', expansion['reverse_dns']])
            if (expansion.get('hosting_provider') or {}).get('provider'):
                exp_data.append(['Hosting Provider:', expansion['hosting_provider']['provider']])
            
            if exp_data:
                exp_table = Table(exp_data, colWidths=[2*inch, 4*inch])
                exp_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f4f8')),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey)
                ]))
                elements.append(exp_table)
                elements.append(Spacer(1, 0.2*inch))
        
        # OS Detection
        if 'os_detection' in all_results and all_results['os_detection']:
            os_info = all_results['os_detection']
            elements.append(Paragraph("Operating System Detection", heading_style))
            os_data = [
                ['OS Guess:', os_info.get('os_guess', 'Unknown')],
                ['Confidence:', os_info.get('confidence', 'Low')]
            ]
            os_table = Table(os_data, colWidths=[2*inch, 4*inch])
            os_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f4f8')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(os_table)
            elements.append(Spacer(1, 0.2*inch))
        
        # Open Ports
        if 'ports' in all_results and all_results['ports']:
            elements.append(Paragraph("Open Ports & Services", heading_style))
            port_data = [['Port', 'Service', 'Product', 'Version']]
            for port in all_results['ports'][:20]:  # Limit to first 20
                port_data.append([
                    str(port.get('port', 'N/A')),
                    port.get('service', 'N/A')[:15],
                    port.get('product', 'N/A')[:15],
                    port.get('version', 'N/A')[:15]
                ])
            
            port_table = Table(port_data, colWidths=[1*inch, 1.5*inch, 1.75*inch, 1.75*inch])
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f4c75')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('FONTSIZE', (0, 1), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f8f9fa')])
            ]))
            elements.append(port_table)
            
            if len(all_results['ports']) > 20:
                elements.append(Paragraph(f"<i>... and {len(all_results['ports']) - 20} more ports</i>", 
                                        styles['Normal']))
            elements.append(Spacer(1, 0.3*inch))
        
        # CVE Summary
        if 'cve_report' in all_results:
            cve_report = all_results['cve_report']
            elements.append(Paragraph("Vulnerability Assessment Summary", heading_style))
            
            vuln_summary_data = [
                ['Total Services Analyzed:', str(cve_report.get('total_services', 0))],
                ['Vulnerable Services:', str(cve_report.get('vulnerable_services', 0))],
                ['Total CVEs Found:', str(cve_report.get('total_cves', 0))]
            ]
            
            vuln_table = Table(vuln_summary_data, colWidths=[2.5*inch, 3.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8f4f8')),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
            ]))
            elements.append(vuln_table)
            elements.append(Spacer(1, 0.2*inch))
            
            # Severity breakdown
            severity_counts = cve_report.get('severity_counts', {})
            if any(severity_counts.values()):
                severity_data = [['Severity', 'Count']]
                severity_colors_map = {
                    'CRITICAL': colors.HexColor('#ff4757'),
                    'HIGH': colors.HexColor('#ff6348'),
                    'MEDIUM': colors.HexColor('#ffa502'),
                    'LOW': colors.HexColor('#1e90ff'),
                    'INFORMATIONAL': colors.grey
                }
                
                for severity, count in severity_counts.items():
                    if count > 0:
                        severity_data.append([severity, str(count)])
                
                severity_table = Table(severity_data, colWidths=[2*inch, 2*inch])
                severity_table_style = [
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f4c75')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                ]
                
                severity_table.setStyle(TableStyle(severity_table_style))
                elements.append(severity_table)
                elements.append(Spacer(1, 0.3*inch))
            
            # Detailed CVE findings
            if cve_report.get('findings'):
                elements.append(PageBreak())
                elements.append(Paragraph("Detailed CVE Findings", heading_style))
                
                for finding in cve_report['findings'][:10]:  # Limit to first 10 services
                    service_text = f"<b>Port {finding['port']}: {finding['product']} {finding['version']}</b>"
                    elements.append(Paragraph(service_text, styles['Normal']))
                    elements.append(Spacer(1, 0.1*inch))
                    
                    if finding.get('cves'):
                        cve_data = [['CVE ID', 'CVSS', 'Severity']]
                        for cve in finding['cves'][:5]:  # Top 5 CVEs per service
                            cve_data.append([
                                cve.get('cve_id', 'N/A'),
                                str(cve.get('cvss', 'N/A')),
                                cve.get('severity', 'N/A')
                            ])
                        
                        cve_table = Table(cve_data, colWidths=[2.5*inch, 1*inch, 1.5*inch])
                        cve_table.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#3282b8')),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                            ('TOPPADDING', (0, 0), (-1, -1), 6),
                        ]))
                        elements.append(cve_table)
                    
                    elements.append(Spacer(1, 0.2*inch))
        
        # Footer
        elements.append(Spacer(1, 0.5*inch))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        footer_text = f"Generated by MMN Reconnaissance Framework | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | FOR AUTHORIZED USE ONLY"
        elements.append(Paragraph(footer_text, footer_style))
        
        # Build PDF
        doc.build(elements)
        
        print(f"{Fore.GREEN}[✓] PDF report saved: {filename}{Style.RESET_ALL}")
        return filename
        
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to generate PDF report: {str(e)}{Style.RESET_ALL}")
        return ""


def generate_reports(all_results: Dict, formats: list = None) -> Dict[str, str]:
    """
    Generate reports in specified formats
    
    Args:
        all_results: Dictionary containing all reconnaissance results
        formats: List of format strings ('cli', 'json', 'html', 'pdf')
        
    Returns:
        Dictionary with format -> filename mappings
    """
    if formats is None:
        formats = ['cli', 'json', 'html', 'pdf']
    
    report_files = {}
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}GENERATING REPORTS{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    if 'cli' in formats:
        generate_cli_report(all_results)
        report_files['cli'] = 'console'
    
    if 'json' in formats:
        json_file = generate_json_report(all_results)
        report_files['json'] = json_file
    
    if 'html' in formats:
        html_file = generate_html_report(all_results)
        report_files['html'] = html_file
    
    if 'pdf' in formats:
        pdf_file = generate_pdf_report(all_results)
        if pdf_file:
            report_files['pdf'] = pdf_file
    
    return report_files


if __name__ == "__main__":
    # Test module
    test_results = {
        'target': 'example.com',
        'timestamp': datetime.now().isoformat(),
        'expansion': {'ip_addresses': ['93.184.216.34']},
        'ports': [
            {'port': 80, 'service': 'HTTP', 'product': 'Apache', 'version': '2.4.41'},
            {'port': 443, 'service': 'HTTPS', 'product': 'Apache', 'version': '2.4.41'}
        ]
    }
    
    generate_reports(test_results)
