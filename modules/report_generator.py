"""
Report Generator Module
Aggregate results and generate structured reports
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict
from colorama import Fore, Style


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
        if expansion.get('hosting_provider', {}).get('provider'):
            print(f"{Fore.WHITE}  Hosting Provider: {expansion['hosting_provider']['provider']}{Style.RESET_ALL}")
        print()
    
    # Footprinting Summary
    if 'footprinting' in all_results:
        footprint = all_results['footprinting']
        print(f"{Fore.YELLOW}FOOTPRINTING SUMMARY{Style.RESET_ALL}")
        
        if footprint.get('whois', {}).get('registrar'):
            print(f"{Fore.WHITE}  Registrar: {footprint['whois']['registrar']}{Style.RESET_ALL}")
        
        if footprint.get('ssl_certificate', {}).get('issuer'):
            issuer = footprint['ssl_certificate']['issuer'].get('organizationName', 'Unknown')
            print(f"{Fore.WHITE}  SSL Issuer: {issuer}{Style.RESET_ALL}")
        
        if footprint.get('http_headers', {}).get('server'):
            print(f"{Fore.WHITE}  Web Server: {footprint['http_headers']['server']}{Style.RESET_ALL}")
        
        security_headers = footprint.get('http_headers', {}).get('security_headers', {})
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
    target = all_results.get('target', 'unknown').replace('.', '_')
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


def generate_html_report(all_results: Dict, output_dir: str = "reports") -> str:
    """
    Generate HTML report file
    
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
    target = all_results.get('target', 'unknown').replace('.', '_')
    filename = f"{output_dir}/mmn_report_{target}_{timestamp}.html"
    
    # Build HTML content
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MMN Reconnaissance Report - {all_results.get('target', 'Unknown')}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #1a1a2e;
            color: #eee;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #16213e;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }}
        h1 {{
            color: #0f4c75;
            text-align: center;
            border-bottom: 3px solid #3282b8;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #3282b8;
            margin-top: 30px;
            border-left: 4px solid #3282b8;
            padding-left: 10px;
        }}
        .section {{
            background-color: #0f3460;
            padding: 20px;
            margin: 20px 0;
            border-radius: 5px;
        }}
        .critical {{ color: #ff4757; font-weight: bold; }}
        .high {{ color: #ff6348; font-weight: bold; }}
        .medium {{ color: #ffa502; }}
        .low {{ color: #1e90ff; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #3282b8;
        }}
        th {{
            background-color: #0f4c75;
            color: white;
        }}
        .timestamp {{
            text-align: center;
            color: #aaa;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ MMN Reconnaissance Report</h1>
        <div class="section">
            <h2>Target Information</h2>
            <p><strong>Target:</strong> {all_results.get('target', 'Unknown')}</p>
            <p><strong>Scan Date:</strong> {all_results.get('timestamp', 'Unknown')}</p>
        </div>
"""
    
    # Add expansion data
    if 'expansion' in all_results:
        expansion = all_results['expansion']
        html_content += """
        <div class="section">
            <h2>Target Expansion</h2>
"""
        if expansion.get('ip_addresses'):
            html_content += f"<p><strong>IP Addresses:</strong> {', '.join(expansion['ip_addresses'])}</p>"
        if expansion.get('reverse_dns'):
            html_content += f"<p><strong>Reverse DNS:</strong> {expansion['reverse_dns']}</p>"
        html_content += "</div>"
    
    # Add open ports
    if 'ports' in all_results and all_results['ports']:
        html_content += """
        <div class="section">
            <h2>Open Ports & Services</h2>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Product</th>
                    <th>Version</th>
                </tr>
"""
        for port in all_results['ports']:
            html_content += f"""
                <tr>
                    <td>{port.get('port', 'N/A')}</td>
                    <td>{port.get('service', 'N/A')}</td>
                    <td>{port.get('product', 'N/A')}</td>
                    <td>{port.get('version', 'N/A')}</td>
                </tr>
"""
        html_content += "</table></div>"
    
    # Add CVE information
    if 'cve_report' in all_results:
        cve_report = all_results['cve_report']
        html_content += f"""
        <div class="section">
            <h2>Vulnerability Assessment</h2>
            <p><strong>Total Services Analyzed:</strong> {cve_report.get('total_services', 0)}</p>
            <p><strong>Vulnerable Services:</strong> {cve_report.get('vulnerable_services', 0)}</p>
            <p><strong>Total CVEs Found:</strong> {cve_report.get('total_cves', 0)}</p>
            
            <h3>Severity Distribution</h3>
            <ul>
"""
        severity_counts = cve_report.get('severity_counts', {})
        for severity, count in severity_counts.items():
            if count > 0:
                severity_class = severity.lower()
                html_content += f'<li class="{severity_class}">{severity}: {count}</li>'
        
        html_content += "</ul></div>"
    
    # Close HTML
    html_content += f"""
        <div class="timestamp">
            <p>Generated by MMN Reconnaissance Framework</p>
            <p>Report Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write HTML report
    try:
        with open(filename, 'w') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[✓] HTML report saved: {filename}{Style.RESET_ALL}")
        return filename
    except Exception as e:
        print(f"{Fore.RED}[!] Failed to save HTML report: {str(e)}{Style.RESET_ALL}")
        return ""


def generate_reports(all_results: Dict, formats: list = None) -> Dict[str, str]:
    """
    Generate reports in specified formats
    
    Args:
        all_results: Dictionary containing all reconnaissance results
        formats: List of format strings ('cli', 'json', 'html')
        
    Returns:
        Dictionary with format -> filename mappings
    """
    if formats is None:
        formats = ['cli', 'json', 'html']
    
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
