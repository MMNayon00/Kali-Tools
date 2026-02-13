"""
CVE Mapper Module
Map detected services to CVE databases and display vulnerabilities
NO EXPLOIT CODE - IDENTIFICATION ONLY
"""

import requests
from typing import Dict, List
from colorama import Fore, Style
import re


def search_cve_circl(product: str, version: str = None) -> List[Dict]:
    """
    Search CVE database using CIRCL CVE Search API
    
    Args:
        product: Software product name
        version: Optional version string
        
    Returns:
        List of CVE entries
    """
    cves = []
    
    try:
        # Clean product name
        product_clean = product.lower().replace(' ', '_')
        
        # Build search URL
        if version:
            search_term = f"{product_clean} {version}"
        else:
            search_term = product_clean
        
        url = f"https://cve.circl.lu/api/search/{search_term}"
        
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            
            # Limit to top 5 most relevant CVEs
            for cve_entry in data[:5]:
                cve_info = {
                    'cve_id': cve_entry.get('id', 'N/A'),
                    'summary': cve_entry.get('summary', 'No description available'),
                    'cvss': cve_entry.get('cvss', 0.0),
                    'published': cve_entry.get('Published', 'Unknown'),
                    'modified': cve_entry.get('Modified', 'Unknown'),
                    'severity': get_severity_from_cvss(cve_entry.get('cvss', 0.0))
                }
                cves.append(cve_info)
        
    except Exception as e:
        print(f"{Fore.RED}  [!] CVE search failed for {product}: {str(e)}{Style.RESET_ALL}")
    
    return cves


def get_severity_from_cvss(cvss_score: float) -> str:
    """
    Convert CVSS score to severity rating
    
    Args:
        cvss_score: CVSS score (0-10)
        
    Returns:
        Severity rating string
    """
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    else:
        return "INFORMATIONAL"


def get_severity_color(severity: str) -> str:
    """
    Get color code for severity level
    
    Args:
        severity: Severity rating
        
    Returns:
        Colorama color code
    """
    colors = {
        'CRITICAL': Fore.RED,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.CYAN,
        'INFORMATIONAL': Fore.WHITE
    }
    return colors.get(severity, Fore.WHITE)


def map_service_to_cve(service_info: Dict) -> List[Dict]:
    """
    Map a service to known CVEs
    
    Args:
        service_info: Dictionary with service details (product, version, etc.)
        
    Returns:
        List of related CVEs
    """
    product = service_info.get('product', 'Unknown')
    version = service_info.get('version', 'Unknown')
    
    # Skip if product or version is unknown
    if product == 'Unknown' or product == 'Generic Service':
        return []
    
    print(f"\n{Fore.YELLOW}[*] Searching CVEs for {product} {version}...{Style.RESET_ALL}")
    
    cves = search_cve_circl(product, version)
    
    if cves:
        print(f"{Fore.GREEN}[✓] Found {len(cves)} CVEs for {product}{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}[i] No CVEs found for {product}{Style.RESET_ALL}")
    
    return cves


def generate_cve_report(services: List[Dict]) -> Dict:
    """
    Generate comprehensive CVE report for all services
    
    Args:
        services: List of discovered services
        
    Returns:
        Dictionary with CVE mapping results
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}CVE VULNERABILITY MAPPING{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    cve_report = {
        'total_services': len(services),
        'vulnerable_services': 0,
        'total_cves': 0,
        'severity_counts': {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFORMATIONAL': 0
        },
        'findings': []
    }
    
    print(f"\n{Fore.YELLOW}[*] Analyzing {len(services)} services for known vulnerabilities...{Style.RESET_ALL}")
    
    for service in services:
        port = service.get('port')
        product = service.get('product', 'Unknown')
        version = service.get('version', 'Unknown')
        
        cves = map_service_to_cve(service)
        
        if cves:
            cve_report['vulnerable_services'] += 1
            cve_report['total_cves'] += len(cves)
            
            finding = {
                'port': port,
                'service': service.get('service'),
                'product': product,
                'version': version,
                'cves': cves
            }
            
            cve_report['findings'].append(finding)
            
            # Count severities
            for cve in cves:
                severity = cve['severity']
                cve_report['severity_counts'][severity] += 1
                
                # Display each CVE
                color = get_severity_color(severity)
                print(f"\n  {color}[{severity}] {cve['cve_id']}{Style.RESET_ALL}")
                print(f"  {color}CVSS Score: {cve['cvss']}{Style.RESET_ALL}")
                print(f"  {Fore.WHITE}Summary: {cve['summary'][:150]}...{Style.RESET_ALL}")
    
    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}CVE SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}Total Services Scanned: {cve_report['total_services']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Vulnerable Services: {cve_report['vulnerable_services']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Total CVEs Found: {cve_report['total_cves']}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}Severity Breakdown:{Style.RESET_ALL}")
    for severity, count in cve_report['severity_counts'].items():
        if count > 0:
            color = get_severity_color(severity)
            print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
    
    # Recommendations
    print(f"\n{Fore.CYAN}RECOMMENDATIONS:{Style.RESET_ALL}")
    
    if cve_report['severity_counts']['CRITICAL'] > 0:
        print(f"{Fore.RED}  [!] CRITICAL vulnerabilities detected - Immediate patching required{Style.RESET_ALL}")
    
    if cve_report['severity_counts']['HIGH'] > 0:
        print(f"{Fore.RED}  [!] HIGH severity vulnerabilities detected - Prioritize patching{Style.RESET_ALL}")
    
    if cve_report['severity_counts']['MEDIUM'] > 0:
        print(f"{Fore.YELLOW}  [!] MEDIUM severity vulnerabilities detected - Schedule patching{Style.RESET_ALL}")
    
    if cve_report['total_cves'] == 0:
        print(f"{Fore.GREEN}  [✓] No known CVEs found for detected services{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}  [i] Review CVE details and apply vendor patches{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  [i] Verify versions against your actual deployment{Style.RESET_ALL}")
    
    return cve_report


if __name__ == "__main__":
    # Test module
    test_services = [
        {'port': 22, 'service': 'SSH', 'product': 'OpenSSH', 'version': '7.4'},
        {'port': 80, 'service': 'HTTP', 'product': 'Apache', 'version': '2.4.6'}
    ]
    
    result = generate_cve_report(test_services)
    print(f"\n{Fore.CYAN}CVE Mapping Complete{Style.RESET_ALL}")
