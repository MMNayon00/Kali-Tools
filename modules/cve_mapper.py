"""
CVE Mapper Module
Map detected services to CVE databases and display vulnerabilities
Uses multiple CVE sources for comprehensive results
NO EXPLOIT CODE - IDENTIFICATION ONLY
"""

import requests
import json
import time
from typing import Dict, List
from colorama import Fore, Style
import re


def _cve_get(url: str, params: dict = None, headers: dict = None,
             timeout: int = 20, retries: int = 3) -> requests.Response | None:
    """GET with retry + exponential back-off for CVE API calls."""
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                return resp
            if resp.status_code == 429:          # rate-limited
                wait = 10 * attempt
                time.sleep(wait)
                continue
            if resp.status_code in (500, 502, 503, 504):
                time.sleep(3 * attempt)
                continue
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            pass
        except Exception:
            pass
        if attempt < retries:
            time.sleep(3 * attempt)
    return None


def search_cve_nvd(product: str, version: str = None) -> List[Dict]:
    """
    Search CVE database using NVD (National Vulnerability Database) API 2.0
    
    Args:
        product: Software product name
        version: Optional version string
        
    Returns:
        List of CVE entries
    """
    cves = []
    
    try:
        # Clean product name
        product_clean = product.lower().strip()
        
        # Build search URL for NVD API 2.0new API)
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Build keyword query
        if version and version != 'Unknown':
            keywords = f"{product_clean} {version}"
        else:
            keywords = product_clean
        
        params = {
            'keywordSearch': keywords,
            'resultsPerPage': 10
        }
        
        headers = {
            'User-Agent': 'MMN-Framework/1.0'
        }

        response = _cve_get(base_url, params=params, headers=headers, timeout=20)

        if response is not None:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                cve_item = vuln.get('cve', {})
                cve_id = cve_item.get('id', 'N/A')
                
                # Get description
                descriptions = cve_item.get('descriptions', [])
                description = descriptions[0].get('value', 'No description') if descriptions else 'No description'
                
                # Get CVSS scores
                metrics = cve_item.get('metrics', {})
                cvss_score = 0.0
                severity = 'UNKNOWN'
                
                # Try CVSS v3.1 first, then v3.0, then v2.0
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
                    cvss_data = metrics['cvssMetricV30'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    cvss_data = metrics['cvssMetricV2'][0]['cvssData']
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    severity = get_severity_from_cvss(cvss_score)
                
                # Get published date
                published = cve_item.get('published', 'Unknown')
                
                cve_info = {
                    'cve_id': cve_id,
                    'summary': description[:300],  # Limit description length
                    'cvss': cvss_score,
                    'published': published,
                    'modified': cve_item.get('lastModified', 'Unknown'),
                    'severity': severity if severity != 'UNKNOWN' else get_severity_from_cvss(cvss_score)
                }
                cves.append(cve_info)
        
        # NVD enforces 5 requests per 30 seconds without an API key (= 6 s/request)
        time.sleep(6)

    except Exception as e:
        print(f"{Fore.YELLOW}  [!] NVD search failed: {str(e)}{Style.RESET_ALL}")
    
    return cves


def search_cve_circl(product: str, version: str = None) -> List[Dict]:
    """
    Search CVE database using CIRCL CVE Search API (backup source)
    
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
        if version and version != 'Unknown':
            search_term = f"{product_clean} {version}"
        else:
            search_term = product_clean
        
        url = f"https://cve.circl.lu/api/search/{search_term}"

        response = _cve_get(url, timeout=15)

        if response is not None:
            try:
                data = response.json()
            except ValueError:
                data = []
            if not isinstance(data, list):
                data = []
            
            for cve_entry in data[:10]:
                cve_info = {
                    'cve_id': cve_entry.get('id', 'N/A'),
                    'summary': cve_entry.get('summary', 'No description available'),
                    'cvss': float(cve_entry.get('cvss', 0.0)) if cve_entry.get('cvss') else 0.0,
                    'published': cve_entry.get('Published', 'Unknown'),
                    'modified': cve_entry.get('Modified', 'Unknown'),
                    'severity': get_severity_from_cvss(float(cve_entry.get('cvss', 0.0)) if cve_entry.get('cvss') else 0.0)
                }
                cves.append(cve_info)
        
    except Exception as e:
        print(f"{Fore.YELLOW}  [!] CIRCL search failed: {str(e)}{Style.RESET_ALL}")
    
    return cves


def get_severity_from_cvss(cvss_score: float) -> str:
    """
    Convert CVSS score to severity rating (CVSS v3.x standard)
    
    Args:
        cvss_score: CVSS score (0-10)
        
    Returns:
        Severity rating string
    """
    try:
        score = float(cvss_score)
    except:
        score = 0.0
        
    if score == 0:
        return "NONE"
    elif score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
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
    Map a service to known CVEs using multiple sources
    
    Args:
        service_info: Dictionary with service details (product, version, etc.)
        
    Returns:
        List of related CVEs (deduplicated)
    """
    product = service_info.get('product', 'Unknown')
    version = service_info.get('version', 'Unknown')
    
    # Skip if product is unknown or generic
    if product == 'Unknown' or product == 'Generic Service':
        return []
    
    print(f"\n{Fore.YELLOW}[*] Searching CVEs for {product} {version}...{Style.RESET_ALL}")
    
    all_cves = []
    cve_ids_seen = set()
    
    # Try NVD first (primary source)
    print(f"{Fore.CYAN}  [*] Querying NVD database...{Style.RESET_ALL}")
    nvd_cves = search_cve_nvd(product, version)
    for cve in nvd_cves:
        if cve['cve_id'] not in cve_ids_seen:
            all_cves.append(cve)
            cve_ids_seen.add(cve['cve_id'])
    
    # Fallback to CIRCL if NVD returns few results
    if len(all_cves) < 3:
        print(f"{Fore.CYAN}  [*] Querying CIRCL database...{Style.RESET_ALL}")
        circl_cves = search_cve_circl(product, version)
        for cve in circl_cves:
            if cve['cve_id'] not in cve_ids_seen:
                all_cves.append(cve)
                cve_ids_seen.add(cve['cve_id'])
    
    if all_cves:
        print(f"{Fore.GREEN}[✓] Found {len(all_cves)} CVEs for {product}{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}[i] No CVEs found for {product} {version}{Style.RESET_ALL}")
    
    # Sort by CVSS score (highest first)
    all_cves.sort(key=lambda x: x.get('cvss', 0), reverse=True)
    
    return all_cves


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
