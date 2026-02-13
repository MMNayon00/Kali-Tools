"""
Footprinting Module
WHOIS lookup, DNS enumeration, SSL/TLS inspection, HTTP header analysis
"""

import whois
import ssl
import socket
import requests
from datetime import datetime
from typing import Dict, Optional
from colorama import Fore, Style


def whois_lookup(target: str) -> Dict:
    """
    Perform WHOIS lookup on target
    
    Args:
        target: Domain name
        
    Returns:
        Dictionary with WHOIS data
    """
    print(f"\n{Fore.YELLOW}[*] Performing WHOIS lookup...{Style.RESET_ALL}")
    
    whois_data = {
        'domain_name': None,
        'registrar': None,
        'creation_date': None,
        'expiration_date': None,
        'name_servers': [],
        'status': None,
        'emails': []
    }
    
    try:
        w = whois.whois(target)
        
        whois_data['domain_name'] = w.domain_name if isinstance(w.domain_name, str) else w.domain_name[0] if w.domain_name else None
        whois_data['registrar'] = w.registrar
        whois_data['creation_date'] = str(w.creation_date) if w.creation_date else None
        whois_data['expiration_date'] = str(w.expiration_date) if w.expiration_date else None
        whois_data['name_servers'] = w.name_servers if w.name_servers else []
        whois_data['status'] = w.status if isinstance(w.status, str) else w.status[0] if w.status else None
        whois_data['emails'] = w.emails if w.emails else []
        
        print(f"{Fore.GREEN}  [✓] WHOIS data retrieved{Style.RESET_ALL}")
        if whois_data['registrar']:
            print(f"{Fore.GREEN}  [✓] Registrar: {whois_data['registrar']}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}  [!] WHOIS lookup failed: {str(e)}{Style.RESET_ALL}")
    
    return whois_data


def ssl_certificate_check(target: str, port: int = 443) -> Dict:
    """
    Inspect SSL/TLS certificate
    
    Args:
        target: Domain or IP
        port: SSL port (default 443)
        
    Returns:
        Dictionary with certificate data
    """
    print(f"\n{Fore.YELLOW}[*] Inspecting SSL/TLS certificate...{Style.RESET_ALL}")
    
    cert_data = {
        'subject': {},
        'issuer': {},
        'version': None,
        'serial_number': None,
        'not_before': None,
        'not_after': None,
        'sans': []
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                
                # Parse certificate data
                cert_data['subject'] = dict(x[0] for x in cert.get('subject', ()))
                cert_data['issuer'] = dict(x[0] for x in cert.get('issuer', ()))
                cert_data['version'] = cert.get('version')
                cert_data['serial_number'] = cert.get('serialNumber')
                cert_data['not_before'] = cert.get('notBefore')
                cert_data['not_after'] = cert.get('notAfter')
                
                # Subject Alternative Names
                if 'subjectAltName' in cert:
                    cert_data['sans'] = [x[1] for x in cert['subjectAltName']]
                
                print(f"{Fore.GREEN}  [✓] Certificate retrieved{Style.RESET_ALL}")
                print(f"{Fore.GREEN}  [✓] Issuer: {cert_data['issuer'].get('organizationName', 'Unknown')}{Style.RESET_ALL}")
                print(f"{Fore.GREEN}  [✓] Valid until: {cert_data['not_after']}{Style.RESET_ALL}")
                
    except Exception as e:
        print(f"{Fore.RED}  [!] SSL inspection failed: {str(e)}{Style.RESET_ALL}")
    
    return cert_data


def http_header_analysis(target: str) -> Dict:
    """
    Analyze HTTP headers
    
    Args:
        target: Domain or IP
        
    Returns:
        Dictionary with HTTP header data
    """
    print(f"\n{Fore.YELLOW}[*] Analyzing HTTP headers...{Style.RESET_ALL}")
    
    header_data = {
        'status_code': None,
        'server': None,
        'powered_by': None,
        'content_type': None,
        'security_headers': {},
        'all_headers': {}
    }
    
    protocols = ['https://', 'http://']
    
    for protocol in protocols:
        url = f"{protocol}{target}"
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            header_data['status_code'] = response.status_code
            header_data['server'] = response.headers.get('Server')
            header_data['powered_by'] = response.headers.get('X-Powered-By')
            header_data['content_type'] = response.headers.get('Content-Type')
            header_data['all_headers'] = dict(response.headers)
            
            # Security headers
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection')
            }
            header_data['security_headers'] = {k: v for k, v in security_headers.items() if v}
            
            print(f"{Fore.GREEN}  [✓] HTTP headers retrieved ({protocol}){Style.RESET_ALL}")
            if header_data['server']:
                print(f"{Fore.GREEN}  [✓] Server: {header_data['server']}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}  [✓] Security headers: {len(header_data['security_headers'])}/5{Style.RESET_ALL}")
            
            break  # Success, no need to try other protocol
            
        except Exception as e:
            if protocol == protocols[-1]:  # Last attempt
                print(f"{Fore.RED}  [!] HTTP analysis failed: {str(e)}{Style.RESET_ALL}")
    
    return header_data


def perform_footprinting(target: str) -> Dict:
    """
    Comprehensive footprinting of target
    
    Args:
        target: Domain or IP address
        
    Returns:
        Dictionary with all footprinting data
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}FOOTPRINTING{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    footprint_data = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'whois': {},
        'ssl_certificate': {},
        'http_headers': {}
    }
    
    # Perform WHOIS lookup
    footprint_data['whois'] = whois_lookup(target)
    
    # SSL certificate inspection
    footprint_data['ssl_certificate'] = ssl_certificate_check(target)
    
    # HTTP header analysis
    footprint_data['http_headers'] = http_header_analysis(target)
    
    return footprint_data


if __name__ == "__main__":
    # Test module
    test_target = "example.com"
    result = perform_footprinting(test_target)
    print(f"\n{Fore.CYAN}Results:{Style.RESET_ALL}")
    print(result)
