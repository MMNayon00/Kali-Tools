"""
Footprinting Module
WHOIS lookup, DNS enumeration, SSL/TLS inspection, HTTP header analysis
"""

import whois
import ssl
import socket
import requests
import re
from datetime import datetime
from typing import Dict, Optional
from colorama import Fore, Style
import urllib3

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def extract_domain_from_target(target: str) -> Optional[str]:
    """
    Extract domain name from target (handles IPs and domains)
    
    Args:
        target: IP or domain
        
    Returns:
        Domain name or None if target is IP
    """
    # Check if it's an IP address
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, target):
        # Try reverse DNS to get domain
        try:
            hostname = socket.gethostbyaddr(target)
            return hostname[0] if hostname else None
        except:
            return None
    return target


def whois_lookup(target: str) -> Dict:
    """
    Perform WHOIS lookup on target
    
    Args:
        target: Domain name or IP
        
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
        'emails': [],
        'country': None
    }
    
    # Extract domain from target
    domain = extract_domain_from_target(target)
    if not domain:
        print(f"{Fore.CYAN}  [i] Target is an IP address with no reverse DNS - WHOIS lookup skipped{Style.RESET_ALL}")
        return whois_data
    
    try:
        w = whois.whois(domain)
        
        # Handle domain name (can be string or list)
        if hasattr(w, 'domain_name'):
            if isinstance(w.domain_name, list):
                whois_data['domain_name'] = w.domain_name[0] if w.domain_name else None
            else:
                whois_data['domain_name'] = w.domain_name
        
        # Handle other fields
        whois_data['registrar'] = w.registrar if hasattr(w, 'registrar') else None
        
        # Handle dates (can be string, datetime, or list)
        if hasattr(w, 'creation_date'):
            if isinstance(w.creation_date, list):
                whois_data['creation_date'] = str(w.creation_date[0]) if w.creation_date else None
            elif w.creation_date:
                whois_data['creation_date'] = str(w.creation_date)
        
        if hasattr(w, 'expiration_date'):
            if isinstance(w.expiration_date, list):
                whois_data['expiration_date'] = str(w.expiration_date[0]) if w.expiration_date else None
            elif w.expiration_date:
                whois_data['expiration_date'] = str(w.expiration_date)
        
        # Name servers
        if hasattr(w, 'name_servers') and w.name_servers:
            whois_data['name_servers'] = w.name_servers if isinstance(w.name_servers, list) else [w.name_servers]
        
        # Status
        if hasattr(w, 'status'):
            if isinstance(w.status, list):
                whois_data['status'] = w.status[0] if w.status else None
            else:
                whois_data['status'] = w.status
        
        # Emails
        if hasattr(w, 'emails') and w.emails:
            whois_data['emails'] = w.emails if isinstance(w.emails, list) else [w.emails]
        
        # Country
        if hasattr(w, 'country'):
            whois_data['country'] = w.country
        
        print(f"{Fore.GREEN}  [✓] WHOIS data retrieved{Style.RESET_ALL}")
        if whois_data['registrar']:
            print(f"{Fore.GREEN}  [✓] Registrar: {whois_data['registrar']}{Style.RESET_ALL}")
        if whois_data['country']:
            print(f"{Fore.GREEN}  [✓] Country: {whois_data['country']}{Style.RESET_ALL}")
        
    except Exception as e:
        error_msg = str(e).lower()
        if 'no match' in error_msg or 'not found' in error_msg:
            print(f"{Fore.CYAN}  [i] Domain not found in WHOIS database{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}  [!] WHOIS lookup failed: {str(e)[:100]}{Style.RESET_ALL}")
    
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
        'sans': [],
        'signature_algorithm': None
    }
    
    # First check if port is open
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target, port))
        sock.close()
        
        if result != 0:
            print(f"{Fore.CYAN}  [i] Port {port} is not open, SSL inspection skipped{Style.RESET_ALL}")
            return cert_data
    except Exception as e:
        print(f"{Fore.CYAN}  [i] Cannot connect to port {port}, SSL inspection skipped{Style.RESET_ALL}")
        return cert_data
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                
                # Parse certificate data
                cert_data['subject'] = dict(x[0] for x in cert.get('subject', ())) if cert.get('subject') else {}
                cert_data['issuer'] = dict(x[0] for x in cert.get('issuer', ())) if cert.get('issuer') else {}
                cert_data['version'] = cert.get('version')
                cert_data['serial_number'] = cert.get('serialNumber')
                cert_data['not_before'] = cert.get('notBefore')
                cert_data['not_after'] = cert.get('notAfter')
                
                # Subject Alternative Names
                if 'subjectAltName' in cert:
                    cert_data['sans'] = [x[1] for x in cert['subjectAltName']]
                
                print(f"{Fore.GREEN}  [✓] Certificate retrieved{Style.RESET_ALL}")
                
                issuer_org = cert_data['issuer'].get('organizationName', 'Unknown')
                print(f"{Fore.GREEN}  [✓] Issuer: {issuer_org}{Style.RESET_ALL}")
                
                if cert_data['not_after']:
                    print(f"{Fore.GREEN}  [✓] Valid until: {cert_data['not_after']}{Style.RESET_ALL}")
                
                if cert_data['sans']:
                    print(f"{Fore.GREEN}  [✓] SANs: {len(cert_data['sans'])} domains{Style.RESET_ALL}")
                
    except ssl.SSLError as e:
        print(f"{Fore.YELLOW}  [!] SSL error: {str(e)[:80]}{Style.RESET_ALL}")
    except socket.timeout:
        print(f"{Fore.YELLOW}  [!] Connection timeout while checking SSL certificate{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}  [!] SSL inspection failed: {str(e)[:80]}{Style.RESET_ALL}")
    
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
        'all_headers': {},
        'protocol': None
    }
    
    # Try different protocols and URLs
    attempts = [
        f"https://{target}",
        f"http://{target}",
        f"https://{target}:443",
        f"http://{target}:80"
    ]
    
    for url in attempts:
        try:
            response = requests.get(
                url,
                timeout=10,
                allow_redirects=True,
                verify=False,  # Don't verify SSL for testing
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
            
            # Success - extract data
            header_data['status_code'] = response.status_code
            header_data['server'] = response.headers.get('Server', 'Unknown')
            header_data['powered_by'] = response.headers.get('X-Powered-By')
            header_data['content_type'] = response.headers.get('Content-Type')
            header_data['all_headers'] = dict(response.headers)
            header_data['protocol'] = 'HTTPS' if url.startswith('https') else 'HTTP'
            
            # Security headers
            security_headers = {
                'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
                'X-Frame-Options': response.headers.get('X-Frame-Options'),
                'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': response.headers.get('X-XSS-Protection')
            }
            header_data['security_headers'] = {k: v for k, v in security_headers.items() if v}
            
            print(f"{Fore.GREEN}  [✓] HTTP headers retrieved ({header_data['protocol']}){Style.RESET_ALL}")
            print(f"{Fore.GREEN}  [✓] Status: {header_data['status_code']}{Style.RESET_ALL}")
            
            if header_data['server']:
                print(f"{Fore.GREEN}  [✓] Server: {header_data['server']}{Style.RESET_ALL}")
            
            if header_data['powered_by']:
                print(f"{Fore.GREEN}  [✓] Powered By: {header_data['powered_by']}{Style.RESET_ALL}")
            
            print(f"{Fore.GREEN}  [✓] Security headers: {len(header_data['security_headers'])}/5{Style.RESET_ALL}")
            
            break  # Success, no need to try other URLs
            
        except requests.exceptions.SSLError:
            # Try next URL (likely will fall back to HTTP)
            continue
        except requests.exceptions.ConnectTimeout:
            print(f"{Fore.YELLOW}  [!] Connection timeout for {url.split('://')[0].upper()}{Style.RESET_ALL}")
            continue
        except requests.exceptions.ConnectionError as e:
            # Try next URL
            continue
        except requests.exceptions.RequestException as e:
            # Try next URL
            continue
        except Exception as e:
            # Try next URL
            continue
    
    # If all attempts failed
    if header_data['status_code'] is None:
        print(f"{Fore.YELLOW}  [!] Could not connect to web server on standard ports{Style.RESET_ALL}")
    
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
