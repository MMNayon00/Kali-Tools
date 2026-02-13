"""
Subdomain Enumeration Module
Passive subdomain enumeration via Certificate Transparency and other sources
"""

import requests
from typing import List, Set
from colorama import Fore, Style
import re


def crt_sh_enumeration(domain: str) -> Set[str]:
    """
    Enumerate subdomains using crt.sh Certificate Transparency logs
    
    Args:
        domain: Target domain
        
    Returns:
        Set of discovered subdomains
    """
    subdomains = set()
    
    print(f"{Fore.YELLOW}  [*] Querying crt.sh...{Style.RESET_ALL}")
    
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                # Split by newlines (crt.sh returns multiple domains per entry sometimes)
                names = name_value.split('\n')
                for name in names:
                    name = name.strip().lower()
                    # Filter wildcards and add valid subdomains
                    if '*' not in name and name.endswith(domain):
                        subdomains.add(name)
            
            print(f"{Fore.GREEN}  [✓] crt.sh: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}  [!] crt.sh returned status {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}  [!] crt.sh lookup failed: {str(e)}{Style.RESET_ALL}")
    
    return subdomains


def hackertarget_enumeration(domain: str) -> Set[str]:
    """
    Enumerate subdomains using HackerTarget API
    
    Args:
        domain: Target domain
        
    Returns:
        Set of discovered subdomains
    """
    subdomains = set()
    
    print(f"{Fore.YELLOW}  [*] Querying HackerTarget...{Style.RESET_ALL}")
    
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = requests.get(url, timeout=15)
        
        if response.status_code == 200:
            lines = response.text.split('\n')
            for line in lines:
                if ',' in line:
                    subdomain = line.split(',')[0].strip().lower()
                    if subdomain and subdomain.endswith(domain):
                        subdomains.add(subdomain)
            
            print(f"{Fore.GREEN}  [✓] HackerTarget: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}  [!] HackerTarget returned status {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}  [!] HackerTarget lookup failed: {str(e)}{Style.RESET_ALL}")
    
    return subdomains


def common_subdomain_bruteforce(domain: str) -> Set[str]:
    """
    Try common subdomain names (passive, DNS query only)
    
    Args:
        domain: Target domain
        
    Returns:
        Set of discovered subdomains
    """
    import socket
    
    subdomains = set()
    
    # Common subdomain prefixes
    common_names = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
        'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
        'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
        'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
        'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
        'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1'
    ]
    
    print(f"{Fore.YELLOW}  [*] Testing common subdomains...{Style.RESET_ALL}")
    
    found_count = 0
    for prefix in common_names:
        subdomain = f"{prefix}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            subdomains.add(subdomain)
            found_count += 1
        except socket.gaierror:
            pass
    
    print(f"{Fore.GREEN}  [✓] Common names: Found {found_count} subdomains{Style.RESET_ALL}")
    
    return subdomains


def enumerate_subdomains(domain: str, use_brute_force: bool = False) -> List[str]:
    """
    Comprehensive subdomain enumeration
    
    Args:
        domain: Target domain
        use_brute_force: Whether to test common subdomain names
        
    Returns:
        List of discovered subdomains
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SUBDOMAIN ENUMERATION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}[*] Starting subdomain discovery for {domain}...{Style.RESET_ALL}")
    
    all_subdomains = set()
    
    # Certificate Transparency
    all_subdomains.update(crt_sh_enumeration(domain))
    
    # HackerTarget API
    all_subdomains.update(hackertarget_enumeration(domain))
    
    # Common subdomain testing (optional)
    if use_brute_force:
        all_subdomains.update(common_subdomain_bruteforce(domain))
    
    # Convert to sorted list
    subdomain_list = sorted(list(all_subdomains))
    
    print(f"\n{Fore.GREEN}[✓] Total unique subdomains found: {len(subdomain_list)}{Style.RESET_ALL}")
    
    # Display first 20 subdomains
    if subdomain_list:
        print(f"\n{Fore.CYAN}Sample subdomains:{Style.RESET_ALL}")
        for subdomain in subdomain_list[:20]:
            print(f"{Fore.GREEN}  • {subdomain}{Style.RESET_ALL}")
        
        if len(subdomain_list) > 20:
            print(f"{Fore.YELLOW}  ... and {len(subdomain_list) - 20} more{Style.RESET_ALL}")
    
    return subdomain_list


if __name__ == "__main__":
    # Test module
    test_domain = "example.com"
    result = enumerate_subdomains(test_domain, use_brute_force=False)
    print(f"\n{Fore.CYAN}Total found: {len(result)}{Style.RESET_ALL}")
