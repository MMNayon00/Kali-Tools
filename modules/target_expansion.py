"""
Target Expansion Module
DNS resolution, IP discovery, ASN and hosting provider identification
"""

import socket
import dns.resolver
from typing import Dict, List, Optional
from colorama import Fore, Style


def dns_resolution(target: str) -> Dict[str, List[str]]:
    """
    Perform comprehensive DNS resolution
    
    Args:
        target: Domain name or IP address
        
    Returns:
        Dictionary containing DNS records
    """
    results = {
        'A': [],
        'AAAA': [],
        'MX': [],
        'NS': [],
        'TXT': [],
        'CNAME': []
    }
    
    if not target:
        return results
    
    print(f"\n{Fore.YELLOW}[*] Performing DNS resolution...{Style.RESET_ALL}")
    
    # Query each record type
    for record_type in results.keys():
        try:
            answers = dns.resolver.resolve(target, record_type, lifetime=5)
            for rdata in answers:
                results[record_type].append(str(rdata))
            print(f"{Fore.GREEN}  [✓] {record_type}: {len(results[record_type])} records{Style.RESET_ALL}")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            print(f"{Fore.RED}  [!] {record_type} lookup failed: {str(e)}{Style.RESET_ALL}")
    
    return results


def get_ip_addresses(target: str) -> List[str]:
    """
    Get all IP addresses associated with target
    
    Args:
        target: Domain name
        
    Returns:
        List of IP addresses
    """
    ip_list = []
    
    try:
        # Get all addresses
        addr_info = socket.getaddrinfo(target, None)
        for info in addr_info:
            ip = info[4][0]
            if ip not in ip_list:
                ip_list.append(ip)
    except socket.gaierror:
        pass
    
    return ip_list


def reverse_dns_lookup(ip_address: str) -> Optional[str]:
    """
    Perform reverse DNS lookup
    
    Args:
        ip_address: IP address
        
    Returns:
        Hostname or None
    """
    try:
        hostname = socket.gethostbyaddr(ip_address)
        return hostname[0]
    except (socket.herror, socket.gaierror):
        return None


def identify_hosting_provider(ip_address: str) -> Dict[str, str]:
    """
    Attempt to identify hosting provider (basic implementation)
    
    Args:
        ip_address: Target IP address
        
    Returns:
        Dictionary with provider info
    """
    provider_info = {
        'provider': 'Unknown',
        'type': 'Unknown'
    }
    
    # This is a simplified implementation
    # In production, you would use IP geolocation APIs or WHOIS data
    try:
        hostname = reverse_dns_lookup(ip_address)
        if hostname:
            # Check for common hosting providers in hostname
            providers = {
                'amazonaws': 'Amazon AWS',
                'googleusercontent': 'Google Cloud',
                'cloudflare': 'Cloudflare',
                'azure': 'Microsoft Azure',
                'digitalocean': 'DigitalOcean',
                'linode': 'Linode',
                'ovh': 'OVH'
            }
            
            hostname_lower = hostname.lower()
            for key, value in providers.items():
                if key in hostname_lower:
                    provider_info['provider'] = value
                    provider_info['type'] = 'Cloud/Hosting'
                    break
    except Exception:
        pass
    
    return provider_info


def expand_target(target: str) -> Dict:
    """
    Comprehensive target expansion
    
    Args:
        target: Domain or IP address
        
    Returns:
        Dictionary with all expansion data
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}TARGET EXPANSION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    expansion_data = {
        'target': target,
        'dns_records': {},
        'ip_addresses': [],
        'reverse_dns': None,
        'hosting_provider': {}
    }
    
    # DNS resolution
    expansion_data['dns_records'] = dns_resolution(target)
    
    # Get IP addresses
    print(f"\n{Fore.YELLOW}[*] Discovering IP addresses...{Style.RESET_ALL}")
    expansion_data['ip_addresses'] = get_ip_addresses(target)
    for ip in expansion_data['ip_addresses']:
        print(f"{Fore.GREEN}  [✓] {ip}{Style.RESET_ALL}")
    
    # Reverse DNS
    if expansion_data['ip_addresses']:
        primary_ip = expansion_data['ip_addresses'][0]
        print(f"\n{Fore.YELLOW}[*] Reverse DNS lookup...{Style.RESET_ALL}")
        expansion_data['reverse_dns'] = reverse_dns_lookup(primary_ip)
        if expansion_data['reverse_dns']:
            print(f"{Fore.GREEN}  [✓] {expansion_data['reverse_dns']}{Style.RESET_ALL}")
        
        # Hosting provider
        print(f"\n{Fore.YELLOW}[*] Identifying hosting provider...{Style.RESET_ALL}")
        expansion_data['hosting_provider'] = identify_hosting_provider(primary_ip)
        print(f"{Fore.GREEN}  [✓] Provider: {expansion_data['hosting_provider']['provider']}{Style.RESET_ALL}")
    
    return expansion_data


if __name__ == "__main__":
    # Test module
    test_target = "example.com"
    result = expand_target(test_target)
    print(f"\n{Fore.CYAN}Results:{Style.RESET_ALL}")
    print(result)
