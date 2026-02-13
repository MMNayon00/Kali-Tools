"""
Target Expansion Module
DNS resolution, IP discovery, ASN and hosting provider identification
"""

import socket
import dns.resolver
import re
from typing import Dict, List, Optional
from colorama import Fore, Style


def is_valid_domain(target: str) -> bool:
    """
    Check if target is a valid domain name
    
    Args:
        target: String to validate
        
    Returns:
        True if valid domain, False otherwise
    """
    # Basic domain validation
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(domain_pattern, target))


def is_valid_ip(target: str) -> bool:
    """
    Check if target is a valid IP address
    
    Args:
        target: String to validate
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        return False


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
        'CNAME': [],
        'SOA': []
    }
    
    if not target:
        return results
    
    # Skip DNS resolution for IP addresses
    if is_valid_ip(target):
        print(f"\n{Fore.CYAN}[i] Target is an IP address, skipping DNS resolution{Style.RESET_ALL}")
        return results
    
    print(f"\n{Fore.YELLOW}[*] Performing DNS resolution...{Style.RESET_ALL}")
    
    # Configure DNS resolver with multiple nameservers
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']  # Google + Cloudflare DNS
    resolver.timeout = 10
    resolver.lifetime = 10
    
    # Query each record type
    for record_type in results.keys():
        try:
            answers = resolver.resolve(target, record_type)
            for rdata in answers:
                record_value = str(rdata).rstrip('.')
                results[record_type].append(record_value)
            if results[record_type]:
                print(f"{Fore.GREEN}  [✓] {record_type}: {len(results[record_type])} records{Style.RESET_ALL}")
        except dns.resolver.NoAnswer:
            # No records of this type - normal, don't print error
            pass
        except dns.resolver.NXDOMAIN:
            print(f"{Fore.RED}  [!] Domain does not exist{Style.RESET_ALL}")
            break
        except dns.resolver.NoNameservers:
            print(f"{Fore.RED}  [!] No nameservers available{Style.RESET_ALL}")
            break
        except dns.resolver.Timeout:
            print(f"{Fore.YELLOW}  [!] {record_type} lookup timed out{Style.RESET_ALL}")
        except Exception as e:
            # Silently continue for other errors
            pass
    
    return results


def get_ip_addresses(target: str) -> List[str]:
    """
    Get all IP addresses associated with target
    
    Args:
        target: Domain name or IP address
        
    Returns:
        List of IP addresses
    """
    ip_list = []
    
    # If target is already an IP, return it
    if is_valid_ip(target):
        return [target]
    
    try:
        # Try standard resolution first
        addr_info = socket.getaddrinfo(target, None, socket.AF_INET)
        for info in addr_info:
            ip = info[4][0]
            if ip not in ip_list:
                ip_list.append(ip)
    except socket.gaierror as e:
        print(f"{Fore.YELLOW}  [!] Could not resolve {target}: {str(e)}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}  [!] Error resolving {target}: {str(e)}{Style.RESET_ALL}")
    
    # Fallback: try DNS A record lookup
    if not ip_list and is_valid_domain(target):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            resolver.timeout = 5
            answers = resolver.resolve(target, 'A')
            for rdata in answers:
                ip = str(rdata)
                if ip not in ip_list:
                    ip_list.append(ip)
        except:
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
        'target_type': 'domain' if is_valid_domain(target) else 'ip',
        'dns_records': {},
        'ip_addresses': [],
        'reverse_dns': None,
        'hosting_provider': {}
    }
    
    # DNS resolution (only for domains)
    if is_valid_domain(target):
        expansion_data['dns_records'] = dns_resolution(target)
    else:
        print(f"\n{Fore.CYAN}[i] Target is an IP address, DNS resolution skipped{Style.RESET_ALL}")
    
    # Get IP addresses
    print(f"\n{Fore.YELLOW}[*] Discovering IP addresses...{Style.RESET_ALL}")
    expansion_data['ip_addresses'] = get_ip_addresses(target)
    
    if expansion_data['ip_addresses']:
        for ip in expansion_data['ip_addresses']:
            print(f"{Fore.GREEN}  [✓] {ip}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}  [!] Could not resolve any IP addresses{Style.RESET_ALL}")
        return expansion_data
    
    # Reverse DNS
    if expansion_data['ip_addresses']:
        primary_ip = expansion_data['ip_addresses'][0]
        print(f"\n{Fore.YELLOW}[*] Reverse DNS lookup...{Style.RESET_ALL}")
        expansion_data['reverse_dns'] = reverse_dns_lookup(primary_ip)
        if expansion_data['reverse_dns']:
            print(f"{Fore.GREEN}  [✓] {expansion_data['reverse_dns']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}  [i] No reverse DNS record found{Style.RESET_ALL}")
        
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
