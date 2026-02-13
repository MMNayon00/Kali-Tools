"""
Port and Service Enumeration Module
Rate-limited port scanning with service detection and banner grabbing
"""

import socket
import time
from typing import Dict, List
from colorama import Fore, Style


# Common ports and their typical services
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt'
}


def check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """
    Check if a port is open
    
    Args:
        ip: Target IP address
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except socket.error:
        return False


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to grab service banner (read-only)
    
    Args:
        ip: Target IP address
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        Banner string or empty string
    """
    banner = ""
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Try to receive banner
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            # Some services need a request first (like HTTP)
            if port in [80, 8080, 8443]:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        
        sock.close()
    except:
        pass
    
    return banner


def detect_service_version(banner: str, port: int) -> Dict[str, str]:
    """
    Detect service name and version from banner
    
    Args:
        banner: Service banner string
        port: Port number
        
    Returns:
        Dictionary with service and version info
    """
    service_info = {
        'service': COMMON_PORTS.get(port, 'Unknown'),
        'version': 'Unknown',
        'product': 'Unknown'
    }
    
    if not banner:
        return service_info
    
    banner_lower = banner.lower()
    
    # SSH detection
    if 'ssh' in banner_lower:
        service_info['service'] = 'SSH'
        if 'openssh' in banner_lower:
            service_info['product'] = 'OpenSSH'
            # Extract version
            import re
            version_match = re.search(r'openssh[_\s]*([\d.]+\w*)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
    
    # HTTP/Web servers
    elif 'http' in banner_lower or port in [80, 443, 8080, 8443]:
        if 'apache' in banner_lower:
            service_info['product'] = 'Apache'
            import re
            version_match = re.search(r'apache/([\d.]+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
        elif 'nginx' in banner_lower:
            service_info['product'] = 'nginx'
            import re
            version_match = re.search(r'nginx/([\d.]+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
        elif 'microsoft-iis' in banner_lower:
            service_info['product'] = 'Microsoft IIS'
            import re
            version_match = re.search(r'microsoft-iis/([\d.]+)', banner_lower)
            if version_match:
                service_info['version'] = version_match.group(1)
        service_info['service'] = 'HTTP' if port in [80, 8080] else 'HTTPS'
    
    # FTP detection
    elif 'ftp' in banner_lower or port == 21:
        service_info['service'] = 'FTP'
        if 'vsftpd' in banner_lower:
            service_info['product'] = 'vsftpd'
        elif 'proftpd' in banner_lower:
            service_info['product'] = 'ProFTPD'
    
    # SMTP detection
    elif 'smtp' in banner_lower or port == 25:
        service_info['service'] = 'SMTP'
        if 'postfix' in banner_lower:
            service_info['product'] = 'Postfix'
        elif 'sendmail' in banner_lower:
            service_info['product'] = 'Sendmail'
    
    return service_info


def scan_ports(target: str, port_range: str = "common", rate_limit: float = 0.1) -> List[Dict]:
    """
    Scan ports on target with rate limiting
    
    Args:
        target: IP address to scan
        port_range: "common", "top100", or "1-1000"
        rate_limit: Delay between scans in seconds
        
    Returns:
        List of open ports with service info
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}PORT & SERVICE ENUMERATION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    # Determine ports to scan
    if port_range == "common":
        ports_to_scan = list(COMMON_PORTS.keys())
    elif port_range == "top100":
        ports_to_scan = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 20, 69, 137, 138, 161, 162, 389,
            512, 513, 514, 587, 631, 1433, 1434, 1521, 2049, 2082, 2083, 2086, 2087,
            2095, 2096, 3128, 5432, 5631, 5632, 5800, 5901, 6000, 6001, 6002, 8008, 8009,
            8011, 8081, 8082, 8181, 8291, 8888, 9090, 9100, 9999, 10000, 32768, 49152,
            49153, 49154, 49155, 49156, 49157, 50000
        ]
    else:
        # Parse range like "1-1000"
        try:
            start, end = map(int, port_range.split('-'))
            ports_to_scan = list(range(start, min(end + 1, 65536)))
        except:
            print(f"{Fore.RED}[!] Invalid port range, using common ports{Style.RESET_ALL}")
            ports_to_scan = list(COMMON_PORTS.keys())
    
    print(f"\n{Fore.YELLOW}[*] Scanning {len(ports_to_scan)} ports on {target}...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Rate limit: {rate_limit}s between scans{Style.RESET_ALL}")
    
    open_ports = []
    scanned = 0
    
    for port in ports_to_scan:
        scanned += 1
        
        # Progress indicator every 10 ports
        if scanned % 10 == 0:
            print(f"{Fore.YELLOW}[*] Progress: {scanned}/{len(ports_to_scan)} ports scanned...{Style.RESET_ALL}")
        
        if check_port(target, port):
            print(f"{Fore.GREEN}[✓] Port {port} is OPEN{Style.RESET_ALL}")
            
            # Grab banner
            banner = grab_banner(target, port)
            
            # Detect service
            service_info = detect_service_version(banner, port)
            
            port_data = {
                'port': port,
                'state': 'open',
                'service': service_info['service'],
                'product': service_info['product'],
                'version': service_info['version'],
                'banner': banner[:200] if banner else ''  # Limit banner size
            }
            
            open_ports.append(port_data)
            
            print(f"{Fore.GREEN}    Service: {service_info['service']} | "
                  f"Product: {service_info['product']} | "
                  f"Version: {service_info['version']}{Style.RESET_ALL}")
        
        # Rate limiting
        time.sleep(rate_limit)
    
    print(f"\n{Fore.GREEN}[✓] Scan complete: {len(open_ports)} open ports found{Style.RESET_ALL}")
    
    return open_ports


if __name__ == "__main__":
    # Test module
    test_target = "scanme.nmap.org"
    print(f"{Fore.CYAN}Testing with {test_target}{Style.RESET_ALL}")
    result = scan_ports(test_target, port_range="common", rate_limit=0.5)
    print(f"\n{Fore.CYAN}Results:{Style.RESET_ALL}")
    for port_info in result:
        print(port_info)
