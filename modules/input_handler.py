"""
Input Handler Module
Validates and sanitizes user input for target specification
"""

import re
import socket
from typing import Optional


def validate_ip(ip_address: str) -> bool:
    """
    Validate IPv4 address format
    
    Args:
        ip_address: String to validate as IP
        
    Returns:
        True if valid IPv4, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip_address):
        return False
    
    # Check each octet is 0-255
    octets = ip_address.split('.')
    for octet in octets:
        if int(octet) > 255:
            return False
    return True


def validate_domain(domain: str) -> bool:
    """
    Validate domain name format
    
    Args:
        domain: String to validate as domain
        
    Returns:
        True if valid domain, False otherwise
    """
    # Basic domain validation
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def sanitize_input(user_input: str) -> str:
    """
    Sanitize user input by removing dangerous characters
    
    Args:
        user_input: Raw input from user
        
    Returns:
        Sanitized string
    """
    # Remove whitespace
    sanitized = user_input.strip()
    
    # Remove protocol if present
    sanitized = re.sub(r'^https?://', '', sanitized, flags=re.IGNORECASE)
    
    # Remove trailing slashes
    sanitized = sanitized.rstrip('/')
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[;&|`$()]', '', sanitized)
    
    return sanitized


def get_target() -> Optional[str]:
    """
    Get and validate target from user input
    
    Returns:
        Validated target string or None if invalid
    """
    from colorama import Fore, Style
    
    while True:
        user_input = input(f"\n{Fore.CYAN}[?] Enter target (IP or domain): {Style.RESET_ALL}").strip()
        
        if not user_input:
            print(f"{Fore.RED}[!] Error: Empty input{Style.RESET_ALL}")
            continue
        
        # Sanitize input
        target = sanitize_input(user_input)
        
        # Validate
        if validate_ip(target):
            print(f"{Fore.GREEN}[✓] Valid IP address: {target}{Style.RESET_ALL}")
            return target
        elif validate_domain(target):
            print(f"{Fore.GREEN}[✓] Valid domain: {target}{Style.RESET_ALL}")
            return target
        else:
            print(f"{Fore.RED}[!] Error: Invalid IP or domain format{Style.RESET_ALL}")
            retry = input(f"{Fore.YELLOW}[?] Try again? (y/n): {Style.RESET_ALL}").lower()
            if retry != 'y':
                return None


def resolve_target(target: str) -> Optional[str]:
    """
    Resolve domain to IP if needed
    
    Args:
        target: Domain name or IP address
        
    Returns:
        IP address or None if resolution fails
    """
    if validate_ip(target):
        return target
    
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        return None


if __name__ == "__main__":
    # Test module
    print("Input Handler Module Test")
    target = get_target()
    if target:
        ip = resolve_target(target)
        print(f"Resolved IP: {ip}")
