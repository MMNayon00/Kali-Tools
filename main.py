#!/usr/bin/env python3
"""
MMN - Modular Reconnaissance & Assessment Framework
Main Controller

FOR AUTHORIZED USE ONLY
Use only on systems you own or have explicit permission to test.
"""

import os
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Import all modules
try:
    from modules import input_handler
    from modules import target_expansion
    from modules import footprinting
    from modules import subdomain_enum
    from modules import port_service_enum
    from modules import tech_fingerprint
    from modules import cve_mapper
    from modules import report_generator
except ImportError as e:
    print(f"{Fore.RED}[!] Error importing modules: {str(e)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Make sure all module files are present in the 'modules' directory{Style.RESET_ALL}")
    sys.exit(1)


# ASCII Banner - MANDATORY REQUIREMENT
MMN_BANNER = f"""{Fore.CYAN}
███╗   ███╗███╗   ███╗███╗   ██╗
████╗ ████║████╗ ████║████╗  ██║
██╔████╔██║██╔████╔██║██╔██╗ ██║
██║╚██╔╝██║██║╚██╔╝██║██║╚██╗██║
██║ ╚═╝ ██║██║ ╚═╝ ██║██║ ╚████║
╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.YELLOW}Modular Reconnaissance & Assessment Framework{Style.RESET_ALL}
{Fore.WHITE}Version 1.0.0 | For Authorized Use Only{Style.RESET_ALL}
"""


def clear_screen():
    """Clear terminal screen"""
    os.system('clear' if os.name != 'nt' else 'cls')


def display_banner():
    """Display MMN banner - MANDATORY at startup"""
    clear_screen()
    print(MMN_BANNER)


def display_disclaimer():
    """Display legal disclaimer - MANDATORY"""
    print(f"\n{Fore.RED}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.RED}⚠️  AUTHORIZATION WARNING ⚠️{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}")
    print("Use only on systems you own or have explicit permission to test.")
    print("Unauthorized access to computer systems is illegal.")
    print("The authors accept no liability for misuse of this tool.")
    print(f"{Style.RESET_ALL}")
    print(f"{Fore.RED}{'='*80}{Style.RESET_ALL}\n")


def display_menu():
    """Display main menu options"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'MAIN MENU':^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}[1] Full Assessment (All Modules){Style.RESET_ALL}")
    print(f"{Fore.WHITE}[2] Basic Footprinting (Quick Scan){Style.RESET_ALL}")
    print(f"{Fore.WHITE}[3] Custom Module Selection{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[0] Exit{Style.RESET_ALL}\n")


def display_module_menu():
    """Display custom module selection menu"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'SELECT MODULES TO RUN':^60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    print(f"{Fore.WHITE}[1] Target Expansion (DNS, IP, ASN){Style.RESET_ALL}")
    print(f"{Fore.WHITE}[2] Footprinting (WHOIS, SSL, HTTP){Style.RESET_ALL}")
    print(f"{Fore.WHITE}[3] Subdomain Enumeration{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[4] Port & Service Scanning{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[5] Technology Fingerprinting{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[6] CVE Vulnerability Mapping{Style.RESET_ALL}")
    print(f"{Fore.WHITE}[0] Back to Main Menu{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}Enter module numbers separated by commas (e.g., 1,2,4):{Style.RESET_ALL}")


def run_full_assessment(target: str) -> dict:
    """
    Run complete reconnaissance assessment
    
    Args:
        target: Target domain or IP address
        
    Returns:
        Dictionary with all results
    """
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'scan_type': 'Full Assessment'
    }
    
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'STARTING FULL ASSESSMENT':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    try:
        # 1. Target Expansion
        print(f"{Fore.YELLOW}[*] Module 1/6: Target Expansion{Style.RESET_ALL}")
        results['expansion'] = target_expansion.expand_target(target)
        
        # 2. Footprinting
        print(f"\n{Fore.YELLOW}[*] Module 2/6: Footprinting{Style.RESET_ALL}")
        results['footprinting'] = footprinting.perform_footprinting(target)
        
        # 3. Subdomain Enumeration
        print(f"\n{Fore.YELLOW}[*] Module 3/6: Subdomain Enumeration{Style.RESET_ALL}")
        results['subdomains'] = subdomain_enum.enumerate_subdomains(target, use_brute_force=False)
        
        # 4. Port Scanning
        print(f"\n{Fore.YELLOW}[*] Module 4/6: Port & Service Enumeration{Style.RESET_ALL}")
        target_ip = input_handler.resolve_target(target)
        if target_ip:
            results['ports'], results['os_detection'] = port_service_enum.scan_ports(target_ip, port_range="common", rate_limit=0.1)
        else:
            print(f"{Fore.RED}[!] Could not resolve target IP, skipping port scan{Style.RESET_ALL}")
            results['ports'] = []
            results['os_detection'] = {}
        
        # 5. Technology Fingerprinting
        print(f"\n{Fore.YELLOW}[*] Module 5/6: Technology Fingerprinting{Style.RESET_ALL}")
        results['technologies'] = tech_fingerprint.fingerprint_web_technology(target)
        
        # 6. CVE Mapping
        print(f"\n{Fore.YELLOW}[*] Module 6/6: CVE Vulnerability Mapping{Style.RESET_ALL}")
        if results.get('ports'):
            results['cve_report'] = cve_mapper.generate_cve_report(results['ports'])
        else:
            print(f"{Fore.YELLOW}[!] No open ports to analyze for CVEs{Style.RESET_ALL}")
            results['cve_report'] = {'total_services': 0, 'vulnerable_services': 0, 'total_cves': 0}
        
        print(f"\n{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[✓] Full assessment complete!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*80}{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Assessment interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during assessment: {str(e)}{Style.RESET_ALL}")
    
    return results


def run_basic_footprinting(target: str) -> dict:
    """
    Run basic footprinting only
    
    Args:
        target: Target domain or IP address
        
    Returns:
        Dictionary with results
    """
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'scan_type': 'Basic Footprinting'
    }
    
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'STARTING BASIC FOOTPRINTING':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    try:
        # Target Expansion
        results['expansion'] = target_expansion.expand_target(target)
        
        # Footprinting
        results['footprinting'] = footprinting.perform_footprinting(target)
        
        print(f"\n{Fore.GREEN}[✓] Basic footprinting complete!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Footprinting interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during footprinting: {str(e)}{Style.RESET_ALL}")
    
    return results


def run_custom_modules(target: str, module_selection: list) -> dict:
    """
    Run selected modules only
    
    Args:
        target: Target domain or IP address
        module_selection: List of module numbers to run
        
    Returns:
        Dictionary with results
    """
    results = {
        'target': target,
        'timestamp': datetime.now().isoformat(),
        'scan_type': 'Custom'
    }
    
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'RUNNING SELECTED MODULES':^80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
    
    try:
        if 1 in module_selection:
            print(f"{Fore.YELLOW}[*] Running: Target Expansion{Style.RESET_ALL}")
            results['expansion'] = target_expansion.expand_target(target)
        
        if 2 in module_selection:
            print(f"\n{Fore.YELLOW}[*] Running: Footprinting{Style.RESET_ALL}")
            results['footprinting'] = footprinting.perform_footprinting(target)
        
        if 3 in module_selection:
            print(f"\n{Fore.YELLOW}[*] Running: Subdomain Enumeration{Style.RESET_ALL}")
            results['subdomains'] = subdomain_enum.enumerate_subdomains(target, use_brute_force=False)
        
        if 4 in module_selection:
            print(f"\n{Fore.YELLOW}[*] Running: Port Scanning{Style.RESET_ALL}")
            target_ip = input_handler.resolve_target(target)
            if target_ip:
                results['ports'], results['os_detection'] = port_service_enum.scan_ports(target_ip, port_range="common", rate_limit=0.1)
            else:
                results['ports'] = []
                results['os_detection'] = {}
        
        if 5 in module_selection:
            print(f"\n{Fore.YELLOW}[*] Running: Technology Fingerprinting{Style.RESET_ALL}")
            results['technologies'] = tech_fingerprint.fingerprint_web_technology(target)
        
        if 6 in module_selection:
            print(f"\n{Fore.YELLOW}[*] Running: CVE Mapping{Style.RESET_ALL}")
            if results.get('ports'):
                results['cve_report'] = cve_mapper.generate_cve_report(results['ports'])
            else:
                print(f"{Fore.YELLOW}[!] Port scanning required for CVE mapping{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[✓] Selected modules complete!{Style.RESET_ALL}")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error during scan: {str(e)}{Style.RESET_ALL}")
    
    return results


def main():
    """Main program execution"""
    # MANDATORY: Display banner FIRST
    display_banner()
    
    # MANDATORY: Display disclaimer
    display_disclaimer()
    
    # Get user confirmation
    confirm = input(f"{Fore.YELLOW}Do you have authorization to test the target? (yes/no): {Style.RESET_ALL}").lower()
    if confirm not in ['yes', 'y']:
        print(f"\n{Fore.RED}[!] Authorization not confirmed. Exiting.{Style.RESET_ALL}")
        sys.exit(0)
    
    # Get target from user
    target = input_handler.get_target()
    
    if not target:
        print(f"\n{Fore.RED}[!] No valid target provided. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    # Main program loop
    while True:
        display_menu()
        
        try:
            choice = input(f"{Fore.CYAN}Select option: {Style.RESET_ALL}").strip()
            
            if choice == '0':
                print(f"\n{Fore.CYAN}[*] Exiting MMN Framework. Stay safe and legal!{Style.RESET_ALL}")
                sys.exit(0)
            
            elif choice == '1':
                # Full Assessment
                results = run_full_assessment(target)
                report_generator.generate_reports(results, formats=['cli', 'json', 'html'])
            
            elif choice == '2':
                # Basic Footprinting
                results = run_basic_footprinting(target)
                report_generator.generate_reports(results, formats=['cli', 'json'])
            
            elif choice == '3':
                # Custom Module Selection
                display_module_menu()
                module_input = input(f"{Fore.CYAN}> {Style.RESET_ALL}").strip()
                
                if module_input == '0':
                    continue
                
                try:
                    module_numbers = [int(x.strip()) for x in module_input.split(',') if x.strip()]
                    if module_numbers:
                        results = run_custom_modules(target, module_numbers)
                        report_generator.generate_reports(results, formats=['cli', 'json'])
                    else:
                        print(f"{Fore.RED}[!] No valid modules selected{Style.RESET_ALL}")
                except ValueError:
                    print(f"{Fore.RED}[!] Invalid input format{Style.RESET_ALL}")
            
            else:
                print(f"{Fore.RED}[!] Invalid option. Please try again.{Style.RESET_ALL}")
            
            # Ask if user wants to continue
            continue_scan = input(f"\n{Fore.YELLOW}Run another scan? (yes/no): {Style.RESET_ALL}").lower()
            if continue_scan not in ['yes', 'y']:
                print(f"\n{Fore.CYAN}[*] Thank you for using MMN Framework. Stay ethical!{Style.RESET_ALL}")
                break
        
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Interrupted by user{Style.RESET_ALL}")
            break
        except Exception as e:
            print(f"\n{Fore.RED}[!] Unexpected error: {str(e)}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Program terminated by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)
