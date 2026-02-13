"""
Technology Fingerprinting Module
Identify web technologies, servers, frameworks, and CMS
"""

import requests
from bs4 import BeautifulSoup
from typing import Dict, List
from colorama import Fore, Style
import re


def identify_from_headers(headers: Dict[str, str]) -> List[Dict]:
    """
    Identify technologies from HTTP headers
    
    Args:
        headers: HTTP response headers
        
    Returns:
        List of identified technologies
    """
    technologies = []
    
    # Server header
    if 'Server' in headers:
        server = headers['Server']
        if 'Apache' in server:
            technologies.append({'name': 'Apache', 'category': 'Web Server', 'confidence': 'High'})
        if 'nginx' in server:
            technologies.append({'name': 'nginx', 'category': 'Web Server', 'confidence': 'High'})
        if 'Microsoft-IIS' in server:
            technologies.append({'name': 'Microsoft IIS', 'category': 'Web Server', 'confidence': 'High'})
        if 'cloudflare' in server.lower():
            technologies.append({'name': 'Cloudflare', 'category': 'CDN', 'confidence': 'High'})
    
    # X-Powered-By header
    if 'X-Powered-By' in headers:
        powered_by = headers['X-Powered-By']
        if 'PHP' in powered_by:
            technologies.append({'name': 'PHP', 'category': 'Programming Language', 'confidence': 'High'})
        if 'ASP.NET' in powered_by:
            technologies.append({'name': 'ASP.NET', 'category': 'Web Framework', 'confidence': 'High'})
    
    # X-AspNet-Version
    if 'X-AspNet-Version' in headers:
        technologies.append({'name': 'ASP.NET', 'category': 'Web Framework', 'confidence': 'High'})
    
    # X-Generator
    if 'X-Generator' in headers:
        generator = headers['X-Generator']
        technologies.append({'name': generator, 'category': 'CMS/Framework', 'confidence': 'Medium'})
    
    return technologies


def identify_from_html(html_content: str, url: str) -> List[Dict]:
    """
    Identify technologies from HTML content
    
    Args:
        html_content: HTML page content
        url: Target URL
        
    Returns:
        List of identified technologies
    """
    technologies = []
    
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Meta generator tag
        generator_meta = soup.find('meta', attrs={'name': 'generator'})
        if generator_meta and generator_meta.get('content'):
            generator = generator_meta.get('content')
            if 'WordPress' in generator:
                technologies.append({'name': 'WordPress', 'category': 'CMS', 'confidence': 'High'})
            elif 'Drupal' in generator:
                technologies.append({'name': 'Drupal', 'category': 'CMS', 'confidence': 'High'})
            elif 'Joomla' in generator:
                technologies.append({'name': 'Joomla', 'category': 'CMS', 'confidence': 'High'})
        
        # WordPress detection
        if '/wp-content/' in html_content or '/wp-includes/' in html_content:
            if not any(t['name'] == 'WordPress' for t in technologies):
                technologies.append({'name': 'WordPress', 'category': 'CMS', 'confidence': 'High'})
        
        # Drupal detection
        if 'Drupal' in html_content or '/sites/default/files/' in html_content:
            if not any(t['name'] == 'Drupal' for t in technologies):
                technologies.append({'name': 'Drupal', 'category': 'CMS', 'confidence': 'Medium'})
        
        # Joomla detection
        if '/components/com_' in html_content or 'Joomla' in html_content:
            if not any(t['name'] == 'Joomla' for t in technologies):
                technologies.append({'name': 'Joomla', 'category': 'CMS', 'confidence': 'Medium'})
        
        # jQuery detection
        if 'jquery' in html_content.lower():
            technologies.append({'name': 'jQuery', 'category': 'JavaScript Library', 'confidence': 'High'})
        
        # React detection
        if 'react' in html_content.lower() or '_reactRootContainer' in html_content:
            technologies.append({'name': 'React', 'category': 'JavaScript Framework', 'confidence': 'High'})
        
        # Vue.js detection
        if 'vue' in html_content.lower() or 'v-if' in html_content or 'v-for' in html_content:
            technologies.append({'name': 'Vue.js', 'category': 'JavaScript Framework', 'confidence': 'Medium'})
        
        # Angular detection
        if 'ng-' in html_content or 'angular' in html_content.lower():
            technologies.append({'name': 'Angular', 'category': 'JavaScript Framework', 'confidence': 'Medium'})
        
        # Bootstrap detection
        if 'bootstrap' in html_content.lower():
            technologies.append({'name': 'Bootstrap', 'category': 'CSS Framework', 'confidence': 'High'})
        
        # Google Analytics
        if 'google-analytics.com' in html_content or 'gtag' in html_content:
            technologies.append({'name': 'Google Analytics', 'category': 'Analytics', 'confidence': 'High'})
        
        # Cloudflare
        if 'cloudflare' in html_content.lower():
            if not any(t['name'] == 'Cloudflare' for t in technologies):
                technologies.append({'name': 'Cloudflare', 'category': 'CDN', 'confidence': 'Medium'})
        
    except Exception as e:
        print(f"{Fore.RED}  [!] HTML parsing error: {str(e)}{Style.RESET_ALL}")
    
    return technologies


def fingerprint_web_technology(target: str) -> Dict:
    """
    Comprehensive web technology fingerprinting
    
    Args:
        target: Domain or IP address
        
    Returns:
        Dictionary with identified technologies
    """
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}TECHNOLOGY FINGERPRINTING{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    fingerprint_data = {
        'target': target,
        'technologies': [],
        'web_servers': [],
        'cms': [],
        'frameworks': [],
        'libraries': []
    }
    
    protocols = ['https://', 'http://']
    
    for protocol in protocols:
        url = f"{protocol}{target}"
        
        try:
            print(f"\n{Fore.YELLOW}[*] Analyzing {url}...{Style.RESET_ALL}")
            
            response = requests.get(
                url,
                timeout=15,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            # Identify from headers
            tech_from_headers = identify_from_headers(dict(response.headers))
            fingerprint_data['technologies'].extend(tech_from_headers)
            
            # Identify from HTML
            tech_from_html = identify_from_html(response.text, url)
            fingerprint_data['technologies'].extend(tech_from_html)
            
            print(f"{Fore.GREEN}[✓] Analysis complete{Style.RESET_ALL}")
            break  # Success
            
        except Exception as e:
            if protocol == protocols[-1]:
                print(f"{Fore.RED}[!] Technology fingerprinting failed: {str(e)}{Style.RESET_ALL}")
    
    # Remove duplicates and categorize
    seen = set()
    unique_technologies = []
    
    for tech in fingerprint_data['technologies']:
        tech_name = tech['name']
        if tech_name not in seen:
            seen.add(tech_name)
            unique_technologies.append(tech)
            
            # Categorize
            category = tech['category']
            if 'Server' in category:
                fingerprint_data['web_servers'].append(tech_name)
            elif 'CMS' in category:
                fingerprint_data['cms'].append(tech_name)
            elif 'Framework' in category:
                fingerprint_data['frameworks'].append(tech_name)
            elif 'Library' in category:
                fingerprint_data['libraries'].append(tech_name)
    
    fingerprint_data['technologies'] = unique_technologies
    
    # Display results
    print(f"\n{Fore.GREEN}[✓] Technologies identified: {len(unique_technologies)}{Style.RESET_ALL}")
    
    if unique_technologies:
        print(f"\n{Fore.CYAN}Detected Technologies:{Style.RESET_ALL}")
        for tech in unique_technologies:
            print(f"{Fore.GREEN}  • {tech['name']} ({tech['category']}) - Confidence: {tech['confidence']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] No technologies identified{Style.RESET_ALL}")
    
    return fingerprint_data


if __name__ == "__main__":
    # Test module
    test_target = "example.com"
    result = fingerprint_web_technology(test_target)
    print(f"\n{Fore.CYAN}Results:{Style.RESET_ALL}")
    print(result)
