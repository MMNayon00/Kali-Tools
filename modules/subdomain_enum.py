"""
Subdomain Enumeration Module
Passive subdomain enumeration via Certificate Transparency and other sources
"""

import socket
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set
from colorama import Fore, Style


# ── helpers ──────────────────────────────────────────────────────────────────

def _get_with_retry(url: str, timeout: int = 20, retries: int = 3,
                    backoff: float = 2.0) -> requests.Response | None:
    """GET request with automatic retry and exponential back-off."""
    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(url, timeout=timeout,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; subdomainEnum/1.0)"})
            if resp.status_code == 200:
                return resp
            # 429 = rate-limited: always retry after a pause
            if resp.status_code == 429:
                time.sleep(backoff * attempt)
                continue
        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass
        if attempt < retries:
            time.sleep(backoff * attempt)
    return None


def _is_valid_subdomain(name: str, domain: str) -> bool:
    """Return True only if name is a real sub/domain of domain."""
    name = name.strip().lower()
    if not name:
        return False
    if '*' in name or ' ' in name:
        return False
    # Must end with the root domain AND be separated by a dot (or equal)
    if name == domain:
        return True
    if name.endswith('.' + domain):
        return True
    return False


# ── sources ───────────────────────────────────────────────────────────────────

def crt_sh_enumeration(domain: str) -> Set[str]:
    """Enumerate subdomains using crt.sh Certificate Transparency logs."""
    subdomains: Set[str] = set()
    print(f"{Fore.YELLOW}  [*] Querying crt.sh...{Style.RESET_ALL}")

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    resp = _get_with_retry(url, timeout=30, retries=3)

    if resp is None:
        print(f"{Fore.RED}  [!] crt.sh lookup failed (no response after retries){Style.RESET_ALL}")
        return subdomains

    try:
        data = resp.json()
    except ValueError:
        print(f"{Fore.RED}  [!] crt.sh returned non-JSON data{Style.RESET_ALL}")
        return subdomains

    for entry in data:
        for name in entry.get('name_value', '').split('\n'):
            if _is_valid_subdomain(name, domain):
                subdomains.add(name.strip().lower())

    print(f"{Fore.GREEN}  [✓] crt.sh: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
    return subdomains


def hackertarget_enumeration(domain: str) -> Set[str]:
    """Enumerate subdomains using HackerTarget API."""
    subdomains: Set[str] = set()
    print(f"{Fore.YELLOW}  [*] Querying HackerTarget...{Style.RESET_ALL}")

    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    resp = _get_with_retry(url, timeout=15, retries=3)

    if resp is None:
        print(f"{Fore.RED}  [!] HackerTarget lookup failed (no response after retries){Style.RESET_ALL}")
        return subdomains

    # HackerTarget sends plain-text error messages when rate-limited
    body = resp.text.strip()
    if body.lower().startswith('error') or 'api count exceeded' in body.lower():
        print(f"{Fore.YELLOW}  [!] HackerTarget: {body[:80]}{Style.RESET_ALL}")
        return subdomains

    for line in body.split('\n'):
        if ',' in line:
            candidate = line.split(',')[0].strip().lower()
            if _is_valid_subdomain(candidate, domain):
                subdomains.add(candidate)

    print(f"{Fore.GREEN}  [✓] HackerTarget: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
    return subdomains


def alienvault_enumeration(domain: str) -> Set[str]:
    """Enumerate subdomains using AlienVault OTX (free, no key required)."""
    subdomains: Set[str] = set()
    print(f"{Fore.YELLOW}  [*] Querying AlienVault OTX...{Style.RESET_ALL}")

    page = 1
    while True:
        url = (f"https://otx.alienvault.com/api/v1/indicators/domain/"
               f"{domain}/passive_dns?limit=500&page={page}")
        resp = _get_with_retry(url, timeout=20, retries=3)
        if resp is None:
            break

        try:
            data = resp.json()
        except ValueError:
            break

        records = data.get('passive_dns', [])
        if not records:
            break

        for record in records:
            hostname = record.get('hostname', '').strip().lower()
            if _is_valid_subdomain(hostname, domain):
                subdomains.add(hostname)

        # Paginate if more results exist
        if len(records) < 500:
            break
        page += 1

    print(f"{Fore.GREEN}  [✓] AlienVault OTX: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
    return subdomains


def common_subdomain_bruteforce(domain: str, max_workers: int = 30) -> Set[str]:
    """
    Try common subdomain names with concurrent DNS lookups and a per-query timeout.
    """
    common_names = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
        'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
        'ns', 'blog', 'pop3', 'dev', 'www2', 'admin', 'forum', 'news', 'vpn',
        'ns3', 'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile', 'mx',
        'static', 'docs', 'beta', 'shop', 'sql', 'secure', 'demo', 'cp', 'calendar',
        'wiki', 'web', 'media', 'email', 'images', 'img', 'www1', 'intranet', 'portal',
        'video', 'sip', 'dns2', 'api', 'cdn', 'stats', 'dns1', 'ns4', 'www3', 'dns',
        'search', 'staging', 'server', 'mx1', 'chat', 'wap', 'my', 'svn', 'mail1',
        'app', 'login', 'auth', 'store', 'help', 'status', 'monitor', 'dashboard',
        'git', 'gitlab', 'jenkins', 'jira', 'confluence', 'remote', 'vpn2', 'proxy',
    ]

    print(f"{Fore.YELLOW}  [*] Testing {len(common_names)} common subdomains (concurrent)...{Style.RESET_ALL}")

    subdomains: Set[str] = set()

    def _resolve(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        try:
            # getaddrinfo respects the system resolver timeout better than gethostbyname
            socket.getaddrinfo(fqdn, None, proto=socket.IPPROTO_TCP)
            return fqdn
        except (socket.gaierror, socket.herror, OSError):
            return None

    # Use a thread pool so all names are tried in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_resolve, name): name for name in common_names}
        for future in as_completed(futures, timeout=60):
            result = future.result()
            if result:
                subdomains.add(result)

    print(f"{Fore.GREEN}  [✓] Common names: Found {len(subdomains)} subdomains{Style.RESET_ALL}")
    return subdomains


# ── main entry-point ──────────────────────────────────────────────────────────

def enumerate_subdomains(domain: str, use_brute_force: bool = False) -> List[str]:
    """
    Comprehensive subdomain enumeration.

    Args:
        domain: Target domain (e.g. 'example.com')
        use_brute_force: Whether to also test common subdomain names via DNS

    Returns:
        Sorted list of discovered subdomains
    """
    # Normalise the domain
    domain = domain.strip().lower().removeprefix('www.')

    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}SUBDOMAIN ENUMERATION{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}[*] Starting subdomain discovery for {domain}...{Style.RESET_ALL}")

    all_subdomains: Set[str] = set()

    # Source 1 – Certificate Transparency (crt.sh)
    all_subdomains.update(crt_sh_enumeration(domain))

    # Source 2 – HackerTarget
    all_subdomains.update(hackertarget_enumeration(domain))

    # Source 3 – AlienVault OTX
    all_subdomains.update(alienvault_enumeration(domain))

    # Source 4 – Common name bruteforce (optional)
    if use_brute_force:
        all_subdomains.update(common_subdomain_bruteforce(domain))

    subdomain_list = sorted(all_subdomains)

    print(f"\n{Fore.GREEN}[✓] Total unique subdomains found: {len(subdomain_list)}{Style.RESET_ALL}")

    if subdomain_list:
        print(f"\n{Fore.CYAN}Sample subdomains:{Style.RESET_ALL}")
        for subdomain in subdomain_list[:20]:
            print(f"{Fore.GREEN}  • {subdomain}{Style.RESET_ALL}")
        if len(subdomain_list) > 20:
            print(f"{Fore.YELLOW}  ... and {len(subdomain_list) - 20} more{Style.RESET_ALL}")

    return subdomain_list


if __name__ == "__main__":
    test_domain = "example.com"
    result = enumerate_subdomains(test_domain, use_brute_force=True)
    print(f"\n{Fore.CYAN}Total found: {len(result)}{Style.RESET_ALL}")
