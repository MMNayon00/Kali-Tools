"""
JS Hidden Document Intelligence Module  (MMN v2)
=================================================
Perform advanced passive reconnaissance by analyzing HTML and JavaScript
resources to discover:
  • Undocumented / hidden API endpoints
  • Hidden backend routes
  • Publicly accessible but non-linked documents (PDF, DOCX, XLSX, JSON …)
  • Sensitive metadata leaked inside JS bundles
  • Outdated front-end libraries

STRICT PASSIVE MODE ONLY – No brute-force, no auth bypass, no fuzzing.
"""

import re
import json
import time
import logging
import threading
import io
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style

# ── Optional PDF reader ──────────────────────────────────────────────────────
try:
    from pypdf import PdfReader as _PdfReader
    _PDF_LIB = "pypdf"
    PDF_READER_AVAILABLE = True
except ImportError:
    try:
        from PyPDF2 import PdfReader as _PdfReader   # type: ignore
        _PDF_LIB = "PyPDF2"
        PDF_READER_AVAILABLE = True
    except ImportError:
        PDF_READER_AVAILABLE = False
        _PdfReader = None                            # type: ignore

# ── Constants ────────────────────────────────────────────────────────────────
MODULE_VERSION = "2.0.0"

DOCUMENT_EXTENSIONS = (
    ".pdf", ".docx", ".doc", ".xlsx", ".xls",
    ".json", ".xml", ".zip", ".tar", ".gz",
    ".backup", ".bak", ".old", ".sql", ".log",
    ".csv", ".ppt", ".pptx",
)

# Regex patterns for JS analysis
_ENDPOINT_PATTERNS: List[Tuple[str, str]] = [
    # REST-style paths
    (r'["\'](\/(api|v\d+|admin|internal|backend|private|secret|'
     r'graphql|ws|wss|swagger|openapi|auth|login|dashboard)'
     r'[\w\-/%.?=&#+]*)["\']',                                "rest_endpoint"),
    # Absolute HTTP(S) URLs embedded literally
    (r'["\`](https?://[^\s"\'\`<>]{8,})["\`]',               "hardcoded_url"),
    # WebSocket endpoints
    (r'["\`](wss?://[^\s"\'\`<>]{4,})["\`]',                  "websocket"),
    # Swagger / OpenAPI references
    (r'["\']([^"\']*(?:swagger|openapi|api[-_]?docs)[^"\']*)["\']', "openapi_ref"),
    # File-path-style document references
    (r'["\']([^"\']*(?:'
     r'\.pdf|\.docx?|\.xlsx?|\.zip|\.backup|\.bak|\.old|\.sql|\.log|\.xml'
     r')[^"\']*)["\']',                                        "document_ref"),
]

# Compiled GraphQL operation detector (separate from URL patterns – captures names, not URLs)
_GRAPHQL_OP_PATTERN = re.compile(
    r'(?:query|mutation|subscription)\s+(\w+)\s*[\({]', re.IGNORECASE
)

# Library fingerprint → (pattern, latest_known_secure)
_LIBRARY_PATTERNS: List[Tuple[str, str, str]] = [
    ("jQuery",     r'jquery[.\-_]?v?([\d.]+(?:\.\d+)?)',         "3.7"),
    ("React",      r'react[.\-_]?v?([\d.]+)',                    "18.0"),
    ("Angular",    r'angular[.\-_]?v?([\d.]+)',                  "17.0"),
    ("Bootstrap",  r'bootstrap[.\-_]?v?([\d.]+)',                "5.3"),
    ("Vue",        r'vue[.\-_]?v?([\d.]+)',                      "3.4"),
    ("Lodash",     r'lodash[.\-_]?v?([\d.]+)',                   "4.17"),
    ("Axios",      r'axios[.\-_]?v?([\d.]+)',                    "1.6"),
    ("Moment.js",  r'moment[.\-_]?v?([\d.]+)',                   "2.29"),
]

# Risk levels
_RISK_LEVELS = ("critical", "high", "medium", "low", "informational")


# ── Logging setup ─────────────────────────────────────────────────────────────
def _setup_audit_logger(target: str) -> logging.Logger:
    """Create a file audit logger that writes to reports/."""
    Path("reports").mkdir(exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w\-]", "_", target)
    log_path = f"reports/js_intel_{safe}_{ts}.log"

    logger = logging.getLogger(f"js_intel.{safe}.{ts}")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        logger.addHandler(fh)
    return logger


# ── HTTP helpers ─────────────────────────────────────────────────────────────
_DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _build_session(rate_limit: float = 0.3, timeout: int = 12) -> requests.Session:
    sess = requests.Session()
    sess.headers.update(_DEFAULT_HEADERS)
    # Store timeout so _safe_get / _safe_head can read it without signature changes
    sess._mmn_timeout = timeout  # type: ignore[attr-defined]
    # Attach a simple rate-limit hook that sleeps before each response
    def _throttle(r, *args, **kwargs):
        time.sleep(rate_limit)
        return r
    sess.hooks["response"].append(_throttle)
    return sess


def _safe_get(session: requests.Session, url: str,
              timeout: int = 12, logger: Optional[logging.Logger] = None
              ) -> Optional[requests.Response]:
    """GET with error handling; returns None on any failure."""
    _timeout = getattr(session, '_mmn_timeout', timeout)
    try:
        resp = session.get(url, timeout=_timeout, allow_redirects=True, verify=False)
        return resp
    except requests.exceptions.Timeout:
        if logger:
            logger.warning(f"TIMEOUT: {url}")
        print(f"{Fore.YELLOW}  [!] Timeout: {url[:80]}{Style.RESET_ALL}")
        return None
    except requests.exceptions.ConnectionError:
        if logger:
            logger.warning(f"CONNECTION_ERROR: {url}")
        return None
    except Exception as e:
        if logger:
            logger.error(f"FETCH_ERROR {url}: {e}")
        return None


def _safe_head(session: requests.Session, url: str,
               timeout: int = 8,
               logger: Optional[logging.Logger] = None
               ) -> Optional[int]:
    """HEAD request; returns HTTP status code or None."""
    _timeout = getattr(session, '_mmn_timeout', timeout)
    try:
        resp = session.head(url, timeout=_timeout, allow_redirects=True, verify=False)
        return resp.status_code
    except Exception:
        return None


# ── Scope enforcement ─────────────────────────────────────────────────────────
def _in_scope(url: str, allowed_domains: Set[str]) -> bool:
    """Return True only if the URL's netloc is within the allowed set."""
    if not allowed_domains:
        return True  # no explicit scope restriction → allow all
    try:
        netloc = urlparse(url).netloc.lower()
        return any(netloc == d or netloc.endswith("." + d) for d in allowed_domains)
    except Exception:
        return False


# ── HTML & JavaScript collection ─────────────────────────────────────────────
def collect_js_resources(
    target_url: str,
    session: requests.Session,
    allowed_domains: Set[str],
    logger: logging.Logger,
) -> Tuple[List[Dict], List[str]]:
    """
    Fetch the target page, extract <script src> references + inline JS.

    Returns:
        (js_files: list of {url, content, source}, inline_scripts: list of str)
    """
    js_files: List[Dict]  = []
    inline_scripts: List[str] = []
    seen_urls: Set[str] = set()
    seen_lock = threading.Lock()  # protect seen_urls across concurrent threads

    print(f"\n{Fore.YELLOW}  [*] Fetching target page: {target_url}{Style.RESET_ALL}")
    resp = _safe_get(session, target_url, logger=logger)
    if not resp or resp.status_code != 200:
        print(f"{Fore.RED}  [!] Could not fetch target page{Style.RESET_ALL}")
        return js_files, inline_scripts

    soup = BeautifulSoup(resp.text, "html.parser")
    base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"

    # ── External <script src=""> ──────────────────────────────────────────
    script_tags = soup.find_all("script", src=True)
    print(f"{Fore.CYAN}  [*] Found {len(script_tags)} external script tags{Style.RESET_ALL}")

    def _fetch_script(tag) -> Optional[Dict]:
        raw_src = tag.get("src", "").strip()
        abs_url = urljoin(base_url, raw_src) if not raw_src.startswith("http") else raw_src
        # Normalise (strip query params for dedup key)
        key = abs_url.split("?")[0]

        with seen_lock:
            if key in seen_urls:
                return None
            seen_urls.add(key)

        # NOTE: we intentionally do NOT scope-check script URLs here.
        # CDN-hosted scripts (cdnjs, jsdelivr, etc.) are public read-only
        # resources – we fetch them for analysis but scope-enforce only
        # the *endpoints/documents* extracted from their content.
        r = _safe_get(session, abs_url, logger=logger)
        if not r or r.status_code != 200:
            return None
        logger.info(f"JS_COLLECTED: {abs_url}")
        return {"url": abs_url, "content": r.text, "source": "external_script", "size": len(r.text)}

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_fetch_script, tag): tag for tag in script_tags}
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                js_files.append(result)

    # ── Inline <script> blocks ────────────────────────────────────────────
    for tag in soup.find_all("script", src=False):
        content = tag.string or ""
        if content.strip():
            inline_scripts.append(content.strip())

    print(f"{Fore.GREEN}  [✓] Collected {len(js_files)} JS files, "
          f"{len(inline_scripts)} inline blocks{Style.RESET_ALL}")
    logger.info(f"COLLECTION_DONE: js_files={len(js_files)}, inline={len(inline_scripts)}")
    return js_files, inline_scripts


# ── JavaScript intelligence extraction ──────────────────────────────────────
def extract_intelligence_from_js(
    js_files: List[Dict],
    inline_scripts: List[str],
    base_url: str,
    allowed_domains: Set[str],
    logger: logging.Logger,
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Extract endpoints, document references, and library versions from JS.

    Returns:
        (endpoints, document_refs, outdated_libraries)
    """
    endpoints:    List[Dict] = []
    doc_refs:     List[Dict] = []
    libraries:    List[Dict] = []

    endpoint_seen: Set[str] = set()
    doc_seen:      Set[str] = set()
    lib_seen:      Set[str] = set()

    all_sources = (
        [(js["url"], js["content"]) for js in js_files] +
        [("inline", block) for block in inline_scripts]
    )

    for source_url, content in all_sources:
        if not content:
            continue

        # ── GraphQL operation detection (metadata) ────────────────────────
        # Detect operation names to confirm GraphQL usage, then add the
        # canonical /graphql endpoint once per source if ops are found.
        gql_ops = _GRAPHQL_OP_PATTERN.findall(content)
        if gql_ops:
            gql_url = base_url.rstrip("/") + "/graphql"
            gql_key = gql_url.lower()
            if gql_key not in endpoint_seen and _in_scope(gql_url, allowed_domains):
                endpoint_seen.add(gql_key)
                endpoints.append({
                    "url":    gql_url,
                    "type":   "graphql_endpoint",
                    "source": source_url,
                    "risk":   "medium",
                    "meta":   f"operations detected: {', '.join(gql_ops[:5])}",
                })
                logger.info(f"GRAPHQL: {gql_url} | ops={gql_ops[:5]}")

        # ── Endpoint / route extraction ───────────────────────────────────
        for pattern, endpoint_type in _ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                raw = match.group(1)
                if not raw or len(raw) < 3:
                    continue

                # Resolve relative paths against the base url
                if raw.startswith("/"):
                    abs_url = base_url.rstrip("/") + raw
                elif raw.startswith("http"):
                    abs_url = raw
                else:
                    continue  # relative paths without leading slash – skip

                key = abs_url.split("?")[0].lower()
                if key in endpoint_seen:
                    continue
                if not _in_scope(abs_url, allowed_domains):
                    logger.info(f"SKIPPED_OOS_ENDPOINT: {abs_url}")
                    continue
                endpoint_seen.add(key)

                # Document references go to a separate bucket
                lk = key.lower()
                if any(lk.endswith(ext) for ext in DOCUMENT_EXTENSIONS):
                    if lk not in doc_seen:
                        doc_seen.add(lk)
                        doc_refs.append({
                            "url":    abs_url,
                            "type":   endpoint_type,
                            "source": source_url,
                            "status": None,
                            "risk":   _classify_document_risk(abs_url),
                        })
                        logger.info(f"DOC_REF: {abs_url}")
                    continue

                risk  = _classify_endpoint_risk(abs_url, endpoint_type)
                endpoints.append({
                    "url":    abs_url,
                    "type":   endpoint_type,
                    "source": source_url,
                    "risk":   risk,
                })
                logger.info(f"ENDPOINT: [{endpoint_type}] {abs_url}")

        # ── Library version fingerprinting ────────────────────────────────
        for lib_name, pattern, latest in _LIBRARY_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                detected_ver = m.group(1) if m.lastindex else "unknown"
                lib_key = f"{lib_name}:{detected_ver}"
                if lib_key in lib_seen:
                    continue
                lib_seen.add(lib_key)
                outdated = _is_version_outdated(detected_ver, latest)
                libraries.append({
                    "library":     lib_name,
                    "version":     detected_ver,
                    "latest":      latest,
                    "outdated":    outdated,
                    "source":      source_url,
                    "risk":        "medium" if outdated else "informational",
                })
                logger.info(f"LIBRARY: {lib_name} v{detected_ver} "
                            f"({'outdated' if outdated else 'current'})")

    print(f"{Fore.GREEN}  [✓] Extracted {len(endpoints)} endpoints, "
          f"{len(doc_refs)} document refs, "
          f"{len(libraries)} library versions{Style.RESET_ALL}")
    return endpoints, doc_refs, libraries


# ── Document verification (HEAD only) ────────────────────────────────────────
def verify_documents(
    doc_refs: List[Dict],
    session: requests.Session,
    logger: logging.Logger,
) -> List[Dict]:
    """
    Verify each document reference is truly publicly accessible via HEAD.
    Only keep HTTP 200 responses.
    """
    confirmed: List[Dict] = []

    def _check(doc: Dict) -> Optional[Dict]:
        status = _safe_head(session, doc["url"], logger=logger)
        if status == 200:
            doc_copy = dict(doc)
            doc_copy["status"] = 200
            logger.info(f"DOC_CONFIRMED: {doc['url']}")
            return doc_copy
        logger.info(f"DOC_INACCESSIBLE [{status}]: {doc['url']}")
        return None

    print(f"\n{Fore.YELLOW}  [*] Verifying {len(doc_refs)} document references...{Style.RESET_ALL}")
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_check, d) for d in doc_refs]
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                confirmed.append(result)

    print(f"{Fore.GREEN}  [✓] Confirmed {len(confirmed)} publicly accessible documents{Style.RESET_ALL}")
    return confirmed


# ── PDF metadata extraction ───────────────────────────────────────────────────
def extract_pdf_metadata(
    doc_url: str,
    session: requests.Session,
    logger: logging.Logger,
) -> Optional[Dict]:
    """
    Download a confirmed-public PDF and extract metadata passively.
    """
    if not PDF_READER_AVAILABLE:
        return None
    if not doc_url.lower().endswith(".pdf"):
        return None

    print(f"{Fore.YELLOW}    [*] Extracting PDF metadata: {doc_url[:70]}{Style.RESET_ALL}")
    resp = _safe_get(session, doc_url, logger=logger)
    if not resp or resp.status_code != 200:
        return None

    try:
        reader = _PdfReader(io.BytesIO(resp.content))
        raw_meta = reader.metadata or {}

        # Normalise keys (strip leading '/')
        meta: Dict = {}
        for k, v in raw_meta.items():
            clean_key = k.lstrip("/")
            meta[clean_key] = str(v) if v is not None else ""

        # Extract embedded URLs from metadata fields
        embedded_urls: List[str] = []
        for v in meta.values():
            found = re.findall(r'https?://[^\s"\'<>]+', v)
            embedded_urls.extend(found)

        result = {
            "url":           doc_url,
            "author":        meta.get("Author", ""),
            "creator":       meta.get("Creator", ""),
            "producer":      meta.get("Producer", ""),
            "creation_date": meta.get("CreationDate", ""),
            "mod_date":      meta.get("ModDate", ""),
            "title":         meta.get("Title", ""),
            "subject":       meta.get("Subject", ""),
            "embedded_urls": embedded_urls,
            "pages":         len(reader.pages),
            "risk":          _classify_pdf_metadata_risk(meta, embedded_urls),
            "raw_metadata":  meta,
        }
        logger.info(f"PDF_METADATA: {doc_url} | author={result['author']}")
        return result
    except Exception as e:
        logger.warning(f"PDF_PARSE_ERROR {doc_url}: {e}")
        return None


# ── Risk classification helpers ───────────────────────────────────────────────
def _classify_endpoint_risk(url: str, ep_type: str) -> str:
    lurl = url.lower()
    # Critical signals
    if any(kw in lurl for kw in ("/admin", "/internal", "/private", "/secret", "/debug")):
        return "high"
    # Medium signals
    if any(kw in lurl for kw in ("/api/v", "/graphql", "/openapi", "/swagger")):
        return "medium"
    if ep_type in ("websocket", "openapi_ref"):
        return "medium"
    if ep_type == "hardcoded_url":
        return "low"
    return "informational"


def _classify_document_risk(url: str) -> str:
    lurl = url.lower()
    sensitive_keywords = (
        "secret", "password", "passwd", "credential", "confidential",
        "private", "internal", "backup", "dump", "export", "database", "db_",
        "admin", "invoice", "contract", "salary", "payroll",
    )
    if any(kw in lurl for kw in sensitive_keywords):
        return "high"
    if lurl.endswith((".backup", ".bak", ".old", ".sql")):
        return "high"
    if lurl.endswith((".zip", ".tar", ".gz")):
        return "medium"
    if lurl.endswith((".pdf", ".docx", ".xlsx")):
        return "low"
    return "low"


def _classify_pdf_metadata_risk(meta: Dict, embedded_urls: List[str]) -> str:
    """Classify risk based on what the PDF metadata reveals."""
    sensitive_vals = " ".join(meta.values()).lower()
    critical_signals = ("password", "secret", "token", "api_key", "bearer", "auth")
    high_signals     = ("internal", "confidential", "private", "vpn", "intranet")

    if any(kw in sensitive_vals for kw in critical_signals):
        return "critical"
    if any(kw in sensitive_vals for kw in high_signals):
        return "high"
    if embedded_urls:
        return "medium"
    if meta.get("Author") or meta.get("Creator"):
        return "medium"   # internal system naming disclosure
    return "informational"


def _is_version_outdated(detected: str, latest: str) -> bool:
    """Simple major.minor comparison; returns True if detected < latest."""
    try:
        d_parts = [int(x) for x in detected.split(".")[:2]]
        l_parts = [int(x) for x in latest.split(".")[:2]]
        return d_parts < l_parts
    except ValueError:
        return False


# ── Risk summary ──────────────────────────────────────────────────────────────
def _build_risk_summary(
    endpoints: List[Dict],
    documents: List[Dict],
    pdf_meta:  List[Dict],
    libraries: List[Dict],
) -> Dict[str, int]:
    counts = {level: 0 for level in _RISK_LEVELS}
    for item in endpoints + documents + pdf_meta + libraries:
        risk = item.get("risk", "informational")
        if risk in counts:
            counts[risk] += 1
    return counts


def _confidence_score(
    js_count:  int,
    ep_count:  int,
    doc_count: int,
    lib_count: int,
) -> int:
    """
    Heuristic confidence score (0-100).
    Higher counts of collected resources → higher confidence in completeness.
    """
    score = 0
    score += min(js_count  * 5,  30)   # up to 30 pts for JS coverage
    score += min(ep_count  * 2,  30)   # up to 30 pts for endpoint breadth
    score += min(doc_count * 5,  20)   # up to 20 pts for document finds
    score += min(lib_count * 5,  20)   # up to 20 pts for library coverage
    return min(score, 100)


# ── CLI output ────────────────────────────────────────────────────────────────
_RISK_COLOR = {
    "critical":      Fore.RED,
    "high":          Fore.RED,
    "medium":        Fore.YELLOW,
    "low":           Fore.CYAN,
    "informational": Fore.WHITE,
}


def _print_cli_summary(result: Dict) -> None:
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'JS HIDDEN DOCUMENT INTELLIGENCE – RESULTS':^70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")

    rs  = result["risk_summary"]
    cs  = result["confidence_score"]
    eps = result["endpoints_discovered"]
    docs = result["hidden_documents_found"]
    libs = result["outdated_libraries"]
    pdfs = result["pdf_metadata_extracted"]

    print(f"\n{Fore.WHITE}  Target          : {result.get('target', 'N/A')}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  JS Files         : {len(result['js_files_collected'])}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}  Confidence Score : {cs}/100{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}  ── Risk Summary ──────────────────────────────{Style.RESET_ALL}")
    for level in _RISK_LEVELS:
        count = rs.get(level, 0)
        if count:
            col = _RISK_COLOR.get(level, Fore.WHITE)
            print(f"{col}  {level.upper():>15}: {count}{Style.RESET_ALL}")

    if eps:
        print(f"\n{Fore.CYAN}  ── Endpoints Discovered ({len(eps)}) ──────────────{Style.RESET_ALL}")
        for ep in eps[:15]:
            col = _RISK_COLOR.get(ep["risk"], Fore.WHITE)
            print(f"{col}  [{ep['risk'].upper():<14}] [{ep['type']:<18}] {ep['url']}{Style.RESET_ALL}")
        if len(eps) > 15:
            print(f"{Fore.YELLOW}  ... and {len(eps) - 15} more endpoints{Style.RESET_ALL}")

    if docs:
        print(f"\n{Fore.CYAN}  ── Hidden Documents Found ({len(docs)}) ───────────{Style.RESET_ALL}")
        for doc in docs:
            col = _RISK_COLOR.get(doc["risk"], Fore.WHITE)
            print(f"{col}  [{doc['risk'].upper():<14}] [HTTP {doc.get('status', '?')}] {doc['url']}{Style.RESET_ALL}")

    if pdfs:
        print(f"\n{Fore.CYAN}  ── PDF Metadata Extracted ({len(pdfs)}) ────────────{Style.RESET_ALL}")
        for p in pdfs:
            col = _RISK_COLOR.get(p["risk"], Fore.WHITE)
            print(f"{col}  [{p['risk'].upper():<14}] {p['url'][:60]}{Style.RESET_ALL}")
            if p.get("author"):
                print(f"{Fore.WHITE}    Author : {p['author']}{Style.RESET_ALL}")
            if p.get("creator"):
                print(f"{Fore.WHITE}    Creator: {p['creator']}{Style.RESET_ALL}")
            if p.get("embedded_urls"):
                print(f"{Fore.YELLOW}    Embedded URLs: {len(p['embedded_urls'])} found{Style.RESET_ALL}")

    if libs:
        print(f"\n{Fore.CYAN}  ── Outdated Libraries ({len(libs)}) ────────────────{Style.RESET_ALL}")
        for lib in libs:
            col = _RISK_COLOR.get(lib["risk"], Fore.WHITE)
            print(f"{col}  [{lib['risk'].upper():<14}] {lib['library']} v{lib['version']} "
                  f"(latest: {lib['latest']}){Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")


# ── Report persistence ────────────────────────────────────────────────────────
def _save_json_report(result: Dict) -> str:
    Path("reports").mkdir(exist_ok=True)
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^\w\-]", "_", result.get("target", "unknown"))
    path = f"reports/js_intel_{safe}_{ts}.json"
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"{Fore.GREEN}  [✓] JSON report saved: {path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}  [!] Could not save JSON report: {e}{Style.RESET_ALL}")
    return path


def _generate_html_section(result: Dict) -> str:
    """Return an HTML string suitable for embedding in the main report."""
    rs   = result.get("risk_summary", {})
    eps  = result.get("endpoints_discovered", [])
    docs = result.get("hidden_documents_found", [])
    libs = result.get("outdated_libraries", [])

    _color_map = {
        "critical": "#ff4757", "high": "#ff6348",
        "medium": "#ffa502",   "low": "#1e90ff",
        "informational": "#cccccc",
    }

    rows_ep = ""
    for ep in eps[:30]:
        color = _color_map.get(ep["risk"], "#ccc")
        rows_ep += (f"<tr>"
                    f"<td style='color:{color}'>{ep['risk'].upper()}</td>"
                    f"<td>{ep['type']}</td>"
                    f"<td style='word-break:break-all'>{ep['url']}</td>"
                    f"</tr>\n")

    rows_doc = ""
    for doc in docs:
        color = _color_map.get(doc["risk"], "#ccc")
        rows_doc += (f"<tr>"
                     f"<td style='color:{color}'>{doc['risk'].upper()}</td>"
                     f"<td>HTTP {doc.get('status','?')}</td>"
                     f"<td style='word-break:break-all'>{doc['url']}</td>"
                     f"</tr>\n")

    rows_lib = ""
    for lib in libs:
        color = _color_map.get(lib["risk"], "#ccc")
        rows_lib += (f"<tr><td style='color:{color}'>{lib['library']}</td>"
                     f"<td>{lib['version']}</td>"
                     f"<td>{lib['latest']}</td></tr>\n")

    severe = sum(rs.get(x, 0) for x in ("critical", "high"))
    exec_para = (
        f"JS Hidden Document Intelligence identified <strong>{len(eps)}</strong> "
        f"undocumented endpoints and <strong>{len(docs)}</strong> publicly accessible "
        f"hidden documents on <em>{result.get('target', 'the target')}</em>. "
        f"<strong>{severe}</strong> findings are classified as Critical or High severity, "
        f"requiring immediate review. Confidence score: "
        f"<strong>{result.get('confidence_score', 0)}/100</strong>."
    )

    html = f"""
<div class="section" id="js-intel">
  <h2>JS Hidden Document Intelligence</h2>

  <h3>Executive Summary</h3>
  <p style="color:#eee">{exec_para}</p>

  <h3>Risk Overview</h3>
  <table>
    <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Informational</th></tr>
    <tr>
      <td style="color:#ff4757">{rs.get('critical',0)}</td>
      <td style="color:#ff6348">{rs.get('high',0)}</td>
      <td style="color:#ffa502">{rs.get('medium',0)}</td>
      <td style="color:#1e90ff">{rs.get('low',0)}</td>
      <td>{rs.get('informational',0)}</td>
    </tr>
  </table>

  <h3>Discovered Endpoints ({len(eps)})</h3>
  <table>
    <tr><th>Risk</th><th>Type</th><th>URL</th></tr>
    {rows_ep}
  </table>

  <h3>Hidden Documents ({len(docs)})</h3>
  <table>
    <tr><th>Risk</th><th>Status</th><th>URL</th></tr>
    {rows_doc}
  </table>

  <h3>Outdated Libraries ({len(libs)})</h3>
  <table>
    <tr><th>Library</th><th>Detected</th><th>Latest</th></tr>
    {rows_lib}
  </table>
</div>
"""
    return html


# ── Main entry-point ──────────────────────────────────────────────────────────
def run_js_document_intelligence(
    target: str,
    scope_domains: Optional[List[str]] = None,
    rate_limit: float = 0.3,
    request_timeout: int = 12,
    extract_pdf_meta: bool = True,
    save_report: bool = True,
) -> Dict:
    """
    Full JS Hidden Document Intelligence scan.

    Args:
        target:          Domain or URL of the authorised target.
        scope_domains:   Optional whitelist of in-scope domains.
        rate_limit:      Seconds to wait between HTTP requests (default 0.3).
        request_timeout: Per-request timeout in seconds (default 12).
        extract_pdf_meta: Whether to download and parse PDF metadata (default True).
        save_report:     Whether to persist a JSON report to reports/ (default True).

    Returns:
        Structured result dictionary matching the module's JSON schema.
    """
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'JS HIDDEN DOCUMENT INTELLIGENCE  v' + MODULE_VERSION:^70}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Target : {target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Mode   : Passive-only (no brute-force, no auth bypass){Style.RESET_ALL}\n")

    # ── Normalise target to URL ───────────────────────────────────────────
    target_clean = target.strip().lower()
    if not target_clean.startswith("http"):
        target_url = f"https://{target_clean}"
    else:
        target_url = target_clean

    parsed      = urlparse(target_url)
    base_url    = f"{parsed.scheme}://{parsed.netloc}"
    # Use removeprefix to avoid lstrip character-stripping bug
    root_domain = parsed.netloc.removeprefix("www.")

    # Scope: add root domain automatically
    allowed_set: Set[str] = {root_domain}
    if scope_domains:
        allowed_set.update(d.removeprefix("www.") for d in scope_domains)

    logger  = _setup_audit_logger(root_domain)
    session = _build_session(rate_limit, timeout=request_timeout)

    result: Dict = {
        "target":                  root_domain,
        "target_url":              target_url,
        "scan_timestamp":          datetime.now().isoformat(),
        "module_version":          MODULE_VERSION,
        "js_files_collected":      [],
        "endpoints_discovered":    [],
        "hidden_documents_found":  [],
        "pdf_metadata_extracted":  [],
        "outdated_libraries":      [],
        "risk_summary":            {level: 0 for level in _RISK_LEVELS},
        "confidence_score":        0,
    }

    try:
        # Step 1 – Collect JS resources ─────────────────────────────────
        print(f"{Fore.CYAN}[*] Step 1/5 – Collecting JS Resources{Style.RESET_ALL}")
        js_files, inline_scripts = collect_js_resources(
            target_url, session, allowed_set, logger
        )
        result["js_files_collected"] = [
            {"url": f["url"], "size": f["size"], "source": f["source"]}
            for f in js_files
        ]

        # Step 2 – Intelligence extraction ──────────────────────────────
        print(f"\n{Fore.CYAN}[*] Step 2/5 – Extracting Intelligence from JS{Style.RESET_ALL}")
        endpoints, doc_refs, libraries = extract_intelligence_from_js(
            js_files, inline_scripts, base_url, allowed_set, logger
        )
        result["endpoints_discovered"] = endpoints
        result["outdated_libraries"]   = [lib for lib in libraries if lib["outdated"]]

        # Step 3 – Document verification ────────────────────────────────
        print(f"\n{Fore.CYAN}[*] Step 3/5 – Verifying Hidden Documents (HEAD only){Style.RESET_ALL}")
        confirmed_docs = verify_documents(doc_refs, session, logger)
        result["hidden_documents_found"] = confirmed_docs

        # Step 4 – PDF metadata extraction ──────────────────────────────
        print(f"\n{Fore.CYAN}[*] Step 4/5 – PDF Metadata Analysis{Style.RESET_ALL}")
        if not PDF_READER_AVAILABLE:
            print(f"{Fore.YELLOW}  [!] pypdf/PyPDF2 not installed – PDF metadata extraction skipped{Style.RESET_ALL}")
            print(f"{Fore.CYAN}  [*] Install with: pip install pypdf{Style.RESET_ALL}")
        elif not extract_pdf_meta:
            print(f"{Fore.CYAN}  [i] PDF metadata extraction disabled by caller{Style.RESET_ALL}")
        else:
            pdf_meta_results = []
            pdf_docs = [d for d in confirmed_docs if d["url"].lower().endswith(".pdf")]
            for doc in pdf_docs:
                meta = extract_pdf_metadata(doc["url"], session, logger)
                if meta:
                    pdf_meta_results.append(meta)
            result["pdf_metadata_extracted"] = pdf_meta_results
            print(f"{Fore.GREEN}  [✓] PDF metadata extracted from "
                  f"{len(pdf_meta_results)} files{Style.RESET_ALL}")

        # Step 5 – Scoring ───────────────────────────────────────────────
        print(f"\n{Fore.CYAN}[*] Step 5/5 – Risk Scoring{Style.RESET_ALL}")
        result["risk_summary"] = _build_risk_summary(
            result["endpoints_discovered"],
            result["hidden_documents_found"],
            result["pdf_metadata_extracted"],
            result["outdated_libraries"],
        )
        result["confidence_score"] = _confidence_score(
            len(js_files),
            len(endpoints),
            len(confirmed_docs),
            len(libraries),
        )

        # ── CLI summary ──────────────────────────────────────────────────
        _print_cli_summary(result)

        # ── Save reports ─────────────────────────────────────────────────
        if save_report:
            _save_json_report(result)

        # Attach HTML section for report_generator integration
        result["_html_section"] = _generate_html_section(result)

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] JS Intelligence scan interrupted{Style.RESET_ALL}")
    except Exception as exc:
        print(f"\n{Fore.RED}[!] Unexpected error: {exc}{Style.RESET_ALL}")
        logger.error(f"FATAL: {exc}", exc_info=True)

    return result


# ── Module self-test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    _target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result  = run_js_document_intelligence(_target)
    print(f"\n{Fore.CYAN}Scan complete – confidence {result['confidence_score']}/100{Style.RESET_ALL}")
