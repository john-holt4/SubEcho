#!/usr/bin/env python3
"""
SubEcho
===========
A cross-platform subdomain enumeration and WAF detection tool that fetches subdomains
from multiple data sources (crt.sh, SecurityTrails, RapidDNS, WebArchive, AlienVault OTX, 
HackerTarget, urlscan.io) and attempts to detect if a domain is behind a WAF.

Usage:
------
  python subecho.py -d example.com
  python subecho.py -d example.com -k YOUR_SECURITYTRAILS_API_KEY
  python subecho.py -d example.com -v   # verbose mode

Features:
----------
  • Online/Offline determination via DNS resolution
  • Real-time WAF detection for online subdomains
  • Results saved to a timestamped .txt file
  • Beautiful Rich-based console output

Author:
-------
  John Holt
"""

import argparse
import asyncio
import logging
import os
import re
import socket
import ssl
from datetime import datetime
from io import StringIO
from typing import Optional, List, Set, Tuple, Dict, Any

import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich.traceback import install

# Install rich traceback for enhanced exception formatting
install(show_locals=True)

# -------------------------------------------------------------------------------
# Constants
# -------------------------------------------------------------------------------
VERSION = "1.1"
OUTPUT_DIR = "output"
MAX_RETRIES = 3
DOMAIN_REGEX = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$'

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Akamai": [
        "Akamai-Ghost",
        "X-Akamai-Transformed",
        "X-Akamai-Edgescape",
        "akamaierror",
    ],
    "Alibaba Cloud": [
        "Server: Alibaba Security",
        "X-Server: Jetty(Alibaba)",
    ],
    "AlienVault OSSIM": [
        "alienvault",
    ],
    "Astra Security": [
        "x-astra-cache",
        "astrawebprotection",
    ],
    "AWS WAF": [
        "AWSWAF",
        "AWSALB",
        "AWSELBCORS",
        "x-amz-server",
    ],
    "Barracuda": [
        "Barracuda",
        "server: Barracuda",
        "WAF: Barracuda",
        "barra_counter_session",
    ],
    "BigIP (F5)": [
        "X-WA-Info",
        "X-Cnection",
        "Set-Cookie: BIGipServer",
        "BIGipServer",
        "F5_ST",
    ],
    "BitNinja": [
        "bitninja-site-protection",
        "bitninja.io",
    ],
    "BlazingFast": [
        "blazing_fast_server",
        "__bfuid",
    ],
    "Cloudflare": [
        "cf-ray",
        "cf-cache-status",
        "CF-Connecting-IP",
        "__cfduid",
        "__cflb",
        "Server: cloudflare",
    ],
    "CloudFront": [
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "Server: CloudFront",
        "Via: CloudFront",
    ],
    "DDoS-Guard": [
        "Server: ddos-guard",
        "DDOS-GUARD",
    ],
    "EdgeCast": [
        "Server: ECD (",
        "Server: ECS (",
    ],
    "FortiWeb": [
        "Server: FortiWeb",
    ],
    "GoDaddy Website Protection": [
        "gd-warden",
    ],
    "Incapsula (Imperva)": [
        "Incapsula",
        "X-CDN: Incapsula",
        "visid_incap_",
        "Incap_ses",
        "X-Iinfo",
    ],
    "NAXSI": [
        "naxsi/waf",
    ],
    "Netlify": [
        "server: Netlify",
    ],
    "Oracle Cloud (OCI)": [
        "ORCL-Application-Protection",
    ],
    "Palo Alto Networks": [
        "X-PaloAlto",
    ],
    "Profense": [
        "Server: PD-OR",
        "Profense",
    ],
    "Reblaze": [
        "X-Reblaze-Proxy",
        "rbzid",
        "rbzerr",
        "rbz",
    ],
    "SiteLock TrueShield": [
        "sitelock-shield",
        "X-Sitelock-Request-Id",
    ],
    "StackPath": [
        "Server: StackPath",
    ],
    "Sucuri": [
        "x-sucuri-id",
        "x-sucuri-block",
        "Server: Sucuri/Cloudproxy",
    ],
    "URLScan.io (Phishing Shield)": [
        "x-urlscan-block",
    ],
    "Varnish": [
        "X-Varnish",
        "Via: varnish",
    ],
    "Wallarm": [
        "wallarm",
        "X-Wallarm-Protection",
    ],
    "WebARX": [
        "x-webarx",
        "x-waf-status",
    ],
    "Wordfence": [
        "X-Wordfence-Blocked",
        "wfwaf-authcookie-",
    ],
    "Wix": [
        "x-wix-request-id",
    ],
    "Framer": [
        "server: framer",
        "x-framer-request-id",
    ],
    "Squarespace": [
        "server: squarespace",
        "x-squarespace-request-id",
    ],
    "Shopify": [
        "x-shopify-stage",
        "x-shopify-as",
        "server: cloudflare",
    ],
    "Radware": [
        "Server: Radware",
        "X-RW-",
    ],
    "Citrix NetScaler": [
        "NSC_",
        "X-NITRO",
        "server: Citrix",
    ],
    "Imperva SecureSphere": [
        "SecureSphere",
        "X-Iinfo",
    ],
    "Distil Networks": [
        "Server: Distil",
        "X-Distil",
    ],
    "Kemp Technologies": [
        "KempLoadMaster",
    ],
    "F5 ASM": [
        "BIG-IP",
        "X-F5-",
    ],
    "ModSecurity": [
        "Mod_Security",
        "ModSecurity",
    ],
}

# -------------------------------------------------------------------------------
# Global Instances
# -------------------------------------------------------------------------------
console = Console()
log_stream = StringIO()

# -------------------------------------------------------------------------------
# Logging Configuration
# -------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(log_stream)]
)
logger = logging.getLogger(__name__)

# -------------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------------
def human_friendly_error(msg: str) -> str:
    """Translate raw error messages into human-friendly messages."""
    if "SSLV3_ALERT_HANDSHAKE_FAILURE" in msg:
        return ("SSL handshake failure while connecting. This might be due to outdated SSL/TLS protocols "
                "or server misconfiguration.")
    if "The specified network name is no longer available" in msg:
        return "Network error: The specified network name is no longer available."
    return msg

class SafeGetContext:
    """
    Asynchronous context manager for performing robust HTTP GET requests with retries.
    """
    def __init__(self, session: aiohttp.ClientSession, url: str, headers: Optional[Dict[str, str]],
                 timeout: int, verbose: bool, ssl_context: Optional[ssl.SSLContext] = None) -> None:
        self.session = session
        self.url = url
        self.headers = headers
        self.timeout = timeout
        self.verbose = verbose
        self.ssl_context = ssl_context
        self.response: Optional[aiohttp.ClientResponse] = None

    async def __aenter__(self) -> aiohttp.ClientResponse:
        for attempt in range(MAX_RETRIES):
            try:
                self.response = await self.session.get(
                    self.url,
                    headers=self.headers,
                    timeout=self.timeout,
                    ssl=self.ssl_context
                )
                if self.response.status == 404:
                    return self.response
                self.response.raise_for_status()
                return self.response

            except aiohttp.ClientResponseError as e:
                if attempt < MAX_RETRIES - 1:
                    if self.verbose and e.status not in [403, 429, 404]:
                        friendly_msg = human_friendly_error(str(e))
                        logger.warning(f"Attempt {attempt+1} failed for {self.url}: {friendly_msg} Retrying...")
                    await asyncio.sleep(2 ** attempt)
                else:
                    if self.verbose and e.status not in [403, 429, 404]:
                        logger.error(f"All retries failed for {self.url}: {human_friendly_error(str(e))}")
                    raise

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempt < MAX_RETRIES - 1:
                    if self.verbose:
                        friendly_msg = human_friendly_error(str(e))
                        logger.warning(f"Attempt {attempt+1} failed for {self.url}: {friendly_msg} Retrying...")
                    await asyncio.sleep(2 ** attempt)
                else:
                    if self.verbose:
                        logger.error(f"All retries failed for {self.url}: {human_friendly_error(str(e))}")
                    raise

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        if self.response is not None:
            self.response.close()

def safe_get(session: aiohttp.ClientSession, url: str, headers: Optional[Dict[str, str]] = None,
             timeout: int = 10, verbose: bool = False, verify_ssl: bool = False) -> SafeGetContext:
    """
    Factory function to create a SafeGetContext with proper SSL settings.
    """
    ssl_context = None
    if not verify_ssl:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    return SafeGetContext(session, url, headers, timeout, verbose, ssl_context)

def validate_domain_format(domain: str) -> str:
    """Validate the domain format using regex."""
    if not re.match(DOMAIN_REGEX, domain):
        raise argparse.ArgumentTypeError(f"Invalid domain format: {domain}")
    return domain

def is_valid_subdomain(subdomain: str) -> bool:
    """Check if a string is a valid subdomain."""
    return re.match(DOMAIN_REGEX, subdomain) is not None

def parse_subdomains(data: List[Dict[str, Any]]) -> List[str]:
    """
    Parse and extract subdomains from JSON data returned by crt.sh.
    """
    results = set()
    for entry in data:
        if 'name_value' in entry:
            for name in entry['name_value'].split(','):
                candidate = name.strip()
                if candidate.startswith('*') or candidate.startswith('.'):
                    continue
                if is_valid_subdomain(candidate):
                    results.add(candidate)
    return sorted(results)

async def display_banner() -> None:
    """Display the ASCII art banner using Rich."""
    ascii_art = r"""
  ██████  █    ██  ▄▄▄▄   ▓█████  ▄████▄   ██░ ██  ▒█████  
▒██    ▒  ██  ▓██▒▓█████▄ ▓█   ▀ ▒██▀ ▀█  ▓██░ ██▒▒██▒  ██▒
░ ▓██▄   ▓██  ▒██░▒██▒ ▄██▒███   ▒▓█    ▄ ▒██▀▀██░▒██░  ██▒
  ▒   ██▒▓▓█  ░██░▒██░█▀  ▒▓█  ▄ ▒▓▓▄ ▄██▒░▓█ ░██ ▒██   ██░
▒██████▒▒▒▒█████▓ ░▓█  ▀█▓░▒████▒▒ ▓███▀ ░░▓█▒░██▓░ ████▓▒░
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░▒▓███▀▒░░ ▒░ ░░ ░▒ ▒  ░ ▒ ░░▒░▒░ ▒░▒░▒░ 
░ ░▒  ░ ░░░▒░ ░ ░ ▒░▒   ░  ░ ░  ░  ░  ▒    ▒ ░▒░ ░  ░ ▒ ▒░ 
░  ░  ░   ░░░ ░ ░  ░    ░    ░   ░         ░  ░░ ░░ ░ ░ ▒  
      ░     ░      ░         ░  ░░ ░       ░  ─  ░ ░  
                        ░        ░                         
"""
    panel = Panel(
        Text(ascii_art, style="red", justify="center"),
        title=f"[bright_magenta]Version {VERSION}[/]",
        subtitle="[bold white]Created by John Holt[/]",
        border_style="bright_magenta",
        padding=0
    )
    console.print(panel)
    console.print()

# -------------------------------------------------------------------------------
# Subdomain Fetcher Functions
# -------------------------------------------------------------------------------
async def fetch_crtsh_subdomains(session: aiohttp.ClientSession, domain: str,
                                 verbose: bool = False) -> List[str]:
    """Fetch subdomains from crt.sh."""
    urls = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.%.%.{domain}&output=json",
    ]
    all_subs: Set[str] = set()
    for url in urls:
        try:
            async with safe_get(session, url, timeout=10, verbose=verbose) as response:
                data = await response.json()
                all_subs.update(parse_subdomains(data))
        except Exception as e:
            if verbose:
                logger.error(f"crt.sh fetch failed for {url}: {e}")
    if verbose:
        logger.info(f"Fetched {len(all_subs)} subdomains from crt.sh.")
    return sorted(all_subs)

async def fetch_securitytrails_subdomains(session: aiohttp.ClientSession, domain: str,
                                          api_key: Optional[str], verbose: bool = False) -> List[str]:
    """Fetch subdomains from SecurityTrails API if API key is provided."""
    if not api_key:
        if verbose:
            logger.warning("SecurityTrails API key missing. Skipping...")
        return []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {'accept': "application/json", 'apikey': api_key}
    try:
        async with safe_get(session, url, headers=headers, timeout=10, verbose=verbose) as response:
            data = await response.json()
            subs = data.get('subdomains', [])
            if verbose:
                logger.info(f"Fetched {len(subs)} subdomains from SecurityTrails API.")
    except Exception as e:
        if verbose:
            logger.error(f"SecurityTrails fetch failed: {e}")
        subs = []
    return [f"{s}.{domain}" for s in subs]

async def fetch_rapiddns_subdomains(session: aiohttp.ClientSession, domain: str,
                                    verbose: bool = False) -> List[str]:
    """Fetch subdomains from RapidDNS."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    headers = {'User-Agent': 'Mozilla/5.0'}
    subs: Set[str] = set()
    try:
        async with safe_get(session, url, headers=headers, timeout=10, verbose=verbose) as response:
            html = await response.text()
            found = re.findall(rf"(?:\b|\.)[A-Za-z0-9-]+\.{re.escape(domain)}", html)
            subs.update(found)
            if verbose:
                logger.info(f"Fetched {len(subs)} subdomains from RapidDNS.")
    except Exception as e:
        if verbose:
            logger.error(f"RapidDNS fetch failed: {e}")
    return sorted(subs)

async def fetch_webarchive_subdomains(session: aiohttp.ClientSession, domain: str,
                                      verbose: bool = False) -> List[str]:
    """Fetch subdomains from the Web Archive."""
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    subs: Set[str] = set()
    try:
        async with safe_get(session, url, timeout=10, verbose=verbose) as response:
            text_data = await response.text()
            for line in text_data.splitlines():
                match = re.search(rf"(?:\b|\.)[A-Za-z0-9-]+\.{re.escape(domain)}", line)
                if match:
                    subs.add(match.group(0))
            if verbose:
                logger.info(f"Fetched {len(subs)} subdomains from Web Archive.")
    except Exception as e:
        if verbose:
            logger.error(f"Web Archive fetch failed: {e}")
    return sorted(subs)

async def fetch_alienvault_subdomains(session: aiohttp.ClientSession, domain: str,
                                      verbose: bool = False) -> List[str]:
    """Fetch subdomains from AlienVault OTX."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subs: Set[str] = set()
    try:
        async with safe_get(session, url, timeout=10, verbose=verbose) as response:
            data = await response.json()
            for rec in data.get("passive_dns", []):
                hostname = rec.get("hostname", "")
                if hostname.endswith(f".{domain}") and is_valid_subdomain(hostname):
                    subs.add(hostname)
            if verbose:
                logger.info(f"Fetched {len(subs)} subdomains from AlienVault OTX.")
    except Exception as e:
        if verbose:
            logger.error(f"AlienVault OTX fetch failed: {e}")
    return sorted(subs)

async def fetch_hackertarget_subdomains(session: aiohttp.ClientSession, domain: str,
                                        verbose: bool = False) -> List[str]:
    """Fetch subdomains from HackerTarget."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subs: Set[str] = set()
    try:
        async with safe_get(session, url, timeout=10, verbose=verbose) as response:
            text_data = await response.text()
            for line in text_data.splitlines():
                sub_candidate = line.split(",")[0]
                if is_valid_subdomain(sub_candidate):
                    subs.add(sub_candidate)
            if verbose:
                logger.info(f"Fetched {len(subs)} subdomains from HackerTarget.")
    except Exception as e:
        if verbose:
            logger.error(f"HackerTarget fetch failed: {e}")
    return sorted(subs)

async def fetch_urlscan_subdomains(session: aiohttp.ClientSession, domain: str,
                                   verbose: bool = False) -> List[str]:
    """Fetch subdomains from urlscan.io."""
    url = f"https://urlscan.io/api/v1/search/?q={domain}"
    subs: Set[str] = set()
    try:
        async with safe_get(session, url, timeout=10, verbose=verbose) as response:
            data = await response.json()
            for res in data.get("results", []):
                task_domain = res.get("task", {}).get("domain", "")
                if task_domain.endswith(f".{domain}") and is_valid_subdomain(task_domain):
                    subs.add(task_domain)
            if verbose:
                logger.info(f"Fetched {len(subs)} subdomains from urlscan.io.")
    except Exception as e:
        if verbose:
            logger.error(f"urlscan.io fetch failed: {e}")
    return sorted(subs)

# -------------------------------------------------------------------------------
# WAF Detection and Domain Status
# -------------------------------------------------------------------------------
async def detect_waf(session: aiohttp.ClientSession, domain: str, verbose: bool = False
                    ) -> Optional[str]:
    """
    Detect if a given domain is behind a WAF by checking HTTP headers and cookies.
    """
    for scheme in ["https://", "http://"]:
        url = f"{scheme}{domain}"
        try:
            async with safe_get(session, url, timeout=5, verbose=verbose) as resp:
                headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                cookies_str = "\n".join(f"{cookie.key}={cookie.value}" for cookie in resp.cookies.values())
                combined_data = (headers_str + "\n" + cookies_str).lower()
                for waf_name, signatures in WAF_SIGNATURES.items():
                    if any(sig.lower() in combined_data for sig in signatures):
                        if verbose:
                            logger.info(f"{domain} is behind WAF: {waf_name}")
                        return waf_name
            return None
        except asyncio.TimeoutError:
            if verbose:
                logger.error(f"Timeout during WAF detection for {domain} with scheme {scheme}")
        except Exception as e:
            if verbose:
                logger.error(f"WAF detection error for {domain} with scheme {scheme}: {e}")
    return None

async def check_domain_status(domain: str, session: aiohttp.ClientSession, verbose: bool = False
                              ) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Check if the domain resolves to an IP address (online) or not (offline).
    Returns a tuple: (domain, status, ip_address, waf_status).
    """
    loop = asyncio.get_event_loop()
    try:
        ip_addr = await loop.run_in_executor(None, socket.gethostbyname, domain)
        return (domain, "Online", ip_addr, None)
    except socket.gaierror:
        return (domain, "Offline", None, None)
    except UnicodeError as ue:
        if verbose:
            logger.warning(f"Skipping invalid domain [{domain}] due to: {ue}")
        return (domain, "Offline", None, None)

# -------------------------------------------------------------------------------
# Results Handling
# -------------------------------------------------------------------------------
async def save_results_to_file(
    main_domain_stats: Tuple[str, str, Optional[str], Optional[str]],
    online: List[Tuple[str, str, Optional[str], Optional[str]]],
    offline: List[Tuple[str, str, Optional[str], Optional[str]]],
    domain: str,
    verbose: bool = False
) -> str:
    """
    Save the domain statistics, online and offline subdomains to a timestamped text file.
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = os.path.join(OUTPUT_DIR, f"{domain}-{timestamp}.txt")

    md_domain, md_status, md_ip, md_waf = main_domain_stats
    md_waf_str = md_waf if md_waf else "None"

    no_waf = [o for o in online if o[3] is None]
    has_waf = [o for o in online if o[3] is not None]

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("Main Domain:\n")
        f.write(f"{md_domain} - {md_status} ({md_ip or 'N/A'}) WAF: {md_waf_str}\n\n")

        f.write("Online Domains (No WAF):\n")
        for d, _, ip, _ in sorted(no_waf, key=lambda x: x[0]):
            f.write(f"{d} ({ip or 'N/A'}) WAF: None\n")

        f.write("\nOnline Domains (Behind WAF):\n")
        for d, _, ip, waf in sorted(has_waf, key=lambda x: x[0]):
            f.write(f"{d} ({ip or 'N/A'}) WAF: {waf or 'None'}\n")

        f.write("\nOffline Domains:\n")
        for d, _, _, _ in sorted(offline, key=lambda x: x[0]):
            f.write(f"{d} (WAF: N/A)\n")
    return filename

async def display_results_in_panel(
    main_domain_stats: Tuple[str, str, Optional[str], Optional[str]],
    online: List[Tuple[str, str, Optional[str], Optional[str]]],
    offline: List[Tuple[str, str, Optional[str], Optional[str]]],
    results_file: str,
    domain: str
) -> None:
    """
    Display the final results in a formatted panel using Rich.
    """
    table = Table(expand=True, border_style="bright_blue", show_edge=False)
    table.add_column("Domain", style="cyan", no_wrap=True)
    table.add_column("Status", style="green", no_wrap=True)
    table.add_column("IP Address", no_wrap=True)
    table.add_column("WAF", no_wrap=True)

    def color_ip(ip: Optional[str]) -> Text:
        return Text("N/A", style="red") if ip is None else Text(ip)

    def color_waf(status: str, waf: Optional[str]) -> Text:
        if status == "Offline":
            return Text("N/A", style="red")
        if not waf:
            return Text("None", style="green")
        return Text(waf, style="orange")

    md_domain, md_status, md_ip, md_waf = main_domain_stats
    status_text = Text("Online", style="green") if md_status == "Online" else Text("Offline", style="red")
    table.add_row(Text(md_domain), status_text, color_ip(md_ip), color_waf(md_status, md_waf))

    separator = "─" * len(md_domain)
    table.add_row(Text(separator), Text(""), Text(""), Text(""))

    no_waf_online = [r for r in online if r[3] is None]
    with_waf_online = [r for r in online if r[3] is not None]
    ordered_online = sorted(no_waf_online, key=lambda x: x[0]) + sorted(with_waf_online, key=lambda x: x[0])

    for subdomain, status, ip_addr, waf_value in ordered_online:
        table.add_row(Text(subdomain), Text("Online", style="green"), color_ip(ip_addr),
                      color_waf(status, waf_value))

    for subdomain, status, ip_addr, waf_value in sorted(offline, key=lambda x: x[0]):
        table.add_row(Text(subdomain), Text("Offline", style="red"), color_ip(ip_addr),
                      color_waf(status, waf_value))

    panel = Panel(
        table,
        title="Subdomain Detection",
        subtitle=f"[white]Output File: {results_file}[/white]",
        border_style="bright_green",
        padding=(1, 1)
    )
    console.print(panel)
    console.print()

# -------------------------------------------------------------------------------
# Main Execution Flow
# -------------------------------------------------------------------------------
async def main() -> None:
    """Main entry point for the SubEcho tool."""
    await display_banner()

    parser = argparse.ArgumentParser(
        prog=f"SubEcho {VERSION}",
        description=f"SubEcho {VERSION}:\nA subdomain enumeration tool with real-time WAF detection.",
        epilog="Example Usage:\n  subecho -d example.com\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-d', '--domain', required=True, type=validate_domain_format,
                        help='Target domain (e.g., "example.com").')
    parser.add_argument('-k', '--apikey',
                        help='(Optional) SecurityTrails API key for deeper subdomain enumeration.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode for debug info.')
    args = parser.parse_args()

    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    all_subdomains: Set[str] = set()

    async with aiohttp.ClientSession() as session:
        # Subdomain enumeration
        enumerating_tasks = [
            fetch_crtsh_subdomains(session, args.domain, args.verbose),
            fetch_securitytrails_subdomains(session, args.domain, args.apikey, args.verbose),
            fetch_rapiddns_subdomains(session, args.domain, args.verbose),
            fetch_webarchive_subdomains(session, args.domain, args.verbose),
            fetch_alienvault_subdomains(session, args.domain, args.verbose),
            fetch_hackertarget_subdomains(session, args.domain, args.verbose),
            fetch_urlscan_subdomains(session, args.domain, args.verbose),
        ]
        with Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold bright_cyan]Enumerating subdomains...[/bold bright_cyan]"),
            BarColumn(bar_width=None),
            "{task.percentage:>3.0f}%",
            transient=True,
            expand=True
        ) as progress:
            progress_task = progress.add_task("Enumerating...", total=len(enumerating_tasks))
            results: List[List[str]] = []
            for coro in asyncio.as_completed(enumerating_tasks):
                sub_list = await coro
                results.append(sub_list)
                progress.advance(progress_task)
            for sub_list in results:
                all_subdomains.update(sub_list)

        all_subdomains.discard(args.domain)
        all_subdomains = {d for d in all_subdomains if not d.startswith('.')}
        sorted_subdomains = sorted(all_subdomains)

        # Domain status checking
        semaphore_status = asyncio.Semaphore(20)

        async def bounded_check_status(subdomain: str) -> Tuple[str, str, Optional[str], Optional[str]]:
            async with semaphore_status:
                return await check_domain_status(subdomain, session, args.verbose)

        total_checks = len(sorted_subdomains) + 1
        status_results: List[Tuple[str, str, Optional[str], Optional[str]]] = []

        with Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold bright_cyan]Checking subdomains status...[/bold bright_cyan]"),
            BarColumn(bar_width=None),
            "{task.percentage:>3.0f}%",
            transient=True,
            expand=True
        ) as progress:
            status_task = progress.add_task("Status checking", total=total_checks)
            main_domain_status = await check_domain_status(args.domain, session, args.verbose)
            status_results.append(main_domain_status)
            progress.advance(status_task)

            subdomain_tasks = [bounded_check_status(sd) for sd in sorted_subdomains]
            for coro in asyncio.as_completed(subdomain_tasks):
                status_results.append(await coro)
                progress.advance(status_task)

        online_domains = [r for r in status_results if r[1] == "Online"]
        offline_domains = [r for r in status_results if r[1] == "Offline"]

        # WAF detection
        semaphore_waf = asyncio.Semaphore(20)

        async def detect_waf_with_domain(item: Tuple[str, str, Optional[str], Optional[str]]
                                        ) -> Tuple[str, str, Optional[str], Optional[str]]:
            domain, status, ip, _ = item
            waf = await detect_waf(session, domain, args.verbose)
            return (domain, status, ip, waf)

        async def bounded_detect_waf(item: Tuple[str, str, Optional[str], Optional[str]]
                                     ) -> Tuple[str, str, Optional[str], Optional[str]]:
            async with semaphore_waf:
                return await detect_waf_with_domain(item)

        updated_online: List[Tuple[str, str, Optional[str], Optional[str]]] = []
        with Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold bright_cyan]Detecting WAF...[/bold bright_cyan]"),
            BarColumn(bar_width=None),
            "{task.percentage:>3.0f}%",
            transient=True,
            expand=True
        ) as progress:
            waf_task = progress.add_task("WAF detection", total=len(online_domains))
            waf_coros = [bounded_detect_waf(item) for item in online_domains]
            for coro in asyncio.as_completed(waf_coros):
                result = await coro
                updated_online.append(result)
                progress.advance(waf_task)

        # Update main domain status if applicable
        if main_domain_status[1] == "Online":
            possibly_updated = next(
                (item for item in updated_online if item[0] == main_domain_status[0]),
                main_domain_status
            )
            main_domain_status = possibly_updated

        online_subs = [o for o in updated_online if o[0] != main_domain_status[0]]
        final_online = [main_domain_status] + online_subs if main_domain_status[1] == "Online" else online_subs
        final_offline = [r for r in offline_domains if r[0] != main_domain_status[0]]

    # Save and display results outside the session context
    results_file = await save_results_to_file(main_domain_status, final_online[1:], final_offline, args.domain, args.verbose)
    await display_results_in_panel(main_domain_status, final_online[1:], final_offline, results_file, args.domain)

    # Verbose logging display
    if args.verbose:
        logs = log_stream.getvalue().splitlines()
        seen = set()
        filtered_lines = []
        pattern = re.compile(r"^\[(.*?)\] \[(.*?)\] (.*)$")
        for line in logs:
            if line in seen:
                continue
            seen.add(line)
            if any(x in line for x in ["is behind WAF", "WAF detection error", "Timeout during WAF detection"]):
                continue
            match = pattern.match(line)
            if match:
                timestamp, level, message = match.groups()
                level_color = {
                    "ERROR": "red",
                    "WARNING": "yellow",
                    "INFO": "green"
                }.get(level, "white")
                colored_line = (
                    f"[bright_cyan][{timestamp}][/bright_cyan] "
                    f"[{level_color}][{level}][/{level_color}] {message}"
                )
            else:
                colored_line = line
            filtered_lines.append(colored_line)
        filtered_output = "\n".join(filtered_lines)
        panel_title = "[bold bright_magenta]Verbose Logs[/bold bright_magenta]"
        panel_subtitle = "[white]Meow 🐱[/white]"
        console.print(Panel(filtered_output or "[yellow]No verbose logs available.[/yellow]",
                            title=panel_title,
                            subtitle=panel_subtitle,
                            border_style="bright_magenta",
                            padding=(1, 1)))

if __name__ == "__main__":
    asyncio.run(main())