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
---------
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
from datetime import datetime
from io import StringIO
from typing import Optional, List, Set, Tuple

import aiohttp
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.text import Text
from rich.traceback import install

# Install rich traceback for better exception formatting
install(show_locals=True)

# ------------------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------------------
VERSION = "BETA"  # Define version in one variable
OUTPUT_DIR = "output"

MAX_RETRIES = 3
DOMAIN_REGEX = r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$'

WAF_SIGNATURES = {
    "Akamai": ["Akamai-Ghost", "X-Akamai-Transformed", "X-Akamai-Edgescape", "akamaierror"],
    "Alibaba Cloud": ["Server: Alibaba Security", "X-Server: Jetty(Alibaba)"],
    "AlienVault OSSIM": ["alienvault"],
    "Astra Security": ["x-astra-cache", "astrawebprotection"],
    "AWS WAF": ["AWSWAF", "AWSALB", "AWSELBCORS", "x-amz-server"],
    "Barracuda": ["Barracuda", "server: Barracuda", "WAF: Barracuda", "barra_counter_session"],
    "BigIP (F5)": ["X-WA-Info", "X-Cnection", "Set-Cookie: BIGipServer", "BIGipServer", "F5_ST"],
    "BitNinja": ["bitninja-site-protection", "bitninja.io"],
    "BlazingFast": ["blazing_fast_server", "__bfuid"],
    "Cloudflare": ["cf-ray", "cf-cache-status", "CF-Connecting-IP", "__cfduid", "__cflb", "Server: cloudflare"],
    "CloudFront": ["x-amz-cf-id", "x-amz-cf-pop", "Server: CloudFront", "Via: CloudFront"],
    "DDoS-Guard": ["Server: ddos-guard", "DDOS-GUARD"],
    "EdgeCast": ["Server: ECD (", "Server: ECS ("],
    "FortiWeb": ["Server: FortiWeb"],
    "GoDaddy Website Protection": ["gd-warden"],
    "Incapsula (Imperva)": ["Incapsula", "X-CDN: Incapsula", "visid_incap_", "Incap_ses", "X-Iinfo"],
    "NAXSI": ["naxsi/waf"],
    "Netlify": ["server: Netlify"],
    "Oracle Cloud (OCI)": ["ORCL-Application-Protection"],
    "Palo Alto Networks": ["X-PaloAlto"],
    "Profense": ["Server: PD-OR", "Profense"],
    "Reblaze": ["X-Reblaze-Proxy", "rbzid", "rbzerr", "rbz"],
    "SiteLock TrueShield": ["sitelock-shield", "X-Sitelock-Request-Id"],
    "StackPath": ["Server: StackPath"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-block", "Server: Sucuri/Cloudproxy"],
    "URLScan.io (Phishing Shield)": ["x-urlscan-block"],
    "Varnish": ["X-Varnish", "Via: varnish"],
    "Wallarm": ["wallarm", "X-Wallarm-Protection"],
    "WebARX": ["x-webarx", "x-waf-status"],
    "Wordfence": ["X-Wordfence-Blocked", "wfwaf-authcookie-"],
}

# ------------------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------------------
log_stream = StringIO()
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(log_stream)]
)
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# Helpers / Validators
# ------------------------------------------------------------------------------
def validate_domain_format(domain: str) -> str:
    """
    Validate that the domain matches a proper domain format.
    Raises an error if invalid.
    """
    if not re.match(DOMAIN_REGEX, domain):
        raise argparse.ArgumentTypeError(f"Invalid domain format: {domain}")
    return domain

def is_valid_subdomain(sd: str) -> bool:
    """
    Returns True if the string `sd` matches the domain regex.
    """
    return re.match(DOMAIN_REGEX, sd) is not None

def parse_subdomains(data: list) -> List[str]:
    """
    Parse subdomains from data returned by crt.sh queries (or other sources).
    - Removes wildcards (e.g., *.example.com)
    - Skips anything that starts with '.' (e.g., .enterprise.example.com)
    - Validates the remaining name to ensure it follows domain naming rules.
    """
    results = set()
    for entry in data:
        if 'name_value' in entry:
            for nm in entry['name_value'].split(','):
                candidate = nm.strip()
                # Skip wildcard subdomains like "*.example.com"
                if candidate.startswith('*'):
                    continue
                # Skip subdomains that begin with '.' 
                if candidate.startswith('.'):
                    continue
                # Finally, check if it matches our domain regex
                if is_valid_subdomain(candidate):
                    results.add(candidate)
    return sorted(results)

# ------------------------------------------------------------------------------
# Display
# ------------------------------------------------------------------------------
async def display_banner() -> None:
    """
    Display a fancy ASCII banner using Rich.
    """
    ascii_art = r"""
  ██████  █    ██  ▄▄▄▄   ▓█████  ▄████▄   ██░ ██  ▒█████  
▒██    ▒  ██  ▓██▒▓█████▄ ▓█   ▀ ▒██▀ ▀█  ▓██░ ██▒▒██▒  ██▒
░ ▓██▄   ▓██  ▒██░▒██▒ ▄██▒███   ▒▓█    ▄ ▒██▀▀██░▒██░  ██▒
  ▒   ██▒▓▓█  ░██░▒██░█▀  ▒▓█  ▄ ▒▓▓▄ ▄██▒░▓█ ░██ ▒██   ██░
▒██████▒▒▒▒█████▓ ░▓█  ▀█▓░▒████▒▒ ▓███▀ ░░▓█▒░██▓░ ████▓▒░
▒ ▒▓▒ ▒ ░░▒▓▒ ▒ ▒ ░▒▓███▀▒░░ ▒░ ░░ ░▒ ▒  ░ ▒ ░░▒░▒░ ▒░▒░▒░ 
░ ░▒  ░ ░░░▒░ ░ ░ ▒░▒   ░  ░ ░  ░  ░  ▒    ▒ ░▒░ ░  ░ ▒ ▒░ 
░  ░  ░   ░░░ ░ ░  ░    ░    ░   ░         ░  ░░ ░░ ░ ░ ▒  
      ░     ░      ░         ░  ░░ ░       ░  ░  ░    ░ ░  
                        ░        ░                         
"""
    panel = Panel(
        Text(ascii_art, style="red", justify="center"),
        title=f"[bright_magenta]Version {VERSION}[/]",
        subtitle="[bold white]Created by John Holt[/]",
        border_style="bright_magenta",
        padding=0
    )
    Console().print(panel)
    Console().print()

# ------------------------------------------------------------------------------
# Subdomain Fetchers
# (unchanged fetch_*_subdomains functions)
# ------------------------------------------------------------------------------

async def fetch_crtsh_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    verbose: bool = False
) -> List[str]:
    """
    Fetch subdomains from crt.sh using multiple wildcard patterns.
    Returns a list of discovered subdomains.
    """
    urls = [
        f"https://crt.sh/?q=%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.%.{domain}&output=json",
        f"https://crt.sh/?q=%.%.%.%.{domain}&output=json",
    ]
    all_subs = set()
    for url in urls:
        try:
            async with session.get(url) as r:
                r.raise_for_status()
                data = await r.json()
                all_subs.update(parse_subdomains(data))
        except Exception as e:
            if verbose:
                logger.error(f"[red]crt.sh fetch failed for {url}: {e}[/red]")
    if verbose:
        logger.info(f"[bright_cyan]Fetched {len(all_subs)} subdomains from crt.sh.[/]")
    return sorted(all_subs)

async def fetch_securitytrails_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    api_key: Optional[str],
    verbose: bool = False
) -> List[str]:
    """
    Fetch subdomains from SecurityTrails API if an API key is provided.
    """
    if not api_key:
        if verbose:
            logger.warning("[yellow]SecurityTrails API key missing. Skipping...[/]")
        return []

    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    headers = {
        'accept': "application/json",
        'apikey': api_key
    }
    subs = []
    try:
        async with session.get(url, headers=headers) as r:
            r.raise_for_status()
            data = await r.json()
            subs = data.get('subdomains', [])
            if verbose:
                logger.info(f"[bright_cyan]Fetched {len(subs)} subdomains from SecurityTrails API.[/]")
    except Exception as e:
        if verbose:
            logger.error(f"[red]SecurityTrails fetch failed: {e}[/red]")
    # Convert them to FQDN with domain
    return [f"{s}.{domain}" for s in subs]

async def fetch_rapiddns_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    verbose: bool = False
) -> List[str]:
    """
    Fetch subdomains from rapiddns.io by scraping the HTML response.
    """
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    headers = {'User-Agent': 'Mozilla/5.0'}
    subs = set()
    try:
        async with session.get(url, headers=headers) as r:
            r.raise_for_status()
            html = await r.text()
            found = re.findall(rf"(?:\b|\.)[A-Za-z0-9-]+\.{re.escape(domain)}", html)
            subs.update(found)
            if verbose:
                logger.info(f"[bright_cyan]Fetched {len(subs)} subdomains from RapidDNS.[/]")
    except Exception as e:
        if verbose:
            logger.error(f"[red]RapidDNS fetch failed: {e}[/red]")
    return sorted(subs)

async def fetch_webarchive_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    verbose: bool = False
) -> List[str]:
    """
    Fetch subdomains from the Internet Archive (Wayback Machine) 
    by scraping the cdx API.
    """
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"
    subs = set()
    try:
        async with session.get(url) as r:
            r.raise_for_status()
            txt = await r.text()
            for line in txt.splitlines():
                m = re.search(rf"(?:\b|\.)[A-Za-z0-9-]+\.{re.escape(domain)}", line)
                if m:
                    subs.add(m.group(0))
            if verbose:
                logger.info(f"[bright_cyan]Fetched {len(subs)} subdomains from Web Archive.[/]")
    except Exception as e:
        if verbose:
            logger.error(f"[red]Web Archive fetch failed: {e}[/red]")
    return sorted(subs)

async def fetch_alienvault_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    verbose: bool = False
) -> List[str]:
    """
    Fetch subdomains from AlienVault OTX.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subs = set()
    try:
        async with session.get(url) as r:
            r.raise_for_status()
            data = await r.json()
            for rec in data.get("passive_dns", []):
                hostname = rec.get("hostname", "")
                if hostname.endswith(f".{domain}") and is_valid_subdomain(hostname):
                    subs.add(hostname)
            if verbose:
                logger.info(f"[bright_cyan]Fetched {len(subs)} subdomains from AlienVault OTX.[/]")
    except Exception as e:
        if verbose:
            logger.error(f"[red]AlienVault OTX fetch failed: {e}[/red]")
    return sorted(subs)

async def fetch_hackertarget_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    verbose: bool = False
) -> List[str]:
    """
    Fetch subdomains from HackerTarget by parsing the CSV-style output.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subs = set()
    try:
        async with session.get(url) as r:
            r.raise_for_status()
            text_data = await r.text()
            for line in text_data.splitlines():
                sub_candidate = line.split(",")[0]
                if is_valid_subdomain(sub_candidate):
                    subs.add(sub_candidate)
            if verbose:
                logger.info(f"[bright_cyan]Fetched {len(subs)} subdomains from HackerTarget.[/]")
    except Exception as e:
        if verbose:
            logger.error(f"[red]HackerTarget fetch failed: {e}[/red]")
    return sorted(subs)

async def fetch_urlscan_subdomains(
    session: aiohttp.ClientSession,
    domain: str,
    verbose: bool = False
) -> List[str]:
    """
    Fetch subdomains from urlscan.io by searching for the domain and parsing results.
    """
    url = f"https://urlscan.io/api/v1/search/?q={domain}"
    subs = set()
    try:
        async with session.get(url) as r:
            r.raise_for_status()
            data = await r.json()
            for res in data.get("results", []):
                task_domain = res.get("task", {}).get("domain", "")
                if task_domain.endswith(f".{domain}") and is_valid_subdomain(task_domain):
                    subs.add(task_domain)
            if verbose:
                logger.info(f"[bright_cyan]Fetched {len(subs)} subdomains from urlscan.io.[/]")
    except Exception as e:
        if verbose:
            logger.error(f"[red]urlscan.io fetch failed: {e}[/red]")
    return sorted(subs)

# ------------------------------------------------------------------------------
# WAF Detection
# ------------------------------------------------------------------------------
async def detect_waf(
    session: aiohttp.ClientSession,
    domain: str,
    verbose: bool = False
) -> Optional[str]:
    """
    Attempt to detect if `domain` is behind a known WAF by looking for 
    signature strings in response headers and cookies.
    """
    for scheme in ["https://", "http://"]:
        url = f"{scheme}{domain}"
        try:
            async with session.get(url, timeout=5) as resp:
                headers_str = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()])
                cookies_str = "\n".join([f"{co.key}={co.value}" for co in resp.cookies.values()])
                combined_data = (headers_str + "\n" + cookies_str).lower()

                for waf_name, signatures in WAF_SIGNATURES.items():
                    for sig in signatures:
                        if sig.lower() in combined_data:
                            if verbose:
                                logger.info(f"[bright_cyan]{domain} is behind WAF: {waf_name}[/]")
                            return waf_name
            return None
        except asyncio.TimeoutError:
            if verbose:
                logger.error(f"[red]Timeout during WAF detection for {domain} with scheme {scheme}[/red]")
        except Exception as e:
            if verbose:
                logger.error(f"[red]WAF detection error {domain} with scheme {scheme}: {e}[/red]")
    return None

# ------------------------------------------------------------------------------
# Domain Status Checking (with UnicodeError Handling)
# ------------------------------------------------------------------------------
async def check_domain_status(
    domain: str,
    session: aiohttp.ClientSession,
    verbose: bool = False
) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Check if the domain is online/offline by trying to resolve its IP.
    Return (domain, status, ip, waf).
      - status: "Online" or "Offline"
      - ip: IP string or None
      - waf: Placeholder for WAF detection result (filled later)
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

# ------------------------------------------------------------------------------
# Results Saving & Display
# ------------------------------------------------------------------------------
async def save_results_to_file(
    main_domain_stats: Tuple[str, str, Optional[str], Optional[str]],
    online: List[Tuple[str, str, Optional[str], Optional[str]]],
    offline: List[Tuple[str, str, Optional[str], Optional[str]]],
    domain: str,
    verbose: bool = False
) -> str:
    """
    Save enumeration results to a timestamped text file.
    Returns the filename.
    """
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(OUTPUT_DIR, exist_ok=True)  # Ensure output directory exists
    filename = os.path.join(OUTPUT_DIR, f"{domain}-{timestamp}.txt")

    with open(filename, 'w', encoding='utf-8') as f:
        md_domain, md_status, md_ip, md_waf = main_domain_stats
        md_waf_str = md_waf if md_waf else "None"

        f.write(f"Main Domain:\n")
        f.write(f"{md_domain} - {md_status} ({md_ip or 'N/A'}) WAF: {md_waf_str}\n\n")

        no_waf = [o for o in online if o[3] is None]
        has_waf = [o for o in online if o[3] is not None]

        f.write("Online Domains (No WAF):\n")
        for d, s, i, w in sorted(no_waf, key=lambda x: x[0]):
            f.write(f"{d} ({i or 'N/A'}) WAF: None\n")

        f.write("\nOnline Domains (Behind WAF):\n")
        for d, s, i, w_ in sorted(has_waf, key=lambda x: x[0]):
            f.write(f"{d} ({i or 'N/A'}) WAF: {w_ if w_ else 'None'}\n")

        f.write("\nOffline Domains:\n")
        for d, s, i, w_ in sorted(offline, key=lambda x: x[0]):
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
    Display the enumeration results in a Rich Table panel.
    """
    table = Table(expand=True, border_style="bright_blue", show_edge=False)
    table.add_column("Domain", style="cyan", no_wrap=True)
    table.add_column("Status", style="green", no_wrap=True)
    table.add_column("IP Address", no_wrap=True)
    table.add_column("WAF", no_wrap=True)

    def color_ip(ip: Optional[str]) -> Text:
        return Text("N/A", style="red") if ip is None else Text(ip)

    def color_waf(status: str, wf: Optional[str]) -> Text:
        if status == "Offline":
            return Text("N/A", style="red")
        if not wf:
            return Text("None", style="green")
        return Text(wf, style="orange")

    # Main domain row
    md_domain, md_status, md_ip, md_waf = main_domain_stats
    status_text = Text("Online", style="green") if md_status == "Online" else Text("Offline", style="red")
    table.add_row(
        Text(md_domain),
        status_text,
        color_ip(md_ip),
        color_waf(md_status, md_waf)
    )

    # A separator row for clarity
    separator = "─" * len(md_domain)
    table.add_row(Text(separator), Text(""), Text(""), Text(""))

    # Online subdomains (no WAF first, then WAF)
    no_waf_online = [r for r in online if r[3] is None]
    with_waf_online = [r for r in online if r[3] is not None]
    ordered_online = sorted(no_waf_online, key=lambda x: x[0]) + sorted(with_waf_online, key=lambda x: x[0])

    for (sd, s_u, si, sw) in ordered_online:
        table.add_row(
            Text(sd),
            Text("Online", style="green"),
            color_ip(si),
            color_waf(s_u, sw)
        )

    # Offline subdomains
    for (sd, s_u, si, sw) in sorted(offline, key=lambda x: x[0]):
        table.add_row(
            Text(sd),
            Text("Offline", style="red"),
            color_ip(si),
            color_waf(s_u, sw)
        )

    panel = Panel(
        table,
        title="Subdomain Detection",
        subtitle=f"[white]Output File: {results_file}[/white]",
        border_style="bright_green",
        padding=(1, 1)
    )

    Console().print(panel)
    Console().print()

# ------------------------------------------------------------------------------
# Main Entry Point
# ------------------------------------------------------------------------------
async def main() -> None:
    """
    Main async function that orchestrates:
      1) Banner display
      2) Argument parsing
      3) Subdomain fetching from multiple sources
      4) Domain status checks (online/offline)
      5) WAF detection for online domains
      6) Results saving and display
      7) Optional verbose log display
    """
    await display_banner()

    parser = argparse.ArgumentParser(
        prog=f"SubEcho {VERSION}",
        description=(
            f"SubEcho {VERSION}:\n"
            "A subdomain enumeration tool with real-time WAF detection."
        ),
        epilog=(
            "Example Usage:\n"
            "  subecho -d example.com\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        '-d', '--domain',
        required=True,
        type=validate_domain_format,
        help='Target domain (e.g., "example.com").'
    )
    parser.add_argument(
        '-k', '--apikey',
        help='(Optional) SecurityTrails API key for deeper subdomain enumeration.'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose mode for debug info.'
    )
    args = parser.parse_args()

    all_subdomains: Set[str] = set()

    # 1) Subdomain enumeration
    async with aiohttp.ClientSession() as session:
        enumerating_tasks = [
            fetch_crtsh_subdomains(session, args.domain, args.verbose),
            fetch_securitytrails_subdomains(session, args.domain, args.apikey, args.verbose),
            fetch_rapiddns_subdomains(session, args.domain, args.verbose),
            fetch_webarchive_subdomains(session, args.domain, args.verbose),
            fetch_alienvault_subdomains(session, args.domain, args.verbose),
            fetch_hackertarget_subdomains(session, args.domain, args.verbose),
            fetch_urlscan_subdomains(session, args.domain, args.verbose),
        ]

        fetcher_names = [
            "crt.sh",
            "SecurityTrails",
            "RapidDNS",
            "WebArchive",
            "AlienVault OTX",
            "HackerTarget",
            "urlscan.io"
        ]

        with Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold bright_cyan]Enumerating subdomains from {task.description}...[/bold bright_cyan]"),
            BarColumn(),
            "{task.percentage:>3.0f}%",
            transient=True,
            expand=True
        ) as progress:
            task = progress.add_task(f"{fetcher_names[0]}", total=len(enumerating_tasks))
            results = []
            for i, coro in enumerate(asyncio.as_completed(enumerating_tasks)):
                sub_list = await coro
                results.append(sub_list)
                progress.update(task, description=f"{fetcher_names[i]}")
                progress.update(task, advance=1)

            for r_ in results:
                all_subdomains.update(r_)

    # Remove the main domain from subdomains if present
    all_subdomains.discard(args.domain)
    
    # Filter out any subdomains that start with a dot
    all_subdomains = {d for d in all_subdomains if not d.startswith('.')}

    # 2) Check domain statuses (online/offline)
    sorted_subdomains = sorted(all_subdomains)
    async with aiohttp.ClientSession() as session:
        with Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold bright_cyan]Checking subdomains status...[/bold bright_cyan]"),
            BarColumn(),
            "{task.percentage:>3.0f}%",
            transient=True,
            expand=True
        ) as progress:
            total_checks = len(sorted_subdomains) + 1  # +1 for main domain
            status_task = progress.add_task("Status checking", total=total_checks)
            
            main_domain_status = await check_domain_status(args.domain, session, args.verbose)
            progress.advance(status_task)

            subdomain_tasks = [check_domain_status(sd, session, args.verbose) for sd in sorted_subdomains]
            status_results = [main_domain_status]
            for coro in asyncio.as_completed(subdomain_tasks):
                status_results.append(await coro)
                progress.advance(status_task)

    online_domains = [r for r in status_results if r[1] == "Online"]
    offline_domains = [r for r in status_results if r[1] == "Offline"]

    # 3) WAF detection for online domains
    async with aiohttp.ClientSession() as session:
        async def detect_waf_with_domain(item: Tuple[str, str, Optional[str], Optional[str]]
        ) -> Tuple[str, str, Optional[str], Optional[str]]:
            dom, st, ip, _ = item
            w = await detect_waf(session, dom, args.verbose)
            return (dom, st, ip, w)

        with Progress(
            SpinnerColumn(spinner_name="dots12"),
            TextColumn("[bold bright_cyan]Detecting WAF...[/bold bright_cyan]"),
            BarColumn(),
            "{task.percentage:>3.0f}%",
            transient=True,
            expand=True
        ) as progress:
            total_waf = len(online_domains)
            waf_task = progress.add_task("WAF detection", total=total_waf)
            waf_coros = [detect_waf_with_domain(item) for item in online_domains]
            
            updated_online = []
            for coro in asyncio.as_completed(waf_coros):
                result = await coro
                updated_online.append(result)
                progress.advance(waf_task)

    # Ensure main domain info is updated with WAF if it's online
    main_domain_list = list(main_domain_status)
    if main_domain_status[1] == "Online":
        possibly_updated = next(
            (item for item in updated_online if item[0] == main_domain_status[0]),
            main_domain_status
        )
        main_domain_list = list(possibly_updated)
    main_domain_status = tuple(main_domain_list)

    # Reorganize online/offline for final display
    final_main_domain = main_domain_status
    online_subs = [o for o in updated_online if o[0] != final_main_domain[0]]
    final_online = [final_main_domain] + online_subs if final_main_domain[1] == "Online" else online_subs
    final_offline = [r for r in offline_domains if r[0] != final_main_domain[0]]

    # 4) Save results to file
    results_file = await save_results_to_file(final_main_domain, final_online[1:], final_offline, args.domain, args.verbose)

    # 5) Display results in a panel
    await display_results_in_panel(final_main_domain, final_online[1:], final_offline, results_file, args.domain)

    # 6) (Optional) Display filtered verbose logs
    if args.verbose:
        console = Console()
        logs = log_stream.getvalue()
        filtered_lines = []
        for line in logs.splitlines():
            if any(x in line for x in ["is behind WAF", "WAF detection error", "Timeout during WAF detection"]):
                continue
            filtered_lines.append(line)

        filtered_output = "\n".join(filtered_lines)
        console.print(
            Panel(
                filtered_output if filtered_output else "[yellow]No verbose logs available.[/]",
                title="Verbose Logs",
                subtitle="[white]Meow 🐱[/white]",
                border_style="red",
                padding=(1, 1)
            )
        )

# Standard entry point
if __name__ == "__main__":
    asyncio.run(main())