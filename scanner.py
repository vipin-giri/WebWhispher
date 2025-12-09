#!/usr/bin/env python3
"""
WebWhisper - Domain Discovery Tool

Fetch random real domains (unique across runs) using Certificate Transparency (crt.sh).
Persists 'seen' domains in a local SQLite DB so each scan returns new domains only.
Filters for live domains with HTTP 200 status.

Usage:
    python scanner.py --count 20 --tlds com,net
    python scanner.py --count 100 --no-verify  (skip live checking)

Notes:
- Be polite to crt.sh (this script has basic rate-limiting and caching).
- If crt.sh is unreachable, the script will try to use cached domains only.
"""

import argparse
import requests
import sqlite3
import time
import random
import hashlib
import sys
from datetime import datetime
from urllib.parse import quote_plus
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib3

# Disable SSL warnings for domains with certificate issues
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === COLORS ===
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    banner = f"""
{Colors.RED}{Colors.BOLD}
 ██╗    ██╗███████╗██████╗ ██╗    ██╗██╗  ██╗██╗███████╗██████╗ ███████╗██████╗ 
 ██║    ██║██╔════╝██╔══██╗██║    ██║██║  ██║██║██╔════╝██╔══██╗██╔════╝██╔══██╗
 ██║ █╗ ██║█████╗  ██████╔╝██║ █╗ ██║███████║██║███████╗██████╔╝█████╗  ██████╔╝
 ██║███╗██║██╔══╝  ██╔══██╗██║███╗██║██╔══██║██║╚════██║██╔═══╝ ██╔══╝  ██╔══██╗
 ╚███╔███╔╝███████╗██████╔╝╚███╔███╔╝██║  ██║██║███████║██║     ███████╗██║  ██║
  ╚══╝╚══╝ ╚══════╝╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝
{Colors.ENDC}
{Colors.YELLOW}              Domain Discovery via Certificate Transparency{Colors.ENDC}
{Colors.BLUE}                        CIpher
"""
    print(banner)

# === CONFIG ===
DB_PATH = "webwhisper_db.db"
CRT_SH_BASE = "https://crt.sh/"
USER_AGENT = "WebWhisper/1.0 (+https://example.local)"
REQUEST_TIMEOUT = 20
SLEEP_BETWEEN_REQUESTS = 1.0  # polite delay
DEFAULT_TLDS = ["com", "net", "org", "io", "co", "uk", "de", "fr", "ca", "au", "jp", "cn", "in", "br", "ru", "nl", "it", "es", "se", "no", "pl", "be", "ch", "at", "dk", "fi", "cz", "pt", "gr", "nz"]
MAX_RESULTS_FETCH = 3000  # safety cap on how many JSON entries we'll ingest per TLD request
LIVE_CHECK_TIMEOUT = 5  # timeout for checking if domain is live
MAX_WORKERS = 20  # concurrent threads for live checking

# === DB ===
def init_db(path=DB_PATH):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS seen_domains (
            id INTEGER PRIMARY KEY,
            domain TEXT UNIQUE,
            fingerprint TEXT UNIQUE,
            first_seen_ts DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn

def mark_seen(conn, domain):
    cur = conn.cursor()
    fp = hashlib.sha256(domain.encode('utf-8')).hexdigest()
    try:
        cur.execute("INSERT INTO seen_domains (domain, fingerprint) VALUES (?, ?)", (domain, fp))
        conn.commit()
        return True
    except Exception:
        return False

def already_seen(conn, domain):
    cur = conn.cursor()
    fp = hashlib.sha256(domain.encode('utf-8')).hexdigest()
    cur.execute("SELECT 1 FROM seen_domains WHERE fingerprint = ? LIMIT 1", (fp,))
    return cur.fetchone() is not None

# === Live domain checking ===
def check_domain_live(domain):
    """
    Check if domain is live by attempting HTTP/HTTPS connections.
    Returns (domain, True) if status 200, else (domain, False)
    """
    protocols = ['https://', 'http://']
    headers = {'User-Agent': USER_AGENT}
    
    for protocol in protocols:
        try:
            url = f"{protocol}{domain}"
            response = requests.get(
                url, 
                headers=headers, 
                timeout=LIVE_CHECK_TIMEOUT, 
                allow_redirects=True,
                verify=False  # Skip SSL verification for domains with cert issues
            )
            if response.status_code == 200:
                return (domain, True, response.status_code, protocol)
        except requests.exceptions.SSLError:
            # Try with verify=False already set, continue to next protocol
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.TooManyRedirects:
            continue
        except Exception:
            continue
    
    return (domain, False, None, None)

def filter_live_domains(domains, show_progress=True):
    """
    Filter domains to only return those with HTTP 200 status.
    Uses ThreadPoolExecutor for concurrent checking.
    """
    live_domains = []
    total = len(domains)
    checked = 0
    
    if show_progress:
        print(f"{Colors.CYAN}[*] Checking {total} domains for live status (HTTP 200)...{Colors.ENDC}")
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_domain = {executor.submit(check_domain_live, domain): domain for domain in domains}
        
        for future in as_completed(future_to_domain):
            checked += 1
            try:
                domain, is_live, status, protocol = future.result()
                if is_live:
                    live_domains.append(domain)
                    if show_progress:
                        print(f"{Colors.GREEN}[✓] {domain} ({protocol[:-3].upper()}) - {checked}/{total}{Colors.ENDC}")
                else:
                    if show_progress:
                        print(f"{Colors.RED}[✗] {domain} - {checked}/{total}{Colors.ENDC}", end='\r')
            except Exception as e:
                if show_progress:
                    print(f"{Colors.RED}[✗] Error checking domain - {checked}/{total}{Colors.ENDC}", end='\r')
    
    if show_progress:
        print(f"\n{Colors.GREEN}[+] Found {len(live_domains)} live domains out of {total} checked{Colors.ENDC}")
    
    return live_domains

# === crt.sh fetch/parsing ===
def fetch_from_crtsh(tld="com"):
    """
    Fetch JSON results from crt.sh searching for '%.<tld>' – returns a set of domains.
    crt.sh JSON fields: 'issuer_ca_id','issuer_name','common_name','name_value' etc.
    We'll parse name_value which can contain multiple domains separated by newline.
    """
    q = quote_plus(f"%.{tld}")
    url = f"{CRT_SH_BASE}?q={q}&output=json"
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        if r.status_code != 200:
            # some deployments redirect to HTML if too many results; treat non-200 as failure
            print(f"{Colors.RED}[!] crt.sh returned status {r.status_code} for tld {tld}{Colors.ENDC}", file=sys.stderr)
            return set()
        data = r.json()
    except ValueError:
        # invalid json or HTML returned
        print(f"{Colors.RED}[!] crt.sh returned non-JSON reply for tld {tld} – skipping.{Colors.ENDC}", file=sys.stderr)
        return set()
    except Exception as e:
        print(f"{Colors.RED}[!] Error fetching crt.sh for tld {tld}: {e}{Colors.ENDC}", file=sys.stderr)
        return set()

    domains = set()
    # data is a list of objects – 'name_value' contains domain(s), possibly with wildcards or newlines
    for i, entry in enumerate(data):
        if i >= MAX_RESULTS_FETCH:
            break
        nv = entry.get("name_value")
        if not nv:
            continue
        # entries can contain multiple names separated by newline
        for name in nv.splitlines():
            name = name.strip().lower()
            if not name:
                continue
            # strip leading wildcard if present
            if name.startswith("*."):
                name = name[2:]
            # filter out IPs and short junk
            if name.count(".") < 1:
                continue
            domains.add(name)
    return domains

# === Main logic ===
def collect_candidates(tlds):
    """Try crt.sh for each tld; build a candidate pool (deduped)."""
    pool = set()
    print(f"{Colors.CYAN}[*] Gathering candidate domains from crt.sh (may take a few seconds)...{Colors.ENDC}")
    for tld in tlds:
        print(f"{Colors.BLUE}    -> fetching .{tld} ...{Colors.ENDC}", end="", flush=True)
        try:
            found = fetch_from_crtsh(tld)
            print(f"{Colors.GREEN} {len(found)}{Colors.ENDC}")
            pool.update(found)
        except Exception as e:
            print(f"{Colors.RED} error: {e}{Colors.ENDC}")
    print(f"{Colors.CYAN}[*] Total unique candidates fetched: {Colors.GREEN}{len(pool)}{Colors.ENDC}")
    return pool

def sample_new_domains(conn, candidates, count, verify_live=True):
    """Return up to `count` domains from candidates that are not already in DB; mark and return them."""
    candidates_list = list(candidates)
    random.shuffle(candidates_list)
    
    # We'll collect more than needed to account for offline domains
    # Reduced multiplier: 3x instead of 10x for faster processing
    fetch_multiplier = 3 if verify_live else 1
    fetch_count = count * fetch_multiplier
    
    potential = []
    for d in candidates_list:
        if len(potential) >= fetch_count:
            break
        if already_seen(conn, d):
            continue
        # simple sanity filter: prefer domains without weird chars
        if any(c in d for c in " <>\\\"'"):
            continue
        potential.append(d)
    
    # Filter for live domains if verification is enabled
    if verify_live and potential:
        live = filter_live_domains(potential)
        # Mark as seen and return
        out = []
        for d in live:
            if len(out) >= count:
                break
            success = mark_seen(conn, d)
            if success:
                out.append(d)
        return out
    else:
        # No verification, just mark and return
        out = []
        for d in potential:
            if len(out) >= count:
                break
            success = mark_seen(conn, d)
            if success:
                out.append(d)
        return out

def save_domains_to_file(domains):
    """Auto-save domains to a file with timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{timestamp}_domains.txt"
    try:
        with open(filename, 'w') as f:
            for domain in domains:
                f.write(f"{domain}\n")
        print(f"{Colors.GREEN}[+] Domains saved to: {Colors.BOLD}{filename}{Colors.ENDC}")
        return filename
    except Exception as e:
        print(f"{Colors.RED}[!] Error saving to file: {e}{Colors.ENDC}")
        return None

def main():
    print_banner()
    
    ap = argparse.ArgumentParser(description="WebWhisper - Random real domains finder (unique per run).")
    ap.add_argument("--count", "-n", type=int, default=25, help="how many unique live domains to return")
    ap.add_argument("--tlds", type=str, default=",".join(DEFAULT_TLDS),
                    help=f"comma-separated list of TLDs to query (default: {len(DEFAULT_TLDS)} common TLDs)")
    ap.add_argument("--use-cache-only", action="store_true",
                    help="don't fetch crt.sh; use DB cache only (useful if offline)")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip live domain verification (faster but may return offline domains)")
    args = ap.parse_args()

    tlds = [t.strip().lstrip(".") for t in args.tlds.split(",") if t.strip()]
    verify_live = not args.no_verify

    conn = init_db()

    if verify_live:
        print(f"{Colors.YELLOW}[*] Live verification: ENABLED (only HTTP 200 domains will be returned){Colors.ENDC}")
    else:
        print(f"{Colors.YELLOW}[*] Live verification: DISABLED (domains may be offline){Colors.ENDC}")

    # If cache-only requested, collect unseen domains from DB by sampling rows not yet returned? We'll just read DB and say none left.
    if args.use_cache_only:
        print(f"{Colors.CYAN}[*] Using DB cache only (no remote fetch).{Colors.ENDC}")
        cur = conn.cursor()
        cur.execute("SELECT domain FROM seen_domains ORDER BY RANDOM() LIMIT ?", (args.count * 3 if verify_live else args.count,))
        rows = cur.fetchall()
        domains = [r[0] for r in rows]
        if not domains:
            print(f"{Colors.RED}[!] DB empty. Run once without --use-cache-only to populate cache.{Colors.ENDC}")
        else:
            if verify_live:
                domains = filter_live_domains(domains)[:args.count]
            for d in domains:
                print(f"{Colors.GREEN}{d}{Colors.ENDC}")
            save_domains_to_file(domains)
        return

    # Fetch candidate pool from crt.sh
    candidates = collect_candidates(tlds)

    if not candidates:
        # Nothing fetched; try to return previously-seen domains that weren't printed before.
        print(f"{Colors.YELLOW}[!] No new candidates fetched from crt.sh. Falling back to DB random selection.{Colors.ENDC}")
        cur = conn.cursor()
        cur.execute("SELECT domain FROM seen_domains ORDER BY RANDOM() LIMIT ?", (args.count * 3 if verify_live else args.count,))
        rows = cur.fetchall()
        domains = [r[0] for r in rows]
        if rows:
            if verify_live:
                domains = filter_live_domains(domains)[:args.count]
            for d in domains:
                print(f"{Colors.GREEN}{d}{Colors.ENDC}")
            save_domains_to_file(domains)
        else:
            print(f"{Colors.RED}[!] DB empty too. Try again later or disable --use-cache-only.{Colors.ENDC}")
        return

    selected = sample_new_domains(conn, candidates, args.count, verify_live)

    # If we didn't find enough live domains, attempt to fetch more from DB
    if len(selected) < args.count:
        need = args.count - len(selected)
        print(f"{Colors.YELLOW}[*] Only {len(selected)} new live domains available. Filling {need} from DB (already seen).{Colors.ENDC}")
        cur = conn.cursor()
        cur.execute("SELECT domain FROM seen_domains ORDER BY RANDOM() LIMIT ?", (need * 3 if verify_live else need,))
        rows = cur.fetchall()
        cached_domains = [r[0] for r in rows]
        
        if verify_live and cached_domains:
            cached_live = filter_live_domains(cached_domains)
            selected.extend(cached_live[:need])
        else:
            for r in rows[:need]:
                selected.append(r[0])

    # Final output
    print(f"\n{Colors.BOLD}{Colors.CYAN}[*] Discovered Live Domains:{Colors.ENDC}\n")
    for d in selected:
        print(f"{Colors.GREEN}{d}{Colors.ENDC}")
    
    # Auto-save to file
    if selected:
        print()
        save_domains_to_file(selected)
    else:
        print(f"{Colors.RED}[!] No live domains found. Try increasing --count or adding more --tlds{Colors.ENDC}")

if __name__ == "__main__":
    main()