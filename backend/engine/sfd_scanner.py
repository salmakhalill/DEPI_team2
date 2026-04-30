#!/usr/bin/env python3
"""
Sensitive File Disclosure Scanner - Stage 3
Supports: built-in paths, custom wordlist, single URL, and multi-URL list.
"""

import requests
import sys
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────
# Built-in 20 Common Sensitive Paths
# ─────────────────────────────────────────────

DEFAULT_PATHS = [
    "/.env",
    "/.git/config",
    "/config.php",
    "/wp-config.php",
    "/config.yml",
    "/config.json",
    "/.htaccess",
    "/web.config",
    "/database.yml",
    "/db.sqlite",
    "/backup.zip",
    "/backup.sql",
    "/.ssh/id_rsa",
    "/id_rsa",
    "/server-status",
    "/phpinfo.php",
    "/info.php",
    "/admin/config.php",
    "/logs/error.log",
    "/debug.log",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (SFD-Scanner/1.0)"
}

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http"):
        url = "http://" + url
    return url.rstrip("/")


def load_wordlist(filepath: str) -> list:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]
            paths = [p if p.startswith("/") else "/" + p for p in lines]
        print(f"  [*] Wordlist loaded: {len(paths)} paths from '{filepath}'")
        return paths
    except FileNotFoundError:
        print(f"  [!] Wordlist file not found: {filepath}")
        sys.exit(1)


def load_url_list(filepath: str) -> list:
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            urls = [line.strip() for line in f if line.strip()]
        print(f"  [*] URL list loaded: {len(urls)} targets from '{filepath}'")
        return urls
    except FileNotFoundError:
        print(f"  [!] URL list file not found: {filepath}")
        sys.exit(1)


def print_banner():
    print("""
╔══════════════════════════════════════════════╗
║     Sensitive File Disclosure Scanner       ║
║            Stage 3 - Full Mode              ║
╚══════════════════════════════════════════════╝
""")

# ─────────────────────────────────────────────
# Core Scan Function (single target)
# ─────────────────────────────────────────────

def scan_target(base_url: str, paths: list, timeout: int) -> list:
    found = []
    for path in paths:
        url = base_url + path
        try:
            r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                found.append(url)
                print(f"  \033[91m[EXPOSED]\033[0m  {url}  (status 200, size {len(r.content)} bytes)")
            else:
                print(f"  \033[92m[SAFE]\033[0m     {url}  (status {r.status_code})")
        except requests.exceptions.ConnectionError:
            print(f"  \033[93m[ERROR]\033[0m    {url}  (connection failed)")
        except requests.exceptions.Timeout:
            print(f"  \033[93m[TIMEOUT]\033[0m  {url}")
    return found


def print_target_summary(base_url: str, found: list):
    print("\n" + "─" * 55)
    if found:
        print(f"  \033[91m⚠  VULNERABLE: {base_url}\033[0m")
        print(f"     {len(found)} sensitive file(s) exposed:")
        for f in found:
            print(f"     → {f}")
    else:
        print(f"  \033[92m✔  SAFE: {base_url} — No sensitive files found.\033[0m")
    print("─" * 55 + "\n")


# ─────────────────────────────────────────────
# Main Runner
# ─────────────────────────────────────────────

def run(args):
    print_banner()

    paths = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_PATHS
    if not args.wordlist:
        print(f"  [*] Using built-in wordlist: {len(paths)} paths")

    print(f"  [*] Timeout : {args.timeout}s\n")

    urls = load_url_list(args.url_list) if args.url_list else [args.url]
    print(f"  [*] Targets : {len(urls)}\n")
    print("=" * 55)

    all_vulnerable = []

    for url in urls:
        base_url = normalize_url(url)
        print(f"\n  [→] Scanning: {base_url}")
        print("─" * 55)
        found = scan_target(base_url, paths, args.timeout)
        print_target_summary(base_url, found)
        if found:
            all_vulnerable.append(base_url)

    # Final summary for multi-target scans
    if len(urls) > 1:
        print("=" * 55)
        print("  FINAL SUMMARY")
        print("=" * 55)
        print(f"  Total targets scanned : {len(urls)}")
        print(f"  Vulnerable targets    : \033[91m{len(all_vulnerable)}\033[0m")
        print(f"  Clean targets         : \033[92m{len(urls) - len(all_vulnerable)}\033[0m")
        if all_vulnerable:
            print("\n  \033[91mVulnerable targets:\033[0m")
            for v in all_vulnerable:
                print(f"    ⚠  {v}")
        print("=" * 55 + "\n")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sensitive File Disclosure Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  Stage 1 — single URL, built-in paths:
    python sfd_scanner.py -u http://example.com

  Stage 2 — single URL, custom wordlist:
    python sfd_scanner.py -u http://example.com -w paths.txt

  Stage 3 — multiple URLs, custom wordlist:
    python sfd_scanner.py -U targets.txt -w paths.txt

  Stage 3 — multiple URLs, built-in paths:
    python sfd_scanner.py -U targets.txt
        """
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-u", "--url",      help="Single target URL")
    target_group.add_argument("-U", "--url-list", help="File with list of target URLs (one per line)")

    parser.add_argument("-w", "--wordlist", help="Custom wordlist file of paths (one per line)")
    parser.add_argument("-t", "--timeout",  type=int, default=10, help="Request timeout in seconds (default: 10)")

    args = parser.parse_args()
    run(args)
