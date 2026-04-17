#!/usr/bin/env python3
"""
Sensitive File Disclosure Scanner - Stage 1
Fuzzes 20 common paths on a target URL and reports exposed sensitive files.
"""

import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────
# 20 Common Sensitive Paths
# ─────────────────────────────────────────────

PATHS = [
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
# Scanner
# ─────────────────────────────────────────────

def scan(base_url: str, timeout: int = 10):
    base_url = base_url.rstrip("/")
    if not base_url.startswith("http"):
        base_url = "http://" + base_url

    print("""
╔══════════════════════════════════════════════╗
║     Sensitive File Disclosure Scanner       ║
║              Stage 1 - Basic                ║
╚══════════════════════════════════════════════╝
""")
    print(f"  Target  : {base_url}")
    print(f"  Paths   : {len(PATHS)}")
    print(f"  Timeout : {timeout}s\n")
    print("  [*] Scanning...\n")

    found = []

    for path in PATHS:
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

    print("\n" + "─" * 50)
    if found:
        print(f"  \033[91m⚠  RESULT: VULNERABLE — {len(found)} sensitive file(s) exposed!\033[0m")
        for f in found:
            print(f"     → {f}")
    else:
        print("  \033[92m✔  RESULT: No sensitive files found.\033[0m")
    print("─" * 50 + "\n")


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sfd_scanner.py <url> [timeout]")
        print("Example: python sfd_scanner.py http://testphp.vulnweb.com")
        sys.exit(1)

    url = sys.argv[1]
    timeout = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    scan(url, timeout)
