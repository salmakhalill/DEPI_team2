from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding
from engine.payloads.payload_manager import PayloadManager

from .checks.rate_limit import check_rate_limit
from .checks.weak_password import check_weak_password
from .checks.session import check_session_flags

class AuthScanner(BaseScanner):
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        
        auth_config = PayloadManager.get_payloads("authentication")
        if not auth_config:
            return findings

        rl_config = auth_config.get("rate_limit", {})
        pw_cases = auth_config.get("weak_password", {}).get("cases", [])
        session_config = auth_config.get("session", {})
        
        scanned_login_urls = set()
        scanned_register_urls = set()
        session_tested = False

        login_keywords = ["login", "signin", "auth", "token"]
        register_keywords = ["register", "signup"]

        if self.log_callback:
            self.log_callback(f"[*] [Auth Orchestrator] Auditing authentication matrix across {len(endpoints)} targets.")

        for ep in endpoints:
            url_lower = ep.url.lower()
            is_login = any(kw in url_lower for kw in login_keywords)
            is_register = any(kw in url_lower for kw in register_keywords)

            if not (is_login or is_register):
                continue

            if not session_tested:
                session_finding, cookie_issued = await check_session_flags(self.client, ep, session_config, self.log_callback)
                if session_finding:
                    findings.append(session_finding)
                    if self.log_callback: 
                        self.log_callback(f"[!] Weak Session Configuration Discovered: {ep.url}")
                
                if cookie_issued:
                    session_tested = True

            if is_login and ep.url not in scanned_login_urls:
                scanned_login_urls.add(ep.url)
                rl_finding = await check_rate_limit(self.client, ep, rl_config, self.log_callback)
                if rl_finding:
                    findings.append(rl_finding)
                    if self.log_callback: 
                        self.log_callback(f"[!] Missing Rate Limiting Confirmed: {ep.url}")

            if is_register and ep.url not in scanned_register_urls:
                scanned_register_urls.add(ep.url)
                pw_findings = await check_weak_password(self.client, ep, pw_cases, self.log_callback)
                if pw_findings:
                    findings.extend(pw_findings)
                    if self.log_callback: 
                        self.log_callback(f"[!] Weak Password Policy Confirmed: {ep.url}")

        return findings