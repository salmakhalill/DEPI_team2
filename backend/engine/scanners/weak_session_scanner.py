from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence


class WeakSessionScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []

        for ep in endpoints:
            if ep.method == "POST" and "login" in ep.url.lower():

                test_data = {"username": "admin", "password": "admin123"}
                response = self.client.post(ep.url, data=test_data)

                if not response.success:
                    continue

                set_cookie_header = response.headers.get("Set-Cookie", "")

                missing_flags = []
                if "httponly" not in set_cookie_header.lower():
                    missing_flags.append("HttpOnly")
                if "secure" not in set_cookie_header.lower():
                    missing_flags.append("Secure")

                if missing_flags:
                    print(f"  [!] Weak Session Configuration Confirmed at {ep.url} — Missing: {', '.join(missing_flags)}")

                    finding = Finding(
                        title="Weak Session Cookie Configuration",
                        owasp_category="A05:2021 - Security Misconfiguration",
                        threat_level="Medium",
                        cvss_score="5.4",
                        affected_path=ep.url,
                        description=f"The session cookie issued after login is missing the following security flags: {', '.join(missing_flags)}. This increases the risk of session hijacking.",
                        business_impact="Without HttpOnly, the cookie can be stolen via XSS. Without Secure, the cookie can be intercepted over unencrypted connections, allowing attackers to hijack user sessions.",
                        recommendations=["Set the HttpOnly flag on all session cookies.", "Set the Secure flag to ensure cookies are only sent over HTTPS.", "Consider adding SameSite=Strict or SameSite=Lax."],
                        references=["OWASP Session Management Cheat Sheet"],
                        proof_of_concept=ProofOfConcept(
                            intro_text=f"Logged in via {ep.url} and inspected the Set-Cookie response header.",
                            steps_to_reproduce=[f"Send POST request to {ep.url} with valid credentials and inspect the Set-Cookie header in the response."],
                            evidence=Evidence(
                                request=f"POST {ep.url}",
                                response=f"Set-Cookie: {set_cookie_header} (Missing: {', '.join(missing_flags)})"
                            )
                        )
                    )
                    findings.append(finding)

        return findings