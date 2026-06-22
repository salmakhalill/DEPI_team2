import re
import time
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


class RateLimitScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        cases = PayloadManager.get_payloads("rate_limit")

        for ep in endpoints:
            if ep.method == "POST" and "login" in ep.url.lower():

                for case in cases:
                    payload = case["payload"]
                    regex_pattern = case["match_regex"]

                    attempt_count = 10
                    successful_attempts = 0

                    for i in range(attempt_count):
                        test_data = {"username": "admin", "password": payload}
                        response = self.client.post(ep.url, data=test_data)

                        if response.success:
                            match = re.search(regex_pattern, response.text, re.IGNORECASE)
                            if match and response.status_code == 200:
                                successful_attempts += 1

                    if successful_attempts == attempt_count:
                        print(f"  [!] Missing Rate Limiting Confirmed at {ep.url}")

                        finding = Finding(
                            title="Missing Rate Limiting on Login Endpoint",
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            threat_level="Medium",
                            cvss_score="5.3",
                            affected_path=ep.url,
                            description=f"The login endpoint accepted {attempt_count} consecutive failed login attempts without any throttling, CAPTCHA, or account lockout mechanism.",
                            business_impact="Attackers can perform brute-force or credential-stuffing attacks against user accounts without restriction.",
                            recommendations=["Implement account lockout after N failed attempts.", "Add CAPTCHA or progressive delays on repeated failures.", "Use rate limiting middleware (e.g. Flask-Limiter)."],
                            references=["OWASP Authentication Cheat Sheet"],
                            proof_of_concept=ProofOfConcept(
                                intro_text=f"Sent {attempt_count} consecutive POST requests with invalid credentials, all were processed normally with no blocking.",
                                steps_to_reproduce=[f"Send {attempt_count}+ POST requests to {ep.url} with invalid passwords in rapid succession."],
                                evidence=Evidence(
                                    request=f"POST {ep.url} (x{attempt_count})",
                                    response=f"All {successful_attempts} attempts returned normal 'invalid credentials' response."
                                )
                            )
                        )
                        findings.append(finding)

        return findings