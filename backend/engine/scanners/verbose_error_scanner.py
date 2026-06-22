import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


class VerboseErrorScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        cases = PayloadManager.get_payloads("verbose_error")

        for ep in endpoints:
            if ep.method == "GET" and ep.params:
                for param in ep.params:

                    for case in cases:
                        payload = case["payload"]
                        regex_pattern = case["match_regex"]

                        test_params = {p: "test" for p in ep.params}
                        test_params[param] = payload

                        response = self.client.get(ep.url, params=test_params)

                        if response.success:
                            match = re.search(regex_pattern, response.text, re.IGNORECASE)

                            if match:
                                print(f"  [!] Verbose Error Disclosure Confirmed at {ep.url}?{param}=")

                                finding = Finding(
                                    title=f"Verbose Error Disclosure in '{param}'",
                                    owasp_category="A05:2021 - Security Misconfiguration",
                                    threat_level="Low",
                                    cvss_score="4.3",
                                    affected_path=ep.url,
                                    description=f"The parameter '{param}' triggers a raw backend error message that reveals internal implementation details (e.g. database type, query structure, or file paths).",
                                    business_impact="Attackers can use the leaked technical details to craft more precise attacks, such as SQL Injection, and gain insight into the application's internal architecture.",
                                    recommendations=["Disable debug mode in production.", "Use generic error pages instead of raw stack traces.", "Log detailed errors server-side only, never expose them to the client."],
                                    references=["OWASP Error Handling Cheat Sheet"],
                                    proof_of_concept=ProofOfConcept(
                                        intro_text=f"Sent payload '{payload}' in parameter '{param}', server responded with a verbose internal error.",
                                        steps_to_reproduce=[f"Inject {payload} in parameter '{param}'"],
                                        evidence=Evidence(
                                            request=f"GET {ep.url}?{param}={payload}",
                                            response=f"Matched Pattern: {match.group(0)}"
                                        )
                                    )
                                )
                                findings.append(finding)
                                break

        return findings