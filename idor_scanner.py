import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class IDORScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        idor_cases = PayloadManager.get_payloads("idor")

        print(f"  [IDOR Scanner] Assessing access control logic across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"[IDOR Scanner] Assessing access control logic across {len(endpoints)} targets...")

        for ep in endpoints:
            if ep.method != "GET":
                continue

            for case in idor_cases:
                test_id = case["payload"]
                target_url = None
                vuln_context = None

                if "profile" in ep.url or "users" in ep.url:
                    target_url = re.sub(r'(/(?:profile|users)/)\d+', f"\\1{test_id}", ep.url)
                    vuln_context = "profile"
                elif "documents" in ep.url:
                    target_url = re.sub(r'(/documents/)\d+', f"\\1{test_id}", ep.url)
                    vuln_context = "document"
                elif "messages" in ep.url:
                    target_url = re.sub(r'(/messages/)\d+', f"\\1{test_id}", ep.url)
                    vuln_context = "message"

                if not target_url or target_url == ep.url:
                    continue

                try:
                    response = self.client.get(target_url)

                    if response.success and response.status_code == 200:

                        if vuln_context == "profile" and not ("api_key" in response.text or "email" in response.text):
                            continue

                        print(f"  [!] IDOR Confirmed! Target: {target_url}")
                        if self.log_callback:
                            self.log_callback(f"[VULN] IDOR Leak Confirmed! Target: {target_url}")

                        title = "Insecure Direct Object Reference (IDOR) - User Profile Exposure" if vuln_context == "profile" else \
                                "Insecure Direct Object Reference (IDOR) - Private Document Access" if vuln_context == "document" else \
                                "Insecure Direct Object Reference (IDOR) - Private Message Access"

                        threat_level = "Medium" if vuln_context == "message" else "High"
                        cvss_score = "8.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)" if vuln_context == "profile" else \
                                     "7.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)" if vuln_context == "document" else \
                                     "6.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)"

                        description = f"The application endpoint dynamic parameters do not validate authorization bounds for object path identifier '{test_id}'. Authenticated users can fetch resource arrays belonging to other user entities directly."

                        business_impact = "An authenticated attacker can extract sensitive internal infrastructure keys, operational production values, confidential client documents, or private communications between organization nodes."

                        recommendations = [
                            "Implement centralized server-side validation verifying that the requesting session identity owns or has explicit relationship mapping records for the target object sequence key.",
                            "Utilize non-enumerable cryptographic hashes or UUIDv4 sequences instead of predictable database auto-increment keys."
                        ]

                        finding = Finding(
                            title=title,
                            owasp_category="A01:2021 - Broken Access Control",
                            threat_level=threat_level,
                            cvss_score=cvss_score,
                            affected_path=f"GET {target_url}",
                            description=description,
                            business_impact=business_impact,
                            recommendations=recommendations,
                            references=["https://owasp.org/www-project-top-ten/2021/A01_2021-Broken_Access_Control"],
                            proof_of_concept=ProofOfConcept(
                                intro_text=f"Altering the sequential reference parameter index directly inside the target locator path to '{test_id}' bypassed authentication validation checks.",
                                steps_to_reproduce=[
                                    "1. Establish an active session using low-privileged validation structures.",
                                    f"2. Modify the target resource parameter address context directly to: {target_url}",
                                    "3. Review the structural response body to confirm content disclosure leakage."
                                ],
                                evidence=Evidence(
                                    type="http_snippet",
                                    request=f"GET {target_url} HTTP/1.1\nHost: target",
                                    response=f"HTTP/1.1 200 OK\nLength: {len(response.text)}\n\n{response.text[:200]}... [Truncated]"
                                )
                            )
                        )
                        findings.append(finding)
                        break

                except Exception as e:
                    if self.log_callback:
                        self.log_callback(f"[IDOR Scanner Error] Failed to scan {target_url}: {str(e)}")
                    continue

        return findings
