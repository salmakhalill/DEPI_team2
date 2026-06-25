import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class SensitiveFileDisclosureScanner(BaseScanner):
    
    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        sfd_cases = PayloadManager.get_payloads("sfd")
        
        print(f"  [SFD Scanner] Assessing sensitive file exposure across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f" [SFD Scanner] Assessing sensitive file exposure across {len(endpoints)} targets...")

        for ep in endpoints:
            for case in sfd_cases:
                payload_path = case["payload"]
                target_url = f"{ep.url.rstrip('/')}{payload_path}"
                
                try:
                    response = self.client.get(target_url)
                    
                    if response.success and response.status_code == 200 and len(response.text) > 0:
                        print(f"  [!] Exposed File Confirmed! Target: {target_url}")
                        
                        if self.log_callback:
                            self.log_callback(f" [VULN] Sensitive File Exposed! Target: {target_url}")
                        
                        finding = Finding(
                            title="Sensitive File Disclosure / Information Exposure",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            threat_level="High",
                            cvss_score="7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                            affected_path=f"GET {target_url}",
                            description=f"The application web root or structural directories expose sensitive configurations or backup files. Accessing the path '{payload_path}' returned an active production footprint with raw file contents.",
                            business_impact="An unauthenticated remote attacker can download configuration files, environmental variables (.env), database backups, or source logic, leading to complete credential extraction and structural exposure.",
                            recommendations=[
                                "Restrict public access to administrative or backup extensions inside server infrastructure rules (e.g., Nginx/Apache configuration).",
                                "Remove production environment configuration snapshots, deployment files (.git), and local backups from public web directories."
                            ],
                            references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                            proof_of_concept=ProofOfConcept(
                                intro_text=f"Directly pointing the browser context to the exposed asset tracking path '{payload_path}' permitted unauthorized reading of sensitive internal configuration arrays.",
                                steps_to_reproduce=[
                                    f"1. Target the application host environment layout node: {ep.url}",
                                    f"2. Force directory navigation traversal to the target file context: {target_url}",
                                    "3. Inspect the returned context to verify structural environment leakage."
                                ],
                                evidence=Evidence(
                                    type="http_snippet",
                                    request=f"GET {target_url} HTTP/1.1\nHost: target",
                                    response=f"HTTP/1.1 200 OK\nContent-Length: {len(response.text)}\n\n{response.text[:200]}... [Truncated]"
                                )
                            )
                        )
                        findings.append(finding)
                        
                except Exception as e:
                    if self.log_callback:
                        self.log_callback(f" [SFD Scanner Error] Failed to scan {target_url}: {str(e)}")
                    continue
                    
        return findings
