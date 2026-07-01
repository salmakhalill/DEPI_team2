import re, random
from urllib.parse import urlparse
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager
from engine.analyzer.response_analyzer import ResponseAnalyzer 

class SensitiveFileDisclosureScanner(BaseScanner):
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        payload_data = PayloadManager.get_payloads("sensitive_file")
        sfd_cases = payload_data.get("cases", []) if isinstance(payload_data, dict) else payload_data
        
        if not sfd_cases: return findings

        scanned_roots = set()

        if self.log_callback:
            self.log_callback("[*] [SFD Scanner] Hunting for exposed files using dynamic signatures.")

        for ep in endpoints:
            parsed_url = urlparse(ep.url)
            base_root = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            if base_root in scanned_roots: continue
            scanned_roots.add(base_root)
            
            baseline_resp = await self.client.request('GET', f"{base_root}/nexus_not_found_{random.randint(100,999)}", follow_redirects=False)
            baseline_text = baseline_resp.text if baseline_resp.success else ""

            for case in sfd_cases:
                payload_path = case.get("payload", "")
                if not payload_path.startswith('/'): payload_path = '/' + payload_path
                target_url = f"{base_root}{payload_path}"
                
                response = await self.client.request('GET', target_url, follow_redirects=False)
                
                if response.success and response.status_code == 200 and len(response.text) > 0:
                    is_vulnerable = False
                    matched_secret = None

                    compiled_signatures = case.get("compiled_signatures", [])
                    for compiled_regex in compiled_signatures:
                        match = ResponseAnalyzer.has_new_signature(baseline_text, response.text, compiled_regex)
                        if match:
                            is_vulnerable = True
                            matched_secret = match.group(0)
                            break

                    if is_vulnerable:
                        findings.append(Finding(
                            title="Sensitive File Disclosure",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            threat_level=case.get("severity", "High"), cvss_score=case.get("cvss", "7.5"),
                            affected_path=f"GET {target_url}",
                            description=f"The application exposes a sensitive file at '{payload_path}'.",
                            business_impact="Unauthenticated attackers can download infrastructure files.",
                            recommendations=["Remove local backups from public web directories."],
                            references=["https://owasp.org/www-project-top-ten/2021/A05_2021-Security_Misconfiguration"],
                            proof_of_concept=ProofOfConcept(
                                intro_text=f"Direct GET request to '{payload_path}' permitted unauthorized reading.",
                                steps_to_reproduce=[f"1. Target domain: {base_root}", f"2. Issue GET to: {target_url}"],
                                evidence=Evidence(type="http_snippet", request=f"GET {target_url} HTTP/1.1", response=f"HTTP/1.1 200 OK\n\n[!] Signature Matched: {matched_secret}")
                            )
                        ))
                        if self.log_callback: self.log_callback(f"[!] SFD Confirmed. Target: {target_url}")
                        break
        return findings
