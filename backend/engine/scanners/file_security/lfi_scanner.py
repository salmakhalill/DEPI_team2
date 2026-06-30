import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager
from engine.analyzer.response_analyzer import ResponseAnalyzer

class LFIScanner(BaseScanner):
    STATIC_EXTENSIONS = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot')

    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        payload_data = PayloadManager.get_payloads("lfi")
        lfi_cases = payload_data.get("cases", []) if isinstance(payload_data, dict) else payload_data

        if not lfi_cases: return findings

        scanned_patterns = set()

        if self.log_callback:
            self.log_callback("[*] [LFI Scanner] Running dynamic LFI scan module.")

        for ep in endpoints:
            if ep.method != "GET" or ep.url.lower().endswith(self.STATIC_EXTENSIONS): continue

            structural_url = re.sub(r'/\d+', '/[ID]', ep.url)
            pattern_key = f"{ep.method}:{structural_url}"
            if pattern_key in scanned_patterns: continue
            scanned_patterns.add(pattern_key)

            baseline_response = await self.client.request(method='GET', url=ep.url, follow_redirects=True)
            baseline_text = baseline_response.text if baseline_response.success else ""

            ep_param_names = [p.name for p in ep.params]
            if not ep_param_names:
                continue

            for param in ep_param_names:
                is_vulnerable_param = False

                for case in lfi_cases:
                    payload, severity, cvss_score = case.get("payload", ""), case.get("severity", "High"), case.get("cvss", "7.5")
                    compiled_regex = case.get("compiled_regex")
                    if not compiled_regex: continue

                    separator = "&" if "?" in ep.url else "?"
                    target_url = f"{ep.url}{separator}{param}={payload}"
                    
                    response = await self.client.request(method='GET', url=target_url, follow_redirects=True)

                    if response.success and response.status_code == 200:
                        match = ResponseAnalyzer.has_new_signature(baseline_text, response.text, compiled_regex)
                        
                        if match:
                            is_vulnerable_param = True
                            matched_text = match.group(0)

                        if is_vulnerable_param:
                            findings.append(Finding(
                                title="Local File Inclusion (LFI)",
                                owasp_category="A01:2021 - Broken Access Control",
                                threat_level=severity, cvss_score=cvss_score,
                                affected_path=f"GET {ep.url} [Param: {param}]",
                                description=case.get("description", "LFI Vulnerability detected."),
                                business_impact="Remote attackers can extract critical system files.",
                                recommendations=["Maintain an explicit allow-list of valid template names."],
                                references=["https://cwe.mitre.org/data/definitions/98.html"],
                                proof_of_concept=ProofOfConcept(
                                    intro_text=f"Injecting traversal sequences into parameter '{param}' extracted sensitive file contexts.",
                                    steps_to_reproduce=[f"1. Target endpoint: {ep.url}", f"2. Inject payload: {payload}"],
                                    evidence=Evidence(type="http_snippet", request=f"GET {target_url} HTTP/1.1", response=f"HTTP/1.1 200 OK\n\n[!] Confirmed Leak: {matched_text}")
                                )
                            ))
                            if self.log_callback: self.log_callback(f"[!] LFI Confirmed. Target: {ep.url} | Param: '{param}'")
                            break 
                if is_vulnerable_param: break
        return findings