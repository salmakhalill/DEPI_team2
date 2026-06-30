import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager
from engine.analyzer.response_analyzer import ResponseAnalyzer

class PathTraversalScanner(BaseScanner):
    STATIC_EXTENSIONS = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.woff', '.woff2', '.ttf', '.eot')

    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        payload_data = PayloadManager.get_payloads("path_traversal")
        pt_cases = payload_data.get("cases", []) if isinstance(payload_data, dict) else payload_data

        if not pt_cases: return findings

        scanned_patterns = set()

        if self.log_callback:
            self.log_callback("[*] [Path Traversal Scanner] Executing analysis.")

        for ep in endpoints:
            if ep.method not in ["GET", "POST"] or ep.url.lower().endswith(self.STATIC_EXTENSIONS): continue

            structural_url = re.sub(r'/\d+', '/[ID]', ep.url)
            pattern_key = f"{ep.method}:{structural_url}"
            if pattern_key in scanned_patterns: continue
            scanned_patterns.add(pattern_key)

            baseline_response = await self.client.request(method=ep.method, url=ep.url, follow_redirects=True)
            baseline_text = baseline_response.text if baseline_response.success else ""

            ep_param_names = [p.name for p in ep.params]
            if not ep_param_names:
                continue

            for param in ep_param_names:
                is_vulnerable_param = False

                for case in pt_cases:
                    payload, severity, cvss_score = case.get("payload", ""), case.get("severity", "High"), case.get("cvss", "7.5")
                    compiled_regex = case.get("compiled_regex")
                    if not compiled_regex: continue

                    if ep.method == "GET":
                        separator = "&" if "?" in ep.url else "?"
                        target_url = f"{ep.url}{separator}{param}={payload}"
                        response = await self.client.request(method='GET', url=target_url, follow_redirects=True)
                        req_evidence = f"GET {target_url} HTTP/1.1"
                    else:
                        target_url, test_params = ep.url, {p_name: "1" for p_name in ep_param_names}
                        test_params[param] = payload
                        response = await self.client.request(method='POST', url=target_url, data=test_params, follow_redirects=True)
                        req_evidence = f"POST {target_url} HTTP/1.1\n\n{param}={payload}"

                    if response.success and response.status_code == 200:
                        match = ResponseAnalyzer.has_new_signature(baseline_text, response.text, compiled_regex)
                        
                        if match:
                            is_vulnerable_param = True
                            matched_text = match.group(0)

                        if is_vulnerable_param:
                            findings.append(Finding(
                                title="Path Traversal (Arbitrary File Read)",
                                owasp_category="A01:2021 - Broken Access Control",
                                threat_level=severity, cvss_score=cvss_score,
                                affected_path=f"{ep.method} {ep.url} [Param: {param}]",
                                description=case.get("description", "Path Traversal detected."),
                                business_impact="Attackers can read arbitrary files on the server.",
                                recommendations=["Resolve requested paths and verify containment."],
                                references=["https://cwe.mitre.org/data/definitions/22.html"],
                                proof_of_concept=ProofOfConcept(
                                    intro_text=f"Injecting traversal sequences into '{param}' escaped the intended bounds.",
                                    steps_to_reproduce=[f"1. Target: {ep.url}", f"2. Inject payload: {payload}"],
                                    evidence=Evidence(type="http_snippet", request=req_evidence, response=f"HTTP/1.1 200 OK\n\n[!] Match: {matched_text}")
                                )
                            ))
                            if self.log_callback: self.log_callback(f"[!] Path Traversal Confirmed. Target: {ep.url} | Param: '{param}'")
                            break 
                if is_vulnerable_param: break
        return findings