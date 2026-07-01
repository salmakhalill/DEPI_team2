import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class IDORScanner(BaseScanner):
    
    # تحويل الـ Method لـ async لتتوافق مع الـ base_scanner وتمنع الـ Crash
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        # Load centralized IDOR payload cases and mapping regex signatures
        idor_cases = PayloadManager.get_payloads("idor")
        
        print(f"  [IDOR Scanner] Assessing authorization bounds across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"🛡️ [IDOR Scanner] Assessing authorization bounds across {len(endpoints)} targets...")

        for ep in endpoints:
            # 1. Test RESTful Path IDs (e.g., /api/v1/users/1)
            path_id_match = re.search(r'/(\d+)(/|$|\?)', ep.url)
            
            if path_id_match:
                original_id = int(path_id_match.group(1))
                
                for case in idor_cases:
                    payload_modifier = case["payload"]
                    regex_pattern = case["match_regex"]
                    
                    test_id = original_id + payload_modifier
                    if test_id <= 0:
                        continue
                        
                    # Substitute the original ID with the manipulated test_id in the URL
                    test_url = re.sub(rf'/({original_id})(/|$|\?)', f'/{test_id}\\2', ep.url)
                    
                    # استخدام await هنا لأن الـ Client يعمل بشكل asynchronous
                    if ep.method == "GET":
                        response = await self.client.get(test_url)
                    else:
                        response = await self.client.post(test_url, data={})

                    if response and response.success:
                        match = re.search(regex_pattern, response.text)
                        
                        if match:
                            self._notify_finding(ep.url, test_url)
                            finding = self._build_finding(ep, test_url, "REST Path", str(test_id), regex_pattern, match.group(0))
                            findings.append(finding)
                            break  # Vulnerability validated; move to next endpoint

            # 2. Test Parameter IDs (e.g., ?user_id=1)
            if ep.params:
                for param in ep.params:
                    # Filter for parameters that typically act as identifiers
                    if any(keyword in param.lower() for keyword in ["id", "user", "doc", "msg", "profile"]):
                        for case in idor_cases:
                            payload_modifier = case["payload"]
                            regex_pattern = case["match_regex"]
                            
                            test_params = {p: "1" for p in ep.params}
                            test_params[param] = str(1 + payload_modifier)

                            # استخدام await لطلبات الـ HTTP المتزامنة
                            if ep.method == "GET":
                                response = await self.client.get(ep.url, params=test_params)
                            else:
                                response = await self.client.post(ep.url, data=test_params)

                            if response and response.success:
                                match = re.search(regex_pattern, response.text)
                                
                                if match:
                                    exploit_url = f"{ep.url}?{param}={test_params[param]}"
                                    self._notify_finding(ep.url, exploit_url)
                                    finding = self._build_finding(ep, exploit_url, f"Parameter '{param}'", test_params[param], regex_pattern, match.group(0))
                                    findings.append(finding)
                                    break
        
        return findings

    def _notify_finding(self, original_url: str, test_url: str):
        print(f"  [!] IDOR Confirmed! Target: {original_url} | Exploit URL: {test_url}")
        if self.log_callback:
            self.log_callback(f"🔓 [VULN] IDOR Confirmed! Exploit URL: {test_url}")

    def _build_finding(self, ep: Endpoint, exploit_url: str, vector_type: str, payload: str, regex_pattern: str, match_text: str) -> Finding:
        return Finding(
            title="Insecure Direct Object Reference (IDOR)",
            owasp_category="A01:2021 - Broken Access Control",
            threat_level="High",
            cvss_score="8.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
            affected_path=f"{ep.method} {ep.url}",
            description=f"The endpoint fails to enforce proper authorization boundary checks on the {vector_type}. By manipulating the object identifier to '{payload}', the system responded with unauthorized data matching signature pattern: {regex_pattern}",
            business_impact="An authenticated attacker can bypass access controls to view, modify, or leak sensitive records belonging to other users, potentially compromising enterprise secrets and personal data.",
            recommendations=[
                "Implement robust authorization checks at the data-access layer ensuring `current_user` has permission to access the requested object.",
                "Replace auto-incrementing integer IDs with unpredictable GUIDs/UUIDs for sensitive database records."
            ],
            references=["https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"],
            proof_of_concept=ProofOfConcept(
                intro_text=f"Manipulating the target identifier in the {vector_type} granted unauthorized cross-tenant read access.",
                steps_to_reproduce=[
                    f"1. Target the identified endpoint: {ep.url}",
                    f"2. Modify the target identifier in the {vector_type} to '{payload}'",
                    "3. Observe that the server returns HTTP 200 OK along with unauthorized sensitive data reflection."
                ],
                evidence=Evidence(
                    type="http_snippet",
                    request=f"{ep.method} {exploit_url} HTTP/1.1\nHost: target",
                    response=f"HTTP/1.1 200 OK\n\nMatched Sensitive Data Footprint: {match_text}"
                )
            )
        )
