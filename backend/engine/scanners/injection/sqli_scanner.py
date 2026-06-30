import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class SQLInjectionScanner(BaseScanner):
    
    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        # Load centralized SQLi payload cases and mapping regex signatures
        sqli_cases = PayloadManager.get_payloads("sqli")
        
        print(f"  [SQLi Scanner] Assessing attack surface logic across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"⚔️ [SQLi Scanner] Assessing attack surface logic across {len(endpoints)} targets...")

        for ep in endpoints:
            # SQLi typically maps to input variables passed via parameters
            if ep.params:
                for param in ep.params:
                    for case in sqli_cases:
                        payload = case["payload"]
                        regex_pattern = case["match_regex"]
                        
                        # Reconstruct the attack query array state
                        test_params = {p: "1" for p in ep.params}
                        test_params[param] = payload

                        # Execute network tracking probe request via SafeHttpClient
                        if ep.method == "GET":
                            response = self.client.get(ep.url, params=test_params)
                        else:
                            response = self.client.post(ep.url, data=test_params)

                        if response.success:
                            # Apply the specific regex signature checking to the raw HTML text body
                            match = re.search(regex_pattern, response.text)
                            
                            if match:
                                # Local terminal print
                                print(f"  [!] SQL Injection Confirmed! Target: {ep.url} | Param: '{param}'")
                                
                                # WebSocket Live Broadcast for a discovered Vulnerability!
                                if self.log_callback:
                                    self.log_callback(f"🔥 [VULN] SQL Injection Confirmed! Target: {ep.url} | Param: '{param}'")
                                
                                finding = Finding(
                                    title=f"SQL Injection (SQLi)",
                                    owasp_category="A03:2021 - Injection",
                                    threat_level="Critical",
                                    cvss_score="9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                                    affected_path=f"{ep.method} {ep.url}",
                                    description=f"The endpoint dynamically concatenates raw user inputs into internal SQL command tracking blocks via parameter '{param}'. The system responded with a database footprint matching signature pattern: {regex_pattern}",
                                    business_impact="An unauthenticated or low-privilege attacker can completely bypass structural storage data tables encryption layers, leaking enterprise secrets, administrative credentials, and business operational source structures.",
                                    recommendations=[
                                        "Implement strictly structured parameterized query logic using Object Relational Mapping templates (SQLAlchemy ORM models).",
                                        "Sanitize and strip downstream special string notations from active application fields dynamically."
                                    ],
                                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                                    proof_of_concept=ProofOfConcept(
                                        intro_text=f"Injecting a targeted payload input character string into the active input variable vector parameter '{param}' triggered an immediate unhandled backend SQL operational structural execution.",
                                        steps_to_reproduce=[
                                            f"1. Target the identified verification node path endpoint: {ep.url}",
                                            f"2. Inject malicious raw character payload format inside target element variable: ?{param}={payload}",
                                            "3. Verify data response tables contents leakage signature reflection."
                                        ],
                                        evidence=Evidence(
                                            type="http_snippet",
                                            request=f"{ep.method} {ep.url}?{param}={payload} HTTP/1.1\nHost: target",
                                            response=f"HTTP/1.1 {response.status_code}\n\nMatched Database Footprint Signature Error: {match.group(0)}"
                                        )
                                    )
                                )
                                findings.append(finding)
                                # Vulnerability validated for this node parameter; advance loop tracking
                                break 
                        
        return findings