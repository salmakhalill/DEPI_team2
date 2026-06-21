import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class SQLInjectionScanner(BaseScanner):
    
    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        # 1. Load payloads and regex rules from JSON
        sqli_cases = PayloadManager.get_payloads("sqli")

        for ep in endpoints:
            if ep.method == "GET" and ep.params:
                for param in ep.params:
                    
                    # 2. Loop through every test case in the JSON
                    for case in sqli_cases:
                        payload = case["payload"]
                        regex_pattern = case["match_regex"]
                        
                        test_params = {p: "1" for p in ep.params}
                        test_params[param] = payload

                        response = self.client.get(ep.url, params=test_params)

                        # 3. Use regex to verify if the vulnerability exists
                        if response.success:
                            # Search for the regex pattern in the response text
                            match = re.search(regex_pattern, response.text)
                            
                            if match:
                                print(f"  [!] SQLi Confirmed at {ep.url}?{param}= using regex '{regex_pattern}'")
                                
                                finding = Finding(
                                    title=f"SQL Injection (Error Based) in '{param}'",
                                    owasp_category="A03:2021 - Injection",
                                    threat_level="Critical",
                                    cvss_score="8.9",
                                    affected_path=ep.url,
                                    description=f"The parameter '{param}' is vulnerable. The database returned an error matching the regex: {regex_pattern}",
                                    business_impact="Attacker can dump the entire database, including passwords and API keys.",
                                    recommendations=["Use parameterized queries (SQLAlchemy ORM).", "Never use raw f-strings for SQL."],
                                    references=["OWASP SQLi Prevention"],
                                    proof_of_concept=ProofOfConcept(
                                        intro_text=f"Sent payload '{payload}', server responded with a database error.",
                                        steps_to_reproduce=[f"Inject {payload} in {param}"],
                                        evidence=Evidence(
                                            request=f"GET {ep.url}?{param}={payload}",
                                            # We can even save the exact regex match as evidence!
                                            response=f"Matched Error: {match.group(0)}"
                                        )
                                    )
                                )
                                findings.append(finding)
                                break # Stop testing this parameter if we already found an SQLi
                        
        return findings