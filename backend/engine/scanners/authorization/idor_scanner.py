import re
from typing import List, Dict, Optional, Any
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class IDORScanner(BaseScanner):
    """
    Advanced asynchronous scanner for BOLA/IDOR.
    Implements Baseline Variance Analysis, Message Heuristics, and Findings Aggregation.
    """
    
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        raw_findings: List[Finding] = []
        
        # Load payloads 
        raw_cases = PayloadManager.get_payloads("idor")
        idor_cases = raw_cases.get("cases", raw_cases) if isinstance(raw_cases, dict) else raw_cases
        
        if not idor_cases:
            print("  [-] [IDOR Scanner] Payload configuration missing. Aborting.")
            return []

        print(f"  [IDOR/BOLA Scanner] Executing Variance Analysis across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"🛡️ [IDOR Scanner] Executing Variance Analysis across {len(endpoints)} targets...")

        # 1. Collect all individual vulnerabilities
        for ep in endpoints:
            path_finding = await self._test_restful_paths(ep, idor_cases)
            if path_finding:
                raw_findings.append(path_finding)
                continue  

            if ep.params:
                param_finding = await self._test_parameters(ep, idor_cases)
                if param_finding:
                    raw_findings.append(param_finding)
        
        # ---------------------------------------------------------------------
        # [NEW]: Vulnerability Aggregation (Merge Findings)
        # ---------------------------------------------------------------------
        if not raw_findings:
            return [] # No vulnerabilities found
            
        # Extract unique affected paths from all findings to avoid duplicates
        unique_paths = list(set([f.affected_path for f in raw_findings]))
        
        # Join them with a newline and bullet points or just commas (newline is best for tables)
        merged_paths_string = "\n".join(unique_paths)
        
        # Use the first finding as the base template for the final report
        merged_finding = raw_findings[0]
        
        # Inject the merged paths into the affected_path field
        merged_finding.affected_path = merged_paths_string
        
        # Update the description to highlight that it's a widespread issue
        merged_finding.description = f"Multiple BOLA/IDOR vulnerabilities detected across {len(unique_paths)} endpoints. " + merged_finding.description
        
        # Clarify in the PoC that this is just one example of the many found
        merged_finding.proof_of_concept.intro_text += f" (Note: This is a representative example. The vulnerability exists across {len(unique_paths)} distinct endpoints)."
        
        # Return as a single finding so it generates only ONE table in the report
        return [merged_finding]

    # -------------------------------------------------------------------------
    # Core Logic Handlers
    # -------------------------------------------------------------------------

    async def _test_restful_paths(self, ep: Endpoint, cases: List[Dict]) -> Optional[Finding]:
        path_id_match = re.search(r'/([^v]\w*/)?(\d+)(/|$|\?)', ep.url)
        if not path_id_match:
            return None
            
        original_id = int(path_id_match.group(2))
        
        baseline_response = await self._safe_request(ep.method, ep.url)
        baseline_text = getattr(baseline_response, 'text', '') if baseline_response and baseline_response.success else ''

        for case in cases:
            test_id = original_id + case["payload"]
            if test_id <= 0:
                continue
                
            test_url = re.sub(rf'/({original_id})(/|$|\?)', f'/{test_id}\\2', ep.url)
            response = await self._safe_request(ep.method, test_url)

            if response and response.success and getattr(response, 'text', None):
                is_vuln, match_preview = self._analyze_variance(ep.url, baseline_text, response.text, case["match_regex"])
                
                if is_vuln:
                    self._notify_finding(ep.url, test_url)
                    return self._build_finding(ep, test_url, "REST Path", str(test_id), case["match_regex"], match_preview)
        return None

    async def _test_parameters(self, ep: Endpoint, cases: List[Dict]) -> Optional[Finding]:
        for p in ep.params:
            param_name = p.name if hasattr(p, 'name') else str(p)
            
            if not self._is_target_parameter(param_name):
                continue
                
            baseline_params = {param.name if hasattr(param, 'name') else str(param): "1" for param in ep.params}
            baseline_response = await self._safe_request(ep.method, ep.url, params_or_data=baseline_params)
            baseline_text = getattr(baseline_response, 'text', '') if baseline_response and baseline_response.success else ''

            for case in cases:
                test_params = baseline_params.copy()
                test_params[param_name] = str(1 + case["payload"])

                response = await self._safe_request(ep.method, ep.url, params_or_data=test_params)

                if response and response.success and getattr(response, 'text', None):
                    is_vuln, match_preview = self._analyze_variance(ep.url, baseline_text, response.text, case["match_regex"])
                    
                    if is_vuln:
                        exploit_url = f"{ep.url}?{param_name}={test_params[param_name]}"
                        self._notify_finding(ep.url, exploit_url)
                        return self._build_finding(ep, exploit_url, f"Parameter '{param_name}'", test_params[param_name], case["match_regex"], match_preview)
        return None

    # -------------------------------------------------------------------------
    # Helper Utilities & Heuristics
    # -------------------------------------------------------------------------

    def _analyze_variance(self, url: str, baseline_text: str, exploit_text: str, regex_pattern: str) -> tuple:
        if baseline_text == exploit_text:
            return False, ""

        match = re.search(regex_pattern, exploit_text)
        if match:
            return True, match.group(0)

        url_lower = url.lower()
        if any(keyword in url_lower for keyword in ["message", "chat", "inbox"]):
            length_diff = abs(len(exploit_text) - len(baseline_text))
            if length_diff > 5:
                return True, "[Heuristic Match] Unauthorized message content reflected."

        return False, ""

    def _is_target_parameter(self, param_name: str) -> bool:
        keywords = {"id", "user", "doc", "msg", "profile", "account", "uuid"}
        return any(keyword in param_name.lower() for keyword in keywords)

    async def _safe_request(self, method: str, url: str, params_or_data: Dict[str, Any] = None):
        params_or_data = params_or_data or {}
        try:
            method = method.upper()
            if method == "GET":
                return await self.client.request(method, url, params=params_or_data)
            else:
                return await self.client.request(method, url, data=params_or_data)
        except Exception as e:
            print(f"  [-] Network exception during BOLA probe on {url}: {str(e)}")
            return None

    def _notify_finding(self, original_url: str, test_url: str):
        # We still print each individual finding to the console so the user sees the scanner working
        print(f"  [!] BOLA/IDOR Confirmed! Target: {original_url} | Exploit URL: {test_url}")
        if self.log_callback:
            self.log_callback(f"🔓 [VULN] BOLA/IDOR Confirmed! Exploit URL: {test_url}")

    def _build_finding(self, ep: Endpoint, exploit_url: str, vector_type: str, payload: str, regex_pattern: str, match_preview: str) -> Finding:
        return Finding(
            title="Broken Object Level Authorization (BOLA / IDOR)",
            owasp_category="API1:2023 - Broken Object Level Authorization",
            threat_level="High",
            cvss_score="8.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
            affected_path=f"{ep.url}",
            description=f"The endpoint fails to enforce authorization bounds on the {vector_type}. By manipulating the ID to '{payload}', the system returned unauthorized data. Verified via Baseline Variance Analysis.",
            business_impact="An authenticated attacker can bypass access controls to view or modify sensitive records belonging to other users.",
            recommendations=[
                "Implement robust authorization checks at the data-access layer ensuring `current_user` has permission to access the requested object.",
                "Replace auto-incrementing integer IDs with unpredictable GUIDs/UUIDs for sensitive database records."
            ],
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0x11-api1-broken-object-level-authorization/"
            ],
            proof_of_concept=ProofOfConcept(
                intro_text=f"Manipulating the target identifier in the {vector_type} granted unauthorized cross-tenant access. Baseline variance confirmed.",
                steps_to_reproduce=[
                    f"1. Captured baseline response for normal request to {ep.url}",
                    f"2. Modified the target identifier in the {vector_type} to '{payload}'",
                    "3. Observed HTTP 200 OK with structural variance from the baseline, confirming unauthorized data access."
                ],
                evidence=Evidence(
                    type="http_snippet",
                    request=f"{ep.method} {exploit_url} HTTP/1.1\nHost: target",
                    response=f"HTTP/1.1 200 OK\n\nMatched Sensitive Footprint: {match_preview}"
                )
            )
        )
