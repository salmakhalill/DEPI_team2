import re
from typing import List, Dict, Optional, Any
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class IDORScanner(BaseScanner):
    """
    Advanced asynchronous scanner for BOLA/IDOR.
    Implements Baseline Variance Analysis and Messaging Heuristics to eliminate False Positives.
    """
    
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        
        # Load payloads (handling both List and Dict formats based on the new JSON structure)
        raw_cases = PayloadManager.get_payloads("idor")
        idor_cases = raw_cases.get("cases", raw_cases) if isinstance(raw_cases, dict) else raw_cases
        
        if not idor_cases:
            print("  [-] [IDOR Scanner] Payload configuration missing. Aborting.")
            return findings

        print(f"  [IDOR/BOLA Scanner] Executing Variance Analysis across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"🛡️ [IDOR Scanner] Executing Variance Analysis across {len(endpoints)} targets...")

        for ep in endpoints:
            # 1. Test RESTful Path Traversal
            path_finding = await self._test_restful_paths(ep, idor_cases)
            if path_finding:
                findings.append(path_finding)
                continue  

            # 2. Test Parameter Traversal (Using updated Object Architecture)
            if ep.params:
                param_finding = await self._test_parameters(ep, idor_cases)
                if param_finding:
                    findings.append(param_finding)
        
        return findings

    # -------------------------------------------------------------------------
    # Core Logic Handlers
    # -------------------------------------------------------------------------

    async def _test_restful_paths(self, ep: Endpoint, cases: List[Dict]) -> Optional[Finding]:
        path_id_match = re.search(r'/([^v]\w*/)?(\d+)(/|$|\?)', ep.url)
        if not path_id_match:
            return None
            
        original_id = int(path_id_match.group(2))
        
        # [NEW]: Fetch Baseline to establish normal behavior
        baseline_response = await self._safe_request(ep.method, ep.url)
        baseline_text = getattr(baseline_response, 'text', '') if baseline_response and baseline_response.success else ''

        for case in cases:
            test_id = original_id + case["payload"]
            if test_id <= 0:
                continue
                
            test_url = re.sub(rf'/({original_id})(/|$|\?)', f'/{test_id}\\2', ep.url)
            
            # [NEW]: Use centralized client.request
            response = await self._safe_request(ep.method, test_url)

            if response and response.success and getattr(response, 'text', None):
                # [NEW]: Apply Variance Analysis & Heuristics
                is_vuln, match_preview = self._analyze_variance(ep.url, baseline_text, response.text, case["match_regex"])
                
                if is_vuln:
                    self._notify_finding(ep.url, test_url)
                    return self._build_finding(ep, test_url, "REST Path", str(test_id), case["match_regex"], match_preview)
        return None

    async def _test_parameters(self, ep: Endpoint, cases: List[Dict]) -> Optional[Finding]:
        # [NEW]: Handle ep.params as Objects (p.name) instead of Strings
        for p in ep.params:
            param_name = p.name if hasattr(p, 'name') else str(p)
            
            if not self._is_target_parameter(param_name):
                continue
                
            # [NEW]: Fetch Baseline for parameters
            baseline_params = {param.name if hasattr(param, 'name') else str(param): "1" for param in ep.params}
            baseline_response = await self._safe_request(ep.method, ep.url, params_or_data=baseline_params)
            baseline_text = getattr(baseline_response, 'text', '') if baseline_response and baseline_response.success else ''

            for case in cases:
                test_params = baseline_params.copy()
                test_params[param_name] = str(1 + case["payload"])

                # [NEW]: Use centralized client.request
                response = await self._safe_request(ep.method, ep.url, params_or_data=test_params)

                if response and response.success and getattr(response, 'text', None):
                    # [NEW]: Apply Variance Analysis & Heuristics
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
        """
        Analyzes the response against the baseline to eliminate False Positives.
        Implements Message Heuristics for endpoints without sensitive regex keywords.
        Returns: (is_vulnerable: bool, evidence_preview: str)
        """
        # 1. Structural Check: If the exploit returns the exact same data as baseline, it's not IDOR.
        if baseline_text == exploit_text:
            return False, ""

        # 2. Regex Check WITH Variance: Target data is found AND it's different from the baseline
        match = re.search(regex_pattern, exploit_text)
        if match:
            return True, match.group(0)

        # 3. Messaging / Chat Heuristics: No regex match, but it's a message endpoint and content changed
        url_lower = url.lower()
        if any(keyword in url_lower for keyword in ["message", "chat", "inbox"]):
            # Calculate length variance to ensure it's a substantially different message, not just a CSRF token change
            length_diff = abs(len(exploit_text) - len(baseline_text))
            if length_diff > 5:  # Margin for small dynamic changes
                return True, "[Heuristic Match] Unauthorized message content reflected."

        return False, ""

    def _is_target_parameter(self, param_name: str) -> bool:
        keywords = {"id", "user", "doc", "msg", "profile", "account", "uuid"}
        return any(keyword in param_name.lower() for keyword in keywords)

    async def _safe_request(self, method: str, url: str, params_or_data: Dict[str, Any] = None):
        """
        [NEW]: Unified Request Handler.
        Uses self.client.request to respect core architecture (SSRF protections, Scan Budgets).
        """
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
