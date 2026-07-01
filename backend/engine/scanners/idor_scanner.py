import re
from typing import List, Dict, Optional, Any
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager

class IDORScanner(BaseScanner):
    """
    Enterprise-grade asynchronous scanner for Broken Object Level Authorization (BOLA/IDOR).
    Identifies predictable resource access across RESTful paths and parameter states.
    """
    
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings: List[Finding] = []
        idor_cases = PayloadManager.get_payloads("idor")
        
        if not idor_cases:
            print("  [-] [IDOR Scanner] Payload configuration missing. Aborting.")
            return findings

        print(f"  [IDOR/BOLA Scanner] Assessing object-level authorization across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"🛡️ [IDOR/BOLA Scanner] Assessing authorization bounds across {len(endpoints)} targets...")

        for ep in endpoints:
            # 1. Test RESTful Path Traversal (e.g., /api/v1/users/1)
            path_finding = await self._test_restful_paths(ep, idor_cases)
            if path_finding:
                findings.append(path_finding)
                continue  # Skip to the next endpoint if vulnerable to avoid duplicate findings

            # 2. Test Parameter Traversal (e.g., ?user_id=1)
            if ep.params:
                param_finding = await self._test_parameters(ep, idor_cases)
                if param_finding:
                    findings.append(param_finding)
        
        return findings

    # -------------------------------------------------------------------------
    # Core Logic Handlers
    # -------------------------------------------------------------------------

    async def _test_restful_paths(self, ep: Endpoint, cases: List[Dict]) -> Optional[Finding]:
        """Tests standard RESTful URL paths for predictable integer IDOR vulnerabilities."""
        path_id_match = re.search(r'/([^v]\w*/)?(\d+)(/|$|\?)', ep.url)
        
        if not path_id_match:
            return None
            
        original_id = int(path_id_match.group(2))
        
        for case in cases:
            test_id = original_id + case["payload"]
            if test_id <= 0:
                continue
                
            test_url = re.sub(rf'/({original_id})(/|$|\?)', f'/{test_id}\\2', ep.url)
            response = await self._send_request(ep.method, test_url)

            if response and response.success and getattr(response, 'text', None):
                if re.search(case["match_regex"], response.text):
                    self._notify_finding(ep.url, test_url)
                    return self._build_finding(ep, test_url, "REST Path", str(test_id), case["match_regex"], response.text)
        return None

    async def _test_parameters(self, ep: Endpoint, cases: List[Dict]) -> Optional[Finding]:
        """Tests URL and Body parameters for BOLA/IDOR vulnerabilities."""
        for param in ep.params:
            if not self._is_target_parameter(param):
                continue
                
            for case in cases:
                # Initialize default parameters safely, then override the targeted one
                test_params = {p: "1" for p in ep.params}
                test_params[param] = str(1 + case["payload"])

                response = await self._send_request(ep.method, ep.url, params_or_data=test_params)

                if response and response.success and getattr(response, 'text', None):
                    if re.search(case["match_regex"], response.text):
                        exploit_url = f"{ep.url}?{param}={test_params[param]}"
                        self._notify_finding(ep.url, exploit_url)
                        return self._build_finding(ep, exploit_url, f"Parameter '{param}'", test_params[param], case["match_regex"], response.text)
        return None

    # -------------------------------------------------------------------------
    # Helper Utilities
    # -------------------------------------------------------------------------

    def _is_target_parameter(self, param: str) -> bool:
        """Filters parameters to target only likely entity identifiers."""
        keywords = {"id", "user", "doc", "msg", "profile", "account", "uuid"}
        param_lower = param.lower()
        return any(keyword in param_lower for keyword in keywords)

    async def _send_request(self, method: str, url: str, params_or_data: Dict[str, Any] = None):
        """Wrapper to safely execute asynchronous HTTP requests dynamically."""
        method = method.upper()
        params_or_data = params_or_data or {}
        
        try:
            if method == "GET":
                return await self.client.get(url, params=params_or_data)
            elif method in ["POST", "PUT", "PATCH", "DELETE"]:
                req_func = getattr(self.client, method.lower(), self.client.post)
                return await req_func(url, data=params_or_data)
        except Exception as e:
            print(f"  [-] Network exception during BOLA probe on {url}: {str(e)}")
            return None
        return None

    def _notify_finding(self, original_url: str, test_url: str):
        """Handles console and websocket notifications for discovered vulnerabilities."""
        print(f"  [!] BOLA/IDOR Confirmed! Target: {original_url} | Exploit URL: {test_url}")
        if self.log_callback:
            self.log_callback(f"🔓 [VULN] BOLA/IDOR Confirmed! Exploit URL: {test_url}")

    def _build_finding(self, ep: Endpoint, exploit_url: str, vector_type: str, payload: str, regex_pattern: str, response_text: str) -> Finding:
        """Constructs the finalized Vulnerability Report Object."""
        match_preview = re.search(regex_pattern, response_text).group(0)
        
        return Finding(
            title="Broken Object Level Authorization (BOLA / IDOR)",
            owasp_category="API1:2023 - Broken Object Level Authorization",
            threat_level="High",
            cvss_score="8.5 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)",
            affected_path=f"{ep.method} {ep.url}",
            description=f"The endpoint fails to enforce proper authorization boundary checks on the {vector_type}. By manipulating the object identifier to '{payload}', the system responded with unauthorized data matching signature pattern: {regex_pattern}",
            business_impact="An authenticated attacker can bypass access controls to view, modify, or delete sensitive records belonging to other users, potentially compromising enterprise secrets and personal data.",
            recommendations=[
                "Implement robust authorization checks at the data-access layer ensuring `current_user` has permission to access the requested object.",
                "Replace auto-incrementing integer IDs with unpredictable GUIDs/UUIDs for sensitive database records."
            ],
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0x11-api1-broken-object-level-authorization/",
                "https://owasp.org/www-community/attacks/Insecure_Direct_Object_Reference"
            ],
            proof_of_concept=ProofOfConcept(
                intro_text=f"Manipulating the target identifier in the {vector_type} granted unauthorized cross-tenant access.",
                steps_to_reproduce=[
                    f"1. Target the identified endpoint: {ep.url}",
                    f"2. Modify the target identifier in the {vector_type} to '{payload}'",
                    "3. Observe that the server returns HTTP 200 OK along with unauthorized sensitive data reflection."
                ],
                evidence=Evidence(
                    type="http_snippet",
                    request=f"{ep.method} {exploit_url} HTTP/1.1\nHost: target",
                    response=f"HTTP/1.1 200 OK\n\nMatched Sensitive Data Footprint: {match_preview}"
                )
            )
        )
