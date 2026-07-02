import html
from urllib.parse import parse_qs
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager
from engine.analyzer.response_analyzer import ResponseAnalyzer

class XSSScanner(BaseScanner):
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []

        payload_data = PayloadManager.get_payloads("xss")
        xss_cases = payload_data.get("cases", []) if isinstance(payload_data, dict) else payload_data
        
        if not xss_cases: return findings

        reflected_cases = [c for c in xss_cases if "stored" not in c.get("id", "")]
        stored_cases = [c for c in xss_cases if "stored" in c.get("id", "")]
        
        if self.log_callback:
            self.log_callback(f"[*] [XSS Scanner] Analyzing reflection contexts across {len(endpoints)} targets.")

        # ---------- 1. Reflected XSS ----------
        for ep in endpoints:
            if ep.method == "GET":
                ep_param_names = [p.name for p in ep.params]
                
                if not ep_param_names:
                    continue
                
                parsed_defaults = parse_qs(ep.original_query)

                for param in ep_param_names:
                    base_parameters = {p_name: parsed_defaults[p_name][0] if p_name in parsed_defaults and parsed_defaults[p_name] else "test" for p_name in ep_param_names}
                    if param not in base_parameters:
                        base_parameters[param] = "test"

                    for case in reflected_cases:
                        payload = case["payload"]
                        test_params = base_parameters.copy()
                        test_params[param] = payload

                        response = await self.client.request('GET', ep.url, params=test_params)
                        if not response.success: continue

                        context = ResponseAnalyzer.get_xss_context(response.text, payload)

                        if context["is_reflected"] and not context["is_escaped"]:
                            findings.append(self._build_finding("Reflected", param, payload, ep.url, f"GET {ep.url}?{param}={payload}"))
                            if self.log_callback: self.log_callback(f"[!] Reflected XSS Confirmed. Target: {ep.url} | Param: '{param}'")
                            break 

        # ---------- 2. Stored XSS ----------
        for ep in endpoints:
            if ep.method == "POST" and "comment" in ep.url.lower():
                ep_param_names = [p.name for p in ep.params]
                
                if not ep_param_names: continue

                for param in ep_param_names:
                    for case in stored_cases:
                        payload = case["payload"]
                        
                        test_data = {p_name: "test_value" for p_name in ep_param_names}
                        test_data[param] = payload

                        post_response = await self.client.request('POST', ep.url, data=test_data)
                        if not post_response.success: continue

                        verify_url = ep.url.lower().replace("/comment", "")
                        verify_response = await self.client.request('GET', verify_url)
                        
                        if verify_response.success:
                            context = ResponseAnalyzer.get_xss_context(verify_response.text, payload)

                            if context["is_reflected"] and not context["is_escaped"]:
                                findings.append(self._build_finding("Stored", param, payload, verify_url, f"POST {ep.url} (data={test_data})"))
                                if self.log_callback: self.log_callback(f"[!] Stored XSS Confirmed. Target: {verify_url} | Param: '{param}'")
                                break

        return findings

    def _build_finding(self, xss_type, param, payload, ep_url, request_line):
        title = f"{xss_type} Cross-Site Scripting (XSS)"
        safe_payload = html.escape(payload)
        
        cvss = "8.1" if xss_type == "Stored" else "7.2"

        if xss_type == "Stored":
            desc = (
                f"The parameter '{param}' at endpoint '{ep_url}' persists user-submitted input "
                f"to the backend datastore without sanitization. The payload '{safe_payload}' "
                f"was stored and subsequently rendered verbatim to other users viewing the page, "
                f"confirming the script executes automatically on every page load — not just for the submitter."
            )
            impact = (
                "A threat actor can permanently inject malicious script into a page accessed by all "
                "NexusFlow users. Every visitor who views the affected content — without clicking any "
                "link — has their session exposed, enabling mass session hijacking, credential theft, "
                "or unauthorized actions performed silently on their behalf."
            )
        else:
            desc = (
                f"The parameter '{param}' at endpoint '{ep_url}' reflects user-supplied input directly "
                f"into the HTML response without output encoding. The payload '{safe_payload}' was "
                f"returned verbatim in the response body, confirming the script executes immediately "
                f"upon request."
            )
            impact = (
                "A threat actor can craft a malicious URL targeting NexusFlow users. Upon visiting the "
                "link, the victim's session cookie or authentication token can be silently exfiltrated "
                "to an attacker-controlled server, enabling account takeover without needing the victim's "
                "credentials."
            )
        
        return Finding(
            title=title,
            owasp_category="A03:2021 - Injection",
            threat_level="High", cvss_score=cvss,
            affected_path=f"{ep_url} [parameter={param}]",
            description=desc,
            business_impact=impact,
            recommendations=["Encode all user-supplied data before rendering it.", "Implement CSP header."],
            references=["https://owasp.org/www-community/attacks/xss/"],
            proof_of_concept=ProofOfConcept(
                intro_text=f"Injected the payload '{safe_payload}' via parameter '{param}' and confirmed unescaped rendering in the server response.",
                steps_to_reproduce=[
                    f"1. Navigate to '{ep_url}'.",
                    f"2. Submit '{safe_payload}' as the value of parameter '{param}'.",
                    "3. Observe that the payload executes without being encoded or stripped by the application."
                ],
                evidence=Evidence(type="http_snippet", request=html.escape(request_line), response="Context: Raw Unescaped Reflection Confirmed")
            )
        )