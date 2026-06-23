import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


class XSSScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        xss_cases = PayloadManager.get_payloads("xss")

        reflected_cases = [c for c in xss_cases if "stored" not in c["id"]]
        stored_cases = [c for c in xss_cases if "stored" in c["id"]]

        # ---------- 1. Reflected XSS (GET parameters) ----------
        for ep in endpoints:
            if ep.method == "GET" and ep.params:
                for param in ep.params:
                    for case in reflected_cases:
                        payload = case["payload"]
                        regex_pattern = case["match_regex"]

                        test_params = {p: "test" for p in ep.params}
                        test_params[param] = payload

                        response = self.client.get(ep.url, params=test_params)

                        if response.success:
                            match = re.search(regex_pattern, response.text, re.IGNORECASE)
                            if match:
                                findings.append(self._build_finding(
                                    xss_type="Reflected",
                                    param=param,
                                    payload=payload,
                                    ep_url=ep.url,
                                    match_text=match.group(0),
                                    request_line=f"GET {ep.url}?{param}={payload}"
                                ))
                                break

        # ---------- 2. Stored XSS (POST form, e.g. comments) ----------
        for ep in endpoints:
            if ep.method == "POST" and "comment" in ep.url.lower() and ep.params:
                for case in stored_cases:
                    payload = case["payload"]
                    regex_pattern = case["match_regex"]

                    # Build form data using the discovered param names
                    test_data = {p: payload for p in ep.params}

                    post_response = self.client.post(ep.url, data=test_data)
                    if not post_response.success:
                        continue

                    # Re-fetch the page (GET) to verify the payload persisted and renders
                    verify_response = self.client.get(ep.url)
                    if verify_response.success:
                        match = re.search(regex_pattern, verify_response.text, re.IGNORECASE)
                        if match:
                            findings.append(self._build_finding(
                                xss_type="Stored",
                                param=ep.params[0] if ep.params else "comment",
                                payload=payload,
                                ep_url=ep.url,
                                match_text=match.group(0),
                                request_line=f"POST {ep.url} (data={test_data})"
                            ))

        return findings

    def _build_finding(self, xss_type, param, payload, ep_url, match_text, request_line):
        if xss_type == "Stored":
            cvss = "8.1"
            threat = "High"
            description = (
                f"The parameter '{param}' on {ep_url} stores user input without sanitization. "
                f"The payload persists in the database and executes on every subsequent page load, "
                f"affecting every user who views the page (not just the submitter)."
            )
            impact = (
                "Stored XSS is more severe than Reflected XSS because the malicious script "
                "executes automatically for every visitor, enabling mass session hijacking, "
                "credential theft, or website defacement without needing to trick a victim into clicking a link."
            )
            steps = [f"Submit payload '{payload}' via the '{param}' field at {ep_url}.",
                     "Reload the page (or have another user visit it) to confirm the payload executes."]
        else:
            cvss = "7.2"
            threat = "High"
            description = (
                f"The parameter '{param}' reflects user input without proper encoding, "
                f"allowing arbitrary JavaScript execution in the victim's browser."
            )
            impact = (
                "An attacker can steal session cookies, hijack user accounts, "
                "or perform actions on behalf of the victim."
            )
            steps = [f"Inject {payload} in parameter '{param}'"]

        return Finding(
            title=f"{xss_type} XSS in '{param}'",
            owasp_category="A03:2021 - Injection",
            threat_level=threat,
            cvss_score=cvss,
            affected_path=ep_url,
            description=description,
            business_impact=impact,
            recommendations=[
                "Encode all output using context-aware escaping (e.g. Jinja2 autoescaping).",
                "Implement a Content-Security-Policy header to restrict inline scripts.",
                "Sanitize and validate all stored user input before rendering it back to other users."
            ],
            references=["OWASP XSS Prevention Cheat Sheet"],
            proof_of_concept=ProofOfConcept(
                intro_text=f"Sent payload '{payload}' in parameter '{param}', server reflected/stored it unencoded.",
                steps_to_reproduce=steps,
                evidence=Evidence(
                    request=request_line,
                    response=f"Matched Pattern: {match_text}"
                )
            )
        )