import re
from urllib.parse import parse_qs
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager
from engine.analyzer.response_analyzer import ResponseAnalyzer

class SQLInjectionScanner(BaseScanner):
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        payload_data = PayloadManager.get_payloads("sqli")
        dynamic_fuzzing_params = payload_data.get("fuzzing_parameters", []) if isinstance(payload_data, dict) else []
        sqli_cases = payload_data.get("cases", []) if isinstance(payload_data, dict) else payload_data
        
        if not sqli_cases: return findings

        if self.log_callback:
            self.log_callback(f"[*] [SQLi Scanner] Assessing attack surface cross-matching {len(endpoints)} targets.")

        for ep in endpoints:
            ep_param_names = [p.name for p in ep.params]
            
            if not ep_param_names:
                if hasattr(self.client, 'context') and not self.client.context.should_fuzz(ep.url):
                    continue
                params_to_test = dynamic_fuzzing_params
            else:
                params_to_test = ep_param_names

            if not params_to_test: continue
                
            parsed_defaults = parse_qs(ep.original_query)

            for param in params_to_test:
                base_parameters = {p_name: parsed_defaults[p_name][0] if p_name in parsed_defaults and parsed_defaults[p_name] else "test" for p_name in ep_param_names}
                if param not in base_parameters:
                    base_parameters[param] = "test"

                baseline_response = await self.client.request(
                    method=ep.method, url=ep.url,
                    params=base_parameters if ep.method == "GET" else None,
                    data=base_parameters if ep.method == "POST" else None
                )
                
                if not baseline_response.success: continue
                
                for case in sqli_cases:
                    base_payload = case.get("payload", "'")
                    true_suffix = case.get("true_suffix", " OR 1=1--")
                    false_suffix = case.get("false_suffix", " AND 1=2--")
                    compiled_regex = case.get("compiled_regex")
                    
                    error_params = base_parameters.copy()
                    error_params[param] = f"{base_parameters[param]}{base_payload}"
                    
                    error_resp = await self.client.request(
                        method=ep.method, url=ep.url,
                        params=error_params if ep.method == "GET" else None,
                        data=error_params if ep.method == "POST" else None
                    )
                    
                    syntax_error_detected = False
                    if error_resp.success:
                        if ResponseAnalyzer.has_new_signature(baseline_response.text, error_resp.text, compiled_regex):
                            syntax_error_detected = True
                            
                    true_payload = f"{base_parameters[param]}{base_payload}{true_suffix}"
                    false_payload = f"{base_parameters[param]}{base_payload}{false_suffix}"
                    
                    true_params, false_params = base_parameters.copy(), base_parameters.copy()
                    true_params[param] = true_payload
                    false_params[param] = false_payload
                    
                    true_resp = await self.client.request(
                        method=ep.method, url=ep.url,
                        params=true_params if ep.method == "GET" else None, data=true_params if ep.method == "POST" else None
                    )
                    false_resp = await self.client.request(
                        method=ep.method, url=ep.url,
                        params=false_params if ep.method == "GET" else None, data=false_params if ep.method == "POST" else None
                    )
                    
                    if not (true_resp.success and false_resp.success): continue
                    
                    is_boolean_vuln = ResponseAnalyzer.is_boolean_variance(
                        baseline_response, true_resp, false_resp,
                        true_payload=true_payload, false_payload=false_payload
                    )
                    
                    if is_boolean_vuln or syntax_error_detected:
                        confidence = "High (Behavioral Verification)" if is_boolean_vuln else "Medium (Strict Error Match)"
                        description = f"Automated verification confirmed logic control over the backend storage via parameter '{param}'."
                        if syntax_error_detected: description += " Explicit backend SQL faults and database errors were triggered."

                        separator = "&" if "?" in ep.url else "?"
                        request_evidence = f"{ep.method} {ep.url}{separator}{param}={true_payload} HTTP/1.1"
                        response_evidence = f"Engine Confidence: {confidence}\nSyntax Error Detected: {syntax_error_detected}\nBoolean Variance Detected: {is_boolean_vuln}"

                        findings.append(Finding(
                            title="SQL Injection (SQLi)",
                            owasp_category="A03:2021 - Injection",
                            threat_level="Critical", cvss_score="9.8",
                            affected_path=f"{ep.url} [parameter={param}]",
                            description=description,
                            business_impact="An unauthenticated remote attacker can completely manipulate application logic parameters and execute arbitrary system functions.",
                            recommendations=["Transition codebase queries to strictly parameterized ORM architectures globally.", "Disable explicit stack-trace mapping outputs."],
                            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                            proof_of_concept=ProofOfConcept(
                                intro_text=f"Injecting relational query operators inside input field '{param}' manipulated the application rendering structure.",
                                steps_to_reproduce=[f"1. Target Endpoint: {ep.url}", f"2. True Logic Payload: {true_payload}", f"3. False Logic Payload: {false_payload}"],
                                evidence=Evidence(type="http_snippet", request=request_evidence, response=response_evidence)
                            )
                        ))
                        
                        if self.log_callback: self.log_callback(f"[!] SQL Injection Confirmed. Target: {ep.url} | Param: '{param}'")
                        break
                        
        return findings