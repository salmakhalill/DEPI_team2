import re
from urllib.parse import urlparse
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager
from engine.analyzer.response_analyzer import ResponseAnalyzer

class FileUploadScanner(BaseScanner):
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        payload_data = PayloadManager.get_payloads("file_upload")
        upload_cases = payload_data.get("cases", []) if isinstance(payload_data, dict) else payload_data
        endpoint_keywords = payload_data.get("endpoint_keywords", []) if isinstance(payload_data, dict) else []
        upload_locations = payload_data.get("upload_locations", ["/static/uploads/", "/uploads/"]) if isinstance(payload_data, dict) else []
        
        # Fetch fallback parameters strictly from the Knowledge Base
        hidden_upload_params = payload_data.get("hidden_upload_params", []) if isinstance(payload_data, dict) else []

        if not upload_cases:
            return findings

        scanned_patterns = set()
        upload_endpoints = [ep for ep in endpoints if self._is_upload_endpoint(ep, endpoint_keywords)]

        if self.log_callback:
            self.log_callback(f"[*] [File Upload Scanner] Initiating execution across {len(upload_endpoints)} nodes.")

        for ep in upload_endpoints:
            structural_url = re.sub(r'/\d+', '/[ID]', ep.url)
            pattern_key = f"UPLOAD_POST:{structural_url}"
            if pattern_key in scanned_patterns: continue
            scanned_patterns.add(pattern_key)

            pre_flight = await self.client.request('GET', ep.url, follow_redirects=True)
            hidden_fields = {}
            if pre_flight.success:
                inputs = re.findall(r'<input[^>]+type=[\'"]hidden[\'"][^>]*>', pre_flight.text, re.IGNORECASE)
                for inp in inputs:
                    name_m = re.search(r'name=[\'"]([^\'"]+)[\'"]', inp, re.IGNORECASE)
                    val_m = re.search(r'value=[\'"]([^\'"]+)[\'"]', inp, re.IGNORECASE)
                    if name_m and val_m: hidden_fields[name_m.group(1)] = val_m.group(1)

            ep_param_names = [p.name for p in (ep.params or [])]
            params_to_test = list(set(ep_param_names + (ep.file_inputs or [])))
            
            # Apply JSON fallbacks only if no explicit inputs were discovered
            if not ep.file_inputs:
                params_to_test.extend(hidden_upload_params)
                params_to_test = list(set(params_to_test))

            if not params_to_test:
                continue

            for param in params_to_test:
                is_vulnerable_param = False

                for case in upload_cases:
                    base_filename = case.get("filename", "test.txt")
                    file_content = case.get("content", "").encode("utf-8")
                    content_type = case.get("content_type", "application/octet-stream")
                    match_regex_str = case.get("match_regex", "(?i)({filename})")

                    url_clean_slug = re.sub(r'[^a-zA-Z0-9]', '_', ep.url.split('//')[-1])
                    unique_filename = f"scan_{url_clean_slug}_{param}_{base_filename}"

                    files = {field_name: (unique_filename, file_content, content_type) for field_name in [param]}
                    extra_data = {"title": "scan", "description": "payload", "name": "scanner", "submit": "1"}
                    extra_data.update(hidden_fields)
                    
                    for p_name in ep_param_names:
                        if p_name not in extra_data and p_name != param: 
                            extra_data[p_name] = "test_value"

                    response = await self.client.request(method='POST', url=ep.url, files=files, data=extra_data, follow_redirects=True)

                    if response.success and response.status_code in [200, 201, 302]:
                        adjusted_regex = match_regex_str.replace("{filename}", unique_filename)
                        try: compiled_regex = re.compile(adjusted_regex, re.IGNORECASE)
                        except re.error: compiled_regex = re.compile(re.escape(unique_filename), re.IGNORECASE)

                        match = ResponseAnalyzer.has_new_signature("", response.text, compiled_regex)
                        
                        if match:
                            is_vulnerable_param = True
                            matched_evidence = f"Application interface mirrored file registration sequence: {match.group(0)}"

                        if not is_vulnerable_param:
                            parsed_url = urlparse(ep.url)
                            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                            
                            for directory in upload_locations:
                                probe_url = f"{base_url}{directory}{unique_filename}"
                                probe_res = await self.client.request('GET', probe_url, follow_redirects=False)
                                
                                if probe_res.success and probe_res.status_code == 200:
                                    if b"UPLOAD_PWN" in file_content and "UPLOAD_PWN" in probe_res.text:
                                        is_vulnerable_param = True
                                        matched_evidence = f"Verified active deployment context hosted directly at: {probe_url}"
                                        break
                                    elif "<?php" in probe_res.text or "flask" in probe_res.text:
                                        is_vulnerable_param = True
                                        matched_evidence = f"Malicious content hosted at: {probe_url}"
                                        break

                        if is_vulnerable_param:
                            findings.append(Finding(
                                title="Unrestricted File Upload",
                                owasp_category="A04:2021 - Insecure Design",
                                threat_level=case.get("severity", "Critical"), cvss_score=case.get("cvss", "9.8"),
                                affected_path=f"POST {ep.url} ➔ {matched_evidence}",
                                description=case.get("description", "Unrestricted File Upload detected."),
                                business_impact="Unauthenticated remote threat actors can register server-side executable code structures.",
                                recommendations=["Enforce binary magic byte signatures inspections instead of depending on MIME types or extensions."],
                                references=["https://cwe.mitre.org/data/definitions/434.html"],
                                proof_of_concept=ProofOfConcept(
                                    intro_text=f"The application dynamically handled file streams using unverified extensions.",
                                    steps_to_reproduce=[f"1. Target mapping node: {ep.url}", f"2. Issue multipart POST mapping payload into '{param}'"],
                                    evidence=Evidence(type="http_snippet", request=f"POST {ep.url} HTTP/1.1\nname=\"{param}\"; filename=\"{unique_filename}\"", response=f"HTTP/1.1 {response.status_code} OK\n\n[!] Confirmed: {matched_evidence}")
                                )
                            ))
                            if self.log_callback: self.log_callback(f"[!] Unrestricted File Upload Confirmed. Target: {ep.url}")
                            break 
                if is_vulnerable_param: break
        return findings

    def _is_upload_endpoint(self, ep: Endpoint, upload_keywords: List[str]) -> bool:
        url_lower = ep.url.lower()
        if any(kw in url_lower for kw in upload_keywords): return True
        if len(ep.file_inputs) > 0: return True
        return False