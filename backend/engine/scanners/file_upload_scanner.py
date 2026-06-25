import re
import json
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


class FileUploadScanner(BaseScanner):

    # Common field names used for file inputs across different frameworks
    FILE_INPUT_NAMES = ["file", "upload", "attachment", "document", "image", "avatar"]

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        # Load centralized File Upload payload cases
        upload_cases = PayloadManager.get_payloads("file_upload")

        print(f"  [File Upload Scanner] Assessing attack surface logic across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"⚔️ [File Upload Scanner] Assessing attack surface logic across {len(endpoints)} targets...")

        # Filter only POST endpoints that likely handle file uploads
        upload_endpoints = [
            ep for ep in endpoints
            if ep.method == "POST" and self._is_upload_endpoint(ep)
        ]

        print(f"  [File Upload Scanner] Found {len(upload_endpoints)} potential upload endpoint(s).")
        if self.log_callback:
            self.log_callback(f"  [File Upload Scanner] Found {len(upload_endpoints)} potential upload endpoint(s).")

        for ep in upload_endpoints:
            for case in upload_cases:
                filename     = case["filename"]
                file_content = case["content"].encode("utf-8")
                content_type = case["content_type"]
                regex_pattern = case["match_regex"]

                # Build multipart payload — try each common file input field name
                for field_name in self.FILE_INPUT_NAMES:
                    files = {
                        field_name: (filename, file_content, content_type)
                    }
                    # Fill any extra form fields with dummy values so required
                    # fields don't block the request before the file is processed
                    extra_data = {p: "test" for p in ep.params if p != field_name}

                    # Send multipart/form-data POST via SafeHttpClient
                    response = self.client.post(ep.url, files=files, data=extra_data)

                    if response.success:
                        match = re.search(regex_pattern, response.text)

                        if match:
                            # Local terminal print
                            print(f"  [!] Unrestricted File Upload Confirmed! Target: {ep.url} | File: '{filename}' | Field: '{field_name}'")

                            # WebSocket Live Broadcast
                            if self.log_callback:
                                self.log_callback(f"🔥 [VULN] Unrestricted File Upload Confirmed! Target: {ep.url} | File: '{filename}'")

                            finding = Finding(
                                title="Unrestricted File Upload",
                                owasp_category="A04:2021 - Insecure Design",
                                threat_level="Critical",
                                cvss_score="9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)",
                                affected_path=f"{ep.method} {ep.url}",
                                description=(
                                    f"The upload endpoint at '{ep.url}' accepted a file named '{filename}' "
                                    f"with a spoofed Content-Type of '{content_type}'. The server performed no "
                                    f"MIME type validation or content inspection, allowing executable files to be "
                                    f"stored on the server. The response matched the confirmation signature: {regex_pattern}"
                                ),
                                business_impact=(
                                    "An attacker can upload a server-side executable (PHP webshell, Python script, etc.) "
                                    "and trigger it via a direct URL request to achieve full Remote Code Execution (RCE). "
                                    "This enables complete server takeover, data exfiltration, lateral movement inside "
                                    "the internal network, and ransomware deployment."
                                ),
                                recommendations=[
                                    "Validate file type by inspecting the actual file content (magic bytes) using a "
                                    "library such as python-magic — never trust the Content-Type header or file extension alone.",
                                    "Maintain a strict allowlist of safe extensions (e.g. pdf, png, jpg) and reject "
                                    "everything else, including double extensions like shell.php.jpg.",
                                    "Store uploaded files outside the web root so they cannot be accessed or executed "
                                    "via a direct URL.",
                                    "Rename every uploaded file to a random UUID on the server side, discarding the "
                                    "original filename entirely.",
                                    "Serve uploaded files through a dedicated download controller that sets "
                                    "Content-Disposition: attachment to prevent browser execution."
                                ],
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                    "https://cwe.mitre.org/data/definitions/434.html"
                                ],
                                proof_of_concept=ProofOfConcept(
                                    intro_text=(
                                        f"Uploading a file named '{filename}' with a spoofed Content-Type of "
                                        f"'{content_type}' to field '{field_name}' was accepted by the server "
                                        f"without any content validation."
                                    ),
                                    steps_to_reproduce=[
                                        f"1. Navigate to the upload endpoint: {ep.url}",
                                        f"2. Submit a POST request with Content-Type: multipart/form-data",
                                        f"3. Set the file field name to '{field_name}', filename to '{filename}', "
                                        f"and MIME type to '{content_type}'",
                                        f"4. Use file content: {case['content']}",
                                        "5. Confirm the server accepted the file and returned a success response.",
                                        "6. If stored in the web root, access the file URL directly to trigger execution."
                                    ],
                                    evidence=Evidence(
                                        type="http_snippet",
                                        request=(
                                            f"POST {ep.url} HTTP/1.1\n"
                                            f"Host: target\n"
                                            f"Content-Type: multipart/form-data\n\n"
                                            f"--boundary\n"
                                            f"Content-Disposition: form-data; name=\"{field_name}\"; filename=\"{filename}\"\n"
                                            f"Content-Type: {content_type}\n\n"
                                            f"{case['content']}\n"
                                            f"--boundary--"
                                        ),
                                        response=(
                                            f"HTTP/1.1 {response.status_code}\n\n"
                                            f"Matched Upload Confirmation Signature: {match.group(0)}"
                                        )
                                    )
                                )
                            )
                            findings.append(finding)
                            # Confirmed on this field — no need to try other field names
                            break

        return findings

    def _is_upload_endpoint(self, ep: Endpoint) -> bool:
        """
        Heuristic filter — returns True if the endpoint URL or its params
        suggest it handles file uploads, avoiding wasted requests on login
        forms, search bars, and other non-upload POST endpoints.
        """
        upload_keywords = ["upload", "file", "document", "attachment", "import", "avatar", "media"]
        url_lower = ep.url.lower()
        if any(kw in url_lower for kw in upload_keywords):
            return True
        # Also flag if any param name looks like a file input
        for param in ep.params:
            if any(kw in param.lower() for kw in self.FILE_INPUT_NAMES):
                return True
        return False