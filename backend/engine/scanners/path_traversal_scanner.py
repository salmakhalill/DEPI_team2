import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


class PathTraversalScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        # Load centralized Path Traversal payload cases and mapping regex signatures
        pt_cases = PayloadManager.get_payloads("path_traversal")

        print(f"  [Path Traversal Scanner] Assessing attack surface logic across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"⚔️ [Path Traversal Scanner] Assessing attack surface logic across {len(endpoints)} targets...")

        for ep in endpoints:

            if ep.params:
                for param in ep.params:
                    for case in pt_cases:
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
                                print(f"  [!] Path Traversal Confirmed! Target: {ep.url} | Param: '{param}'")

                                # WebSocket Live Broadcast for a discovered Vulnerability!
                                if self.log_callback:
                                    self.log_callback(f"🔥 [VULN] Path Traversal Confirmed! Target: {ep.url} | Param: '{param}'")

                                finding = Finding(
                                    title="Path Traversal",
                                    owasp_category="A01:2021 - Broken Access Control",
                                    threat_level="High",
                                    cvss_score="7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)",
                                    affected_path=f"{ep.method} {ep.url}",
                                    description=(
                                        f"The endpoint passes raw user input from parameter '{param}' directly into a "
                                        f"file system path resolution function without sanitization. The server responded "
                                        f"with file content matching the signature pattern: {regex_pattern}"
                                    ),
                                    business_impact=(
                                        "An unauthenticated attacker can read arbitrary files outside the web root, "
                                        "including OS credential files, application configuration files, private keys, "
                                        "and database files — leading to full server compromise."
                                    ),
                                    recommendations=[
                                        "Resolve the canonical (absolute) path of the requested file and verify it starts "
                                        "with the expected base directory before opening it (e.g., os.path.realpath).",
                                        "Use an allowlist of permitted file names or identifiers instead of accepting raw "
                                        "path strings from user input.",
                                        "Strip or reject sequences containing '../', '..\\\\', or URL-encoded equivalents "
                                        "(%2e%2e%2f) at the input validation layer."
                                    ],
                                    references=[
                                        "https://owasp.org/www-community/attacks/Path_Traversal",
                                        "https://cwe.mitre.org/data/definitions/22.html"
                                    ],
                                    proof_of_concept=ProofOfConcept(
                                        intro_text=(
                                            f"Injecting a directory traversal sequence into parameter '{param}' caused "
                                            f"the server to resolve and return a sensitive file from outside the web root."
                                        ),
                                        steps_to_reproduce=[
                                            f"1. Target the identified endpoint: {ep.url}",
                                            f"2. Inject traversal payload into parameter: ?{param}={payload}",
                                            "3. Observe that the response body contains sensitive file content "
                                            "matching the expected signature."
                                        ],
                                        evidence=Evidence(
                                            type="http_snippet",
                                            request=(
                                                f"{ep.method} {ep.url}?{param}={payload} HTTP/1.1\n"
                                                f"Host: target"
                                            ),
                                            response=(
                                                f"HTTP/1.1 {response.status_code}\n\n"
                                                f"Matched Sensitive File Signature: {match.group(0)}"
                                            )
                                        )
                                    )
                                )
                                findings.append(finding)
                                break

        return findings