import re
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


class LFIScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        # Load centralized LFI payload cases and mapping regex signatures
        lfi_cases = PayloadManager.get_payloads("lfi")

        print(f"  [LFI Scanner] Assessing attack surface logic across {len(endpoints)} targets...")
        if self.log_callback:
            self.log_callback(f"⚔️ [LFI Scanner] Assessing attack surface logic across {len(endpoints)} targets...")

        for ep in endpoints:
            # LFI typically maps to parameters that reference file names or paths
            if ep.params:
                for param in ep.params:
                    for case in lfi_cases:
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
                                print(f"  [!] Local File Inclusion Confirmed! Target: {ep.url} | Param: '{param}'")

                                # WebSocket Live Broadcast for a discovered Vulnerability!
                                if self.log_callback:
                                    self.log_callback(f"🔥 [VULN] Local File Inclusion Confirmed! Target: {ep.url} | Param: '{param}'")

                                finding = Finding(
                                    title="Local File Inclusion (LFI)",
                                    owasp_category="A01:2021 - Broken Access Control",
                                    threat_level="High",
                                    cvss_score="8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)",
                                    affected_path=f"{ep.method} {ep.url}",
                                    description=(
                                        f"The endpoint passes raw user input from parameter '{param}' directly into a "
                                        f"server-side file include or require function without sanitization. The server "
                                        f"executed the inclusion and returned content matching the signature pattern: {regex_pattern}"
                                    ),
                                    business_impact=(
                                        "An unauthenticated attacker can force the server to include and execute arbitrary "
                                        "local files, exposing application source code, configuration files, environment "
                                        "secrets, and OS credential files. In PHP environments, LFI can be chained with "
                                        "log poisoning to achieve full Remote Code Execution (RCE)."
                                    ),
                                    recommendations=[
                                        "Never pass raw user input directly to include(), require(), or equivalent file "
                                        "loading functions. Use a strict allowlist of permitted file identifiers instead.",
                                        "Map user-controlled identifiers to absolute internal file paths server-side "
                                        "(e.g., a dictionary/switch statement) so the user never controls the actual path.",
                                        "Disable dangerous PHP stream wrappers such as php://, file://, and zip:// "
                                        "in php.ini if they are not required by the application.",
                                        "Validate and reject input containing path separators (/, \\\\), null bytes (%00), "
                                        "or protocol wrapper prefixes before any file operation."
                                    ],
                                    references=[
                                        "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
                                        "https://cwe.mitre.org/data/definitions/98.html"
                                    ],
                                    proof_of_concept=ProofOfConcept(
                                        intro_text=(
                                            f"Injecting a local file path or PHP stream wrapper into parameter '{param}' "
                                            f"caused the server to include and return the contents of a sensitive local file."
                                        ),
                                        steps_to_reproduce=[
                                            f"1. Target the identified endpoint: {ep.url}",
                                            f"2. Inject the file inclusion payload into parameter: ?{param}={payload}",
                                            "3. Observe that the response body contains included file content "
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
                                                f"Matched Included File Content Signature: {match.group(0)}"
                                            )
                                        )
                                    )
                                )
                                findings.append(finding)
                                # Vulnerability validated for this node parameter; advance loop tracking
                                break

        return findings