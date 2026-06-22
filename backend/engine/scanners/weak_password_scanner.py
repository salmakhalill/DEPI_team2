import re
import random
import string
from typing import List
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


class WeakPasswordScanner(BaseScanner):

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        cases = PayloadManager.get_payloads("weak_password")

        for ep in endpoints:
            if ep.method == "POST" and "register" in ep.url.lower():

                for case in cases:
                    payload = case["payload"]
                    regex_pattern = case["match_regex"]

                    # Generate a unique random username to avoid "already exists" collisions
                    random_username = "scanuser_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))

                    test_data = {"username": random_username, "password": payload}
                    response = self.client.post(ep.url, data=test_data)

                    if response.success:
                        match = re.search(regex_pattern, response.text, re.IGNORECASE)

                        if match:
                            print(f"  [!] Weak Password Policy Confirmed at {ep.url} using password '{payload}'")

                            finding = Finding(
                                title="Weak Password Policy on Registration",
                                owasp_category="A07:2021 - Identification and Authentication Failures",
                                threat_level="Medium",
                                cvss_score="5.3",
                                affected_path=ep.url,
                                description=f"The registration endpoint accepted the weak password '{payload}' with no minimum length or complexity enforcement.",
                                business_impact="Weak passwords make user accounts highly susceptible to brute-force and credential-guessing attacks.",
                                recommendations=["Enforce a minimum password length (e.g. 8+ characters).", "Require a mix of uppercase, lowercase, numbers, and symbols.", "Check new passwords against common password blacklists."],
                                references=["OWASP Authentication Cheat Sheet"],
                                proof_of_concept=ProofOfConcept(
                                    intro_text=f"Registered a new account using the weak password '{payload}', the server accepted it without any validation error.",
                                    steps_to_reproduce=[f"Send POST request to {ep.url} with a weak password such as '{payload}'."],
                                    evidence=Evidence(
                                        request=f"POST {ep.url} (password={payload})",
                                        response=f"Matched Pattern: {match.group(0)}"
                                    )
                                )
                            )
                            findings.append(finding)
                            break

        return findings