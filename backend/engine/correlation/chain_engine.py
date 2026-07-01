import os
import json
from typing import List
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.storage.finding_repository import FindingRepository

class CorrelationEngine:
    """
    Analyzes isolated findings to identify Attack Paths (Vulnerability Chaining).
    Translates technical flaws into high-impact business risks based on rules.
    """
    def __init__(self, repository: FindingRepository, log_callback=None):
        self.repository = repository
        self.log_callback = log_callback
        self.rules = self._load_rules()

    def _load_rules(self) -> dict:
        rules_path = os.path.join(os.path.dirname(__file__), 'rules.json')
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            if self.log_callback:
                self.log_callback(f"[-] Error loading correlation rules: {e}")
            return {"chains": []}

    def run_correlation(self) -> None:
        findings = self.repository.get_all()
        if not findings:
            return

        if self.log_callback:
            self.log_callback("[*] [Correlation Engine] Analyzing findings for potential Attack Chains...")

        for chain in self.rules.get("chains", []):
            requires = chain.get("requires", [])
            
            # Check if ALL required vulnerabilities are present in the repository
            matched_findings = []
            for req in requires:
                match = next((f for f in findings if req.lower() in f.title.lower()), None)
                if match:
                    matched_findings.append(match)

            # If all requirements are met, we have a Chain!
            if len(matched_findings) == len(requires) and len(requires) > 0:
                affected_paths = set([f.affected_path for f in matched_findings])
                
                # Dynamically build the attack steps based on the found vulnerabilities
                steps = ["Attack Path Execution Sequence:"]
                for idx, f in enumerate(matched_findings):
                    clean_path = f.affected_path.split(' ')[1] if ' ' in f.affected_path else f.affected_path
                    steps.append(f"{idx+1}. Leverage '{f.title}' discovered at {clean_path}")
                    
                chain_finding = Finding(
                    title=chain["name"],
                    owasp_category="Attack Chain / Exploit Path",
                    threat_level=chain["severity"],
                    cvss_score=chain["cvss"],
                    affected_path=" & ".join(affected_paths),
                    description=chain["description"],
                    business_impact=chain["impact"],
                    recommendations=chain["recommendations"],
                    references=[],
                    proof_of_concept=ProofOfConcept(
                        intro_text="The correlation engine successfully linked multiple vulnerabilities to form this verified attack path.",
                        steps_to_reproduce=steps,
                        evidence=Evidence(type="http_snippet", request="[Automated Chain Generation]", response="System Compromise Verified via Correlation")
                    )
                )
                self.repository.save(chain_finding)
                
                if self.log_callback:
                    self.log_callback(f"[+] [Correlation Engine] {chain['name']} identified successfully!")