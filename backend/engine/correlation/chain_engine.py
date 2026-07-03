import os
import json
from typing import List
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.storage.finding_repository import FindingRepository

class CorrelationEngine:
    """
    Correlates related findings to identify predefined attack chains.

    The engine applies rule-based correlation to demonstrate how
    multiple vulnerabilities may be combined into a higher-level
    security scenario during automated assessments.
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
                steps = ["Potential Attack Path:"]
                for idx, f in enumerate(matched_findings):
                    clean_path = f.affected_path.split(' ')[1] if ' ' in f.affected_path else f.affected_path
                    steps.append(f"{idx+1}. Finding identified: '{f.title}' discovered at {clean_path}")
                    
                chain_finding = Finding(
                    title=chain["name"],
                    owasp_category="Attack Chain / Exploit Path",
                    threat_level=chain["severity"],
                    cvss_score=chain["cvss"],
                    affected_path = " → ".join(f.title for f in matched_findings),
                    description=chain["description"],
                    business_impact=chain["impact"],
                    recommendations=chain["recommendations"],
                    references=[],
                    proof_of_concept=ProofOfConcept(
                        intro_text=(
                            "The correlation engine identified multiple related findings "
                            "that satisfy a predefined attack-chain rule. "
                            "This represents a potential attack path inferred from the "
                            "combined scanner results."
                        ), 
                        steps_to_reproduce=steps,
                        evidence=Evidence( 
                            type="analysis",
                            request="Correlation Rule Evaluation",
                            response=(
                                f"Correlation Rule: {chain['name']}\n"
                                f"Matched Findings: {len(matched_findings)}\n"
                                "Status: Rule conditions satisfied"
                            )
                        )
                    )
                )
                self.repository.save(chain_finding)
                
                if self.log_callback:
                    self.log_callback(f"[+] [Correlation Engine] {chain['name']} identified successfully!")