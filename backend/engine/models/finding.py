import uuid
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict

@dataclass
class Evidence:
    # structure to hold HTTP snippets or base64 screenshots for the report
    type: str = "http_snippet" # or "screenshot"
    request: str = ""
    response: str = ""
    screenshot_base64: Optional[str] = None

@dataclass
class ProofOfConcept:
    intro_text: str
    steps_to_reproduce: List[str]
    evidence: Evidence

@dataclass
class Finding:
    title: str
    owasp_category: str
    threat_level: str
    cvss_score: str
    affected_path: str
    description: str
    business_impact: str
    recommendations: List[str]
    references: List[str]
    proof_of_concept: ProofOfConcept
    
    status: str = "Open"
    id: str = field(default_factory=lambda: f"VULN-{uuid.uuid4().hex[:6].upper()}")
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        # converts the dataclass to a clean dictionary for the final JSON report
        return {
            "id": self.id,
            "title": self.title,
            "owasp_category": self.owasp_category,
            "threat_level": self.threat_level,
            "cvss_score": self.cvss_score,
            "affected_path": self.affected_path,
            "description": self.description,
            "business_impact": self.business_impact,
            "recommendations": self.recommendations,
            "references": self.references,
            "proof_of_concept": {
                "intro_text": self.proof_of_concept.intro_text,
                "steps_to_reproduce": self.proof_of_concept.steps_to_reproduce,
                "evidence": self.proof_of_concept.evidence.__dict__
            },
            "status": self.status,
            "timestamp": self.timestamp
        }