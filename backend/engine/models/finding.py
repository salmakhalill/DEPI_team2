import uuid
from datetime import datetime
from dataclasses import dataclass, field
from typing import List
from .http_context import RequestContext, ResponseContext, ProofContext

@dataclass
class Finding:
    vulnerability: str
    severity: str
    confidence: str
    cwe: str
    owasp: str
    url: str
    description: str
    remediation: str
    request: RequestContext
    response: ResponseContext
    proof: ProofContext
    reproduction_steps: List[str]
    
    id: str = field(default_factory=lambda: f"vuln-{uuid.uuid4().hex[:8]}")
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")

    def to_dict(self) -> dict:
        # filter out empty fields from proof to keep json output clean
        clean_proof = {k: v for k, v in self.proof.__dict__.items() if v}
        
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "vulnerability": self.vulnerability,
            "severity": self.severity,
            "confidence": self.confidence,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "url": self.url,
            "description": self.description,
            "request": self.request.__dict__,
            "response": self.response.__dict__,
            "proof": clean_proof,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation
        }