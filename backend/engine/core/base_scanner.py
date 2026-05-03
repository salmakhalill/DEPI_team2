import uuid
from datetime import datetime
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List

class BaseScanner(ABC):
    # Default metadata to be overridden by subclasses
    VULNERABILITY = "Unknown"
    SEVERITY = "INFO"
    CWE = ""
    OWASP = ""
    DESCRIPTION = ""
    REMEDIATION = ""

    def __init__(self, target_url: str, client=None):
        self.target_url = target_url
        self.client = client

    def format_result(self, 
                      is_vulnerable: bool, 
                      confidence: str = "",
                      url: str = "", 
                      request_data: Optional[Dict[str, Any]] = None,
                      response_data: Optional[Dict[str, Any]] = None,
                      proof: Optional[Dict[str, Any]] = None, 
                      reproduction_steps: Optional[List[str]] = None) -> dict:
        
        # Return a minimal dict if no vulnerability is found
        if not is_vulnerable:
            return {
                "vulnerability": self.VULNERABILITY,
                "is_vulnerable": False
            }

        # Build the standardized finding structure
        return {
            "id": f"vuln-{uuid.uuid4().hex[:8]}",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            
            "vulnerability": self.VULNERABILITY,
            "severity": self.SEVERITY,
            "confidence": confidence,
            "cwe": self.CWE,
            "owasp": self.OWASP,
            "url": url,
            "description": self.DESCRIPTION,
            
            "request": request_data or {},
            "response": response_data or {},
            "proof": proof or {},
            "reproduction_steps": reproduction_steps or [],
            "remediation": self.REMEDIATION
        }

    @abstractmethod
    def run_scan(self):
        """
        Execute the scanning logic. Must be implemented by all scanners.
        """
        pass