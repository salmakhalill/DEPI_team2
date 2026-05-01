from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseScanner(ABC):
    def __init__(self, target_url: str):
        self.target_url = target_url

    def format_result(self, 
                      vuln_name: str, 
                      is_vulnerable: bool, 
                      severity: str = "", 
                      url: str = "", 
                      description: str = "", 
                      proof: Optional[Dict[str, Any]] = None, 
                      remediation: str = "") -> dict:
        return {
            "vulnerability": vuln_name,
            "is_vulnerable": is_vulnerable,
            "severity": severity,
            "url": url,
            "description": description,
            "proof": proof or {},
            "remediation": remediation
        }

    @abstractmethod
    def run_scan(self):
        pass
