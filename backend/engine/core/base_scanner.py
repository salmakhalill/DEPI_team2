from abc import ABC, abstractmethod

class BaseScanner(ABC):
    def __init__(self, target_url):
        self.target_url = target_url

    def format_result(self, vuln_name, is_vuln, payload, steps):
        return {
            "vulnerability_name": vuln_name,
            "is_vulnerable": is_vuln,
            "payload_used": payload,
            "technical_steps": steps
        }

    @abstractmethod
    def run_scan(self):
        pass