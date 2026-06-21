import traceback
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding
from engine.core.http_client import SafeHttpClient

class BaseScanner(ABC):
    def __init__(self, target_url: str, client: SafeHttpClient):
        self.target_url = target_url
        self.client = client

    def execute(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Wrapper to isolate crashes. The orchestrator calls this, NOT run_scan directly.
        This ensures one buggy scanner doesn't crash the entire assessment.
        """
        try:
            findings = self.run_scan(endpoints)
            return findings if findings else []
        except Exception as e:
            print(f"[-] [Scanner Crash] {self.__class__.__name__} failed: {str(e)}")
            # uncomment the next line during active development to see exact errors
            # traceback.print_exc() 
            return []

    @abstractmethod
    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Team members MUST implement this method.
        It should iterate over endpoints, inject payloads, and return a list of Finding objects.
        """
        pass