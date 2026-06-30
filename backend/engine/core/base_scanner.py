import traceback
from abc import ABC, abstractmethod
from typing import List
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding
from engine.core.http_client import AsyncSafeHttpClient

class BaseScanner(ABC):
    """
    Abstract blueprint for asynchronous vulnerability scanners.
    Enforces non-blocking execution and crash isolation across modular scanners.
    """
    def __init__(self, target_url: str, client: AsyncSafeHttpClient, log_callback=None):
        self.target_url = target_url
        self.client = client
        self.log_callback = log_callback

    async def execute(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Asynchronous execution wrapper. Isolates exceptions to prevent 
        a single scanner failure from halting the entire orchestration process.
        """
        try:
            findings = await self.run_scan(endpoints)
            return findings if findings else []
        except Exception as e:
            print(f"[-] [Scanner Exception] {self.__class__.__name__} encountered a fatal error: {str(e)}")
            return []

    @abstractmethod
    async def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        """
        Core vulnerability detection logic. 
        Must be implemented by all derived scanner classes.
        """
        pass