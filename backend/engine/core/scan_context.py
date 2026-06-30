import time
from dataclasses import dataclass, field
from typing import Dict

@dataclass
class ScanContext:
    target_url: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    
    
    max_requests: int = 15000
    max_scan_time_sec: int = 1800 
    
    request_count: int = 0
    start_time: float = field(default_factory=time.time)
    is_aborted: bool = False

    def consume_budget(self) -> bool:
        if self.is_aborted: return False
        self.request_count += 1
        elapsed_time = time.time() - self.start_time
        if self.request_count >= self.max_requests or elapsed_time > self.max_scan_time_sec:
            self.is_aborted = True
            return False
        return True

    def should_fuzz(self, url: str) -> bool:
        """
        Smart Fuzzing Strategy: Only fuzz paths that traditionally accept data.
        Prevents wasting thousands of requests on static or purely structural pages.
        """
        skip_keywords = ['logout', 'signout', 'destroy', 'delete', 'remove', 'assets', 'static', 'dashboard']
        url_lower = url.lower()
        
        if any(kw in url_lower for kw in skip_keywords):
            return False
            
        # Only fuzz if the URL hints at data retrieval/action
        fuzz_targets = ['search', 'profile', 'api', 'query', 'view', 'item', 'page', 'post', 'article']
        if any(kw in url_lower for kw in fuzz_targets):
            return True
            
        return False # Default to False to preserve scan budget