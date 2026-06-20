from dataclasses import dataclass, field
from typing import List

@dataclass
class Endpoint:
    url: str
    method: str
    params: List[str] = field(default_factory=list)
    # preserve original query for replay attacks and verification later
    original_query: str = ""