from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class Parameter:
    """
    Represents a discrete injection point.
    Essential for targeted fuzzing and reconstructing requests accurately.
    """
    name: str
    value: str
    param_type: str = "query"  # Supported: 'query', 'body', 'header', 'path'

@dataclass
class Endpoint:
    """
    Comprehensive representation of a discovered target surface.
    """
    url: str
    method: str
    
    # Structural Data
    params: List[Parameter] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Dict[str, str] = field(default_factory=dict)
    
    # Metadata
    original_query: str = ""
    file_inputs: List[str] = field(default_factory=list)
    source: str = "crawler"  # Supported: 'crawler', 'form', 'api_discovery'
    type: str = "general"