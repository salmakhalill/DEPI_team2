from dataclasses import dataclass, field
from typing import Dict

@dataclass
class HttpResponse:
    success: bool
    status_code: int = 0
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    # populated if success is False (e.g., Timeout, Connection Error)
    error_message: str = ""

@dataclass
class RequestContext:
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

@dataclass
class ResponseContext:
    status_code: int
    snippet: str

@dataclass
class ProofContext:
    # flexible fields, scanners populate only what applies to the finding
    parameter: str = ""
    payload: str = ""
    file_path: str = ""
    matched_pattern: str = ""
    tested_parameter: str = ""
    foreign_id_accessed: str = ""