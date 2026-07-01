from dataclasses import dataclass, field
from typing import Dict

@dataclass
class HttpRequest:
    """Represents the outbound HTTP request."""
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""

@dataclass
class HttpResponse:
    """Represents the inbound HTTP response."""
    success: bool
    status_code: int = 0
    text: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    error_message: str = ""
    elapsed_time: float = 0.0

    @property
    def size(self):
        """Returns the length of the response text automatically."""
        return len(self.text)

@dataclass
class HttpTransaction:
    """
    Binds a specific HttpRequest to its resulting HttpResponse.
    Crucial for Proof of Concept generation and delayed vulnerability verification.
    """
    request: HttpRequest
    response: HttpResponse

@dataclass
class ProofContext:
    """
    Maintains context for building the final vulnerability report finding.
    """
    parameter: str = ""
    payload: str = ""
    file_path: str = ""
    matched_pattern: str = ""
    tested_parameter: str = ""
    foreign_id_accessed: str = ""