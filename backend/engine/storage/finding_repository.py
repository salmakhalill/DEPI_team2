from typing import List
from engine.models.finding import Finding

class FindingRepository:
    """
    In-memory storage layer for vulnerabilities.
    Decouples scanners from the reporting and orchestration logic.
    """
    def __init__(self):
        self._findings: List[Finding] = []

    def save(self, finding: Finding) -> None:
        """Saves a finding if it doesn't strictly duplicate an existing one."""
        for existing in self._findings:
            if existing.title == finding.title and existing.affected_path == finding.affected_path:
                return
        self._findings.append(finding)

    def save_all(self, findings: List[Finding]) -> None:
        for f in findings:
            self.save(f)

    def get_all(self) -> List[Finding]:
        return self._findings

    def clear(self) -> None:
        self._findings = []