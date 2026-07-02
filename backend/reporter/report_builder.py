import json
from datetime import datetime
from typing import List, Dict, Any
from engine.models.finding import Finding

class ReportBuilder:
    """
    Transforms raw Finding objects into a structured JSON dictionary.
    This dictionary acts as the 'dynamic_data' injected strictly into the PDF templates.
    """
    
    @classmethod
    def build_json_report(cls, scan_id: str, target_url: str, findings: List[Finding], start_time: datetime = None) -> Dict[str, Any]:
        # Calculate Threat Distribution
        critical = sum(1 for f in findings if f.threat_level.lower() == "critical")
        high = sum(1 for f in findings if f.threat_level.lower() == "high")
        medium = sum(1 for f in findings if f.threat_level.lower() == "medium")
        low = sum(1 for f in findings if f.threat_level.lower() == "low")
        
        total = len(findings)
        
        # Determine Overall Risk
        if critical > 0: overall = "Critical"
        elif high > 0: overall = "High"
        elif medium > 0: overall = "Medium"
        elif low > 0: overall = "Low"
        else: overall = "Secure"

        current_time_dt = datetime.utcnow()
        current_time = current_time_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        if start_time:
            duration_seconds = round((current_time_dt - start_time).total_seconds(), 2)
        else:
            duration_seconds = "N/A"

        # Build the Summary Table required by HTML template
        summary_table = []
        for i, f in enumerate(findings):
            summary_table.append({
                "id": f"VULN-{i+1:03d}",
                "finding_name": getattr(f, 'title', 'Unknown Vulnerability'),
                "risk": getattr(f, 'threat_level', 'Low'),
                "status": "Open"
            })

        # Build the exact JSON Schema expected by report.html
        return {
            "report_metadata": {
                "document_number": f"NEXUS-{str(scan_id)[:8].upper()}",
                "scan_id": str(scan_id),
                "target_url": target_url,
                "date_generated": current_time,
                "document_author": "Nexus Automated Engine",
                "document_review": "System Evaluator",
                "total_vulnerabilities": total
            },
            "scope": {
                "targets": [{"url": target_url}],
                "out_of_scope": ["Third-party integrations", "External CDNs"],
                "test_accounts": [],
               "timeline": {
                    "start_date": start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if start_time else current_time,
                    "duration_seconds": duration_seconds
                }
            },
            "executive_summary": {
                "overall_threat_level": overall,
                "aggregated_threat_distribution": {
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low
                },
                "findings_summary_table": summary_table
            },
            "detailed_findings": [cls._finding_to_dict(f, i+1) for i, f in enumerate(findings)]
        }

    @classmethod
    def _finding_to_dict(cls, finding: Finding, idx: int) -> Dict[str, Any]:
        """Serializes a single Finding object safely, matching Jinja loops."""
        
        # Safely extract PoC data
        poc_data = {}
        if getattr(finding, 'proof_of_concept', None):
            ev = getattr(finding.proof_of_concept, 'evidence', None)
            poc_data = {
                "intro_text": finding.proof_of_concept.intro_text,
                "steps_to_reproduce": finding.proof_of_concept.steps_to_reproduce,
                "evidence": {
                    "type": ev.type if ev else "",
                    "request": ev.request if ev else "",
                    "response": ev.response if ev else ""
                }
            }

        # Handle affected_path_html strictly required by the template
        safe_affected_path = getattr(finding, 'affected_path', 'N/A')
        affected_path_html = safe_affected_path.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

        return {
            "id": f"VULN-{idx:03d}",
            "title": getattr(finding, 'title', 'Unknown Vulnerability'),
            "owasp_category": getattr(finding, 'owasp_category', 'N/A'),
            "threat_level": getattr(finding, 'threat_level', 'Low'),
            "cvss_score": getattr(finding, 'cvss_score', '0.0'),
            "affected_path_html": affected_path_html,
            "description": getattr(finding, 'description', ''),
            "business_impact": getattr(finding, 'business_impact', 'N/A'),
            "recommendations": getattr(finding, 'recommendations', []),
            "references": getattr(finding, 'references', []),
            # Wrap in a list because the template iterates over finding.pocs
            "pocs": [poc_data] if poc_data else [] 
        }