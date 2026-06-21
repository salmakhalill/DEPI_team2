import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any
from engine.crawler.spider import PlaywrightSpider
from engine.extractor.param_extractor import ParamExtractor
from engine.models.finding import Finding

class Orchestrator:
    def __init__(self, target_url: str, cookies: dict = None):
        self.target_url = target_url
        self.cookies = cookies or {}
        self.start_time = datetime.utcnow()
        self.scanners = [] # Container array for active technical assessment extensions

    def register_scanner(self, scanner_instance):
        self.scanners.append(scanner_instance)

    def run_assessment(self) -> Dict[str, Any]:
        print("[*] Phase 1: Discovery & Attack Surface Mapping")
        spider = PlaywrightSpider(target_url=self.target_url, cookies=self.cookies)
        raw_crawl_data = spider.crawl()
        
        endpoints = ParamExtractor.extract(raw_crawl_data)
        print(f"[+] Attack Surface: {len(endpoints)} endpoints discovered.")

        print("[*] Phase 2: Vulnerability Assessment (Concurrent Scans)")
        all_findings: List[Finding] = []
        
        # Multithreaded execution loop across separate vulnerability scanning plugins
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_scanner = {
                executor.submit(scanner.execute, endpoints): scanner 
                for scanner in self.scanners
            }
            for future in concurrent.futures.as_completed(future_to_scanner):
                findings = future.result()
                if findings:
                    all_findings.extend(findings)

        print("[*] Phase 3: Generating Dynamic Payload")
        return self._build_master_json(all_findings)

    def _build_master_json(self, findings: List[Finding]) -> Dict[str, Any]:
        end_time = datetime.utcnow()
        duration = (end_time - self.start_time).total_seconds()
        
        aggregated_findings: Dict[str, Dict[str, Any]] = {}
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for f in findings:
            vuln_type = "SQL Injection" 
            severity = f.threat_level.lower()
            
            # Extract raw steps and evidence fields strictly to prevent NoneType rendering errors
            poc_data = {
                "intro_text": f.proof_of_concept.intro_text if f.proof_of_concept else "Vulnerability verified via automated payload reflection.",
                "steps_to_reproduce": f.proof_of_concept.steps_to_reproduce if f.proof_of_concept else [],
                "evidence": {
                    "request": f.proof_of_concept.evidence.request if f.proof_of_concept and f.proof_of_concept.evidence else "",
                    "response": f.proof_of_concept.evidence.response if f.proof_of_concept and f.proof_of_concept.evidence else ""
                }
            }
            
            if vuln_type not in aggregated_findings:
                if severity in distribution:
                    distribution[severity] += 1
                
                aggregated_findings[vuln_type] = {
                    "id": "VULN-SQLI-01",
                    "title": "SQL Injection (SQLi)",
                    "owasp_category": f.owasp_category,
                    "threat_level": f.threat_level,
                    "cvss_score": f.cvss_score,
                    "description": "The application fails to properly sanitize user-supplied input before concatenating it into internal dynamic SQL query blocks, allowing arbitrary command execution.",
                    "business_impact": f.business_impact,
                    "recommendations": f.recommendations,
                    "references": f.references,
                    "status": f.status,
                    "paths_list": [f.affected_path],
                    "pocs": [poc_data]
                }
            else:
                if f.affected_path not in aggregated_findings[vuln_type]["paths_list"]:
                    aggregated_findings[vuln_type]["paths_list"].append(f.affected_path)
                aggregated_findings[vuln_type]["pocs"].append(poc_data)

        # Enforce strategic clean newline injection for the HTML table cell rendering context
        for vuln_type in aggregated_findings:
            aggregated_findings[vuln_type]["affected_path_html"] = "<br>".join(aggregated_findings[vuln_type]["paths_list"])

        findings_summary_table = []
        for vuln_type, data in aggregated_findings.items():
            findings_summary_table.append({
                "id": data["id"],
                "finding_name": f"{data['title']} ({len(data['paths_list'])} Vulnerable Parameters Discovered)",
                "risk": data["threat_level"],
                "status": data["status"]
            })

        overall_threat = "Low"
        if distribution["critical"] > 0: overall_threat = "Critical"
        elif distribution["high"] > 0: overall_threat = "High"
        elif distribution["medium"] > 0: overall_threat = "Medium"

        return {
            "report_metadata": {
                "document_number": "T1-51.001",
                "document_name": "NexusFlow SaaS Penetration Testing Report",
                "date_generated": self.start_time.strftime("%Y-%m-%d"),
                "document_author": "Automated Scanner Engine",
                "document_review": "Tech Lead"
            },
            "scope": {
                "timeline": {
                    "start_date": self.start_time.strftime("%Y-%m-%d"),
                    "duration_seconds": int(duration)
                },
                "targets": [{"url": self.target_url}]
            },
            "executive_summary": {
                "overall_threat_level": overall_threat,
                "aggregated_threat_distribution": distribution,
                "findings_summary_table": findings_summary_table
            },
            "detailed_findings": list(aggregated_findings.values())
        }