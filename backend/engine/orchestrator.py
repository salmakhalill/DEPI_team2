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
        
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        findings_summary_table = []
        
        for f in findings:
            severity = f.threat_level.lower()
            if severity in distribution:
                distribution[severity] += 1
                
            findings_summary_table.append({
                "id": f.id,
                "finding_name": f.title,
                "risk": f.threat_level,
                "status": f.status
            })

        # Process logical overall risk threshold calculation
        overall_threat = "Low"
        if distribution["critical"] > 0: overall_threat = "Critical"
        elif distribution["high"] > 0: overall_threat = "High"
        elif distribution["medium"] > 0: overall_threat = "Medium"

        # Return structural API contract containing dynamic assessment metadata only
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
            "detailed_findings": [f.to_dict() for f in findings]
        }