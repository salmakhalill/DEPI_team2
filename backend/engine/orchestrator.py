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
        # the list of scanner classes to run (team will add their classes here)
        self.scanners = [] 

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
        
        # run all registered scanners in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_scanner = {
                executor.submit(scanner.execute, endpoints): scanner 
                for scanner in self.scanners
            }
            for future in concurrent.futures.as_completed(future_to_scanner):
                findings = future.result()
                if findings:
                    all_findings.extend(findings)

        print("[*] Phase 3: Reporting & Formatting")
        return self._build_master_json(all_findings)

    def _build_master_json(self, findings: List[Finding]) -> Dict[str, Any]:
        end_time = datetime.utcnow()
        duration = (end_time - self.start_time).total_seconds()
        
        # calculate distribution for the charts
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        findings_table = []
        
        for f in findings:
            severity = f.threat_level.lower()
            if severity in distribution:
                distribution[severity] += 1
                
            findings_table.append({
                "id": f.id,
                "finding_name": f.title,
                "risk": f.threat_level,
                "status": f.status
            })

        # overall risk logic
        overall_threat = "Low"
        if distribution["critical"] > 0: overall_threat = "Critical"
        elif distribution["high"] > 0: overall_threat = "High"
        elif distribution["medium"] > 0: overall_threat = "Medium"

        # The Exact JSON Contract for the Reporter Module
        return {
            "report_metadata": {
                "document_number": "T1-51.001",
                "document_name": "Web Application Penetration Testing Report",
                "document_author": "Scanner Engine (Automated)",
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
                "findings_table": findings_table
            },
            "findings": [f.to_dict() for f in findings]
        }