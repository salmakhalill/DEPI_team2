import asyncio
import concurrent.futures
from datetime import datetime
from typing import List, Dict, Any
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

from engine.crawler.spider import PlaywrightSpider
from engine.extractor.param_extractor import ParamExtractor
from engine.models.finding import Finding

class Orchestrator:
    def __init__(self, scan_id: str, target_url: str, cookies: dict = None):
        # We need the scan_id to dynamically identify the correct WebSocket room
        self.scan_id = str(scan_id)
        self.target_url = target_url
        self.cookies = cookies or {}
        self.start_time = datetime.utcnow()
        self.scanners = [] # Container array for active technical assessment extensions
        
        # Initialize the WebSocket channel layer and group name for live telemetry
        self.channel_layer = get_channel_layer()
        self.room_group_name = f'scan_{self.scan_id}'

    def send_live_log(self, message_text: str):
        """
        Pushes a live log message securely to the WebSocket frontend.
        Uses asyncio.run inside a detached micro-thread to completely 
        bypass any Windows/Playwright Event Loop thread constraints.
        """
        import threading
        import asyncio

        def _broadcast():
            try:
                if self.channel_layer:
                    # Directly run the async group_send without relying on async_to_sync
                    asyncio.run(
                        self.channel_layer.group_send(
                            self.room_group_name,
                            {
                                'type': 'scan_telemetry',
                                'message': message_text
                            }
                        )
                    )
            except Exception as e:
                # Fallback for debugging if the channel layer fails
                print(f"[WS Error] {e}")
        
        # Fire and forget micro-thread
        threading.Thread(target=_broadcast).start()

    def register_scanner(self, scanner_instance):
        self.scanners.append(scanner_instance)
        self.send_live_log(f"[+] Successfully registered scanner module: {scanner_instance.__class__.__name__}")

    def run_assessment(self) -> Dict[str, Any]:
        self.send_live_log("[*] Phase 1: Discovery & Attack Surface Mapping Initialization")
        
        # FIX: Pass the WebSocket broadcast function directly to the Spider
        spider = PlaywrightSpider(
            target_url=self.target_url, 
            cookies=self.cookies,
            log_callback=self.send_live_log  
        )
        
        self.send_live_log(f"[*] Dispatching asynchronous spider to crawl: {self.target_url}")
        
        raw_crawl_data = spider.crawl()
        
        endpoints = ParamExtractor.extract(raw_crawl_data)
        self.send_live_log(f"[+] Attack Surface Extracted: {len(endpoints)} unique endpoints discovered.")
        print(f"[+] Attack Surface: {len(endpoints)} endpoints discovered.")

        self.send_live_log("[*] Phase 2: Vulnerability Assessment (Concurrent Scans Initiated)")
        print("[*] Phase 2: Vulnerability Assessment (Concurrent Scans)")
        all_findings: List[Finding] = []
        
        # Multithreaded execution loop across separate vulnerability scanning plugins
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_scanner = {
                executor.submit(scanner.execute, endpoints): scanner 
                for scanner in self.scanners
            }
            for future in concurrent.futures.as_completed(future_to_scanner):
                scanner_name = future_to_scanner[future].__class__.__name__
                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                        self.send_live_log(f"[!] {scanner_name} completed and identified {len(findings)} vulnerable vectors.")
                    else:
                        self.send_live_log(f"[-] {scanner_name} completed cleanly. No vulnerabilities found.")
                except Exception as exc:
                    self.send_live_log(f"[!] Engine Error: {scanner_name} generated an exception: {exc}")

        self.send_live_log("[*] Phase 3: Aggregating Threat Matrices and Generating Dynamic Payload")
        print("[*] Phase 3: Generating Dynamic Payload")
        
        return self._build_master_json(all_findings)

    def _build_master_json(self, findings: List[Finding]) -> Dict[str, Any]:
        end_time = datetime.utcnow()
        duration = (end_time - self.start_time).total_seconds()
        
        aggregated_findings: Dict[str, Dict[str, Any]] = {}
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        
        for f in findings:
            # 1. Dynamic Vulnerability Type instead of Hardcoded SQLi
            # Assuming your Finding model has a 'title' or 'name' attribute
            vuln_type = f.title  
            severity = f.threat_level.lower()
            
            poc_data = {
                "intro_text": f.proof_of_concept.intro_text if f.proof_of_concept else "Vulnerability verified via automated payload reflection.",
                "steps_to_reproduce": f.proof_of_concept.steps_to_reproduce if f.proof_of_concept else [],
                "evidence": {
                    "request": f.proof_of_concept.evidence.request if f.proof_of_concept and getattr(f.proof_of_concept, 'evidence', None) else "",
                    "response": f.proof_of_concept.evidence.response if f.proof_of_concept and getattr(f.proof_of_concept, 'evidence', None) else ""
                }
            }
            
            if vuln_type not in aggregated_findings:
                if severity in distribution:
                    distribution[severity] += 1
                
                # 2. Map all fields dynamically from the 'f' (Finding) object
                aggregated_findings[vuln_type] = {
                    "id": getattr(f, 'vuln_id', f"VULN-{vuln_type.upper().replace(' ', '-')[:10]}"), # Dynamic ID
                    "title": f.title,
                    "owasp_category": f.owasp_category,
                    "threat_level": f.threat_level,
                    "cvss_score": f.cvss_score,
                    "description": getattr(f, 'description', 'No description provided.'), # Dynamic description
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

        self.send_live_log("[+] Scan Engine operations completed. Report payload is ready for compilation.")

        return {
            "report_metadata": {
                "document_number": "T1-51.001",
                "document_name": "Automated Vulnerability Assessment Report",
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