import asyncio
import threading
from datetime import datetime
from typing import List, Dict, Any
from channels.layers import get_channel_layer

from engine.storage.finding_repository import FindingRepository
from engine.correlation.chain_engine import CorrelationEngine
from engine.core.scan_context import ScanContext
from engine.models.finding import Finding
from engine.core.http_client import AsyncSafeHttpClient
from engine.crawler.spider import PlaywrightSpider
from engine.extractor.param_extractor import ParamExtractor
from engine.registry.scanner_registry import SCANNER_REGISTRY
from reporter.report_builder import ReportBuilder

class Orchestrator:
    """
    Coordinates the execution flow of the DAST engine.
    Responsible for initializing the scope, invoking the crawler,
    delegating execution to scanners, running the correlation engine,
    and returning the final unified report.
    """

    def __init__(self, scan_id: str, context: ScanContext, client: AsyncSafeHttpClient = None):
        self.scan_id = str(scan_id)
        self.context = context
        self.client = client
        self.start_time = datetime.utcnow()
        self.scanners = []
        
        # Initialize the Central Storage Layer
        self.repository = FindingRepository()
        
        self.channel_layer = get_channel_layer()
        self.room_group_name = f'scan_{self.scan_id}'
        

    def send_live_log(self, message_text: str) -> None:
        """Transmits telemetry data securely to the presentation layer via WebSockets."""
        def _broadcast():
            try:
                if self.channel_layer:
                    asyncio.run(
                        self.channel_layer.group_send(
                            self.room_group_name,
                            {
                                'type': 'scan_telemetry',
                                'message': message_text
                            }
                        )
                    )
            except Exception as ex:
                print(f"[-] [WebSocket Runtime Error] {str(ex)}")
        
        threading.Thread(target=_broadcast).start()

    def register_scanner(self, scanner_instance) -> None:
        """Appends a new scanner module to the execution pipeline."""
        self.scanners.append(scanner_instance)
        self.send_live_log(f"[*] Module Initialized: {scanner_instance.__class__.__name__}")

    def load_scanners(self) -> None:
        """Instantiates all scanner classes defined in the global registry."""
        for ScannerClass in SCANNER_REGISTRY:
            scanner_instance = ScannerClass(
                target_url=self.context.target_url,
                client=self.client,
                log_callback=self.send_live_log
            )
            self.register_scanner(scanner_instance)

    def run_assessment(self) -> Dict[str, Any]:
        """
        Executes the primary assessment phases: Discovery, Vulnerability Scanning,
        Correlation (Chaining), and Report Generation.
        Returns the final JSON report dictionary.
        """
        # ==========================================
        # Phase 1: Recon & Attack Surface Discovery
        # ==========================================
        self.send_live_log("[*] Phase 1: Discovery & Attack Surface Mapping")
        
        spider = PlaywrightSpider(
            target_url=self.context.target_url, 
            cookies=self.context.cookies,
            log_callback=self.send_live_log  
        )
        
        raw_crawl_data = spider.crawl()
        endpoints = ParamExtractor.extract(raw_crawl_data)
        
        self.send_live_log(f"[+] Attack Surface Extracted: {len(endpoints)} unique endpoints discovered.")

        # ==========================================
        # Phase 2: Vulnerability Assessment (Scanners)
        # ==========================================
        self.send_live_log("[*] Phase 2: Vulnerability Assessment (Asynchronous Execution)")
        
        async def run_all_scanners():
            tasks = [scanner.execute(endpoints) for scanner in self.scanners]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for scanner, result in zip(self.scanners, results):
                scanner_name = scanner.__class__.__name__
                if isinstance(result, Exception):
                    self.send_live_log(f"[-] Engine Fault: {scanner_name} encountered an exception -> {str(result)}")
                elif result:
                    # Save findings to the central repository instead of a local list
                    self.repository.save_all(result)
                    self.send_live_log(f"[+] {scanner_name}: Discovered {len(result)} vulnerable vectors.")
                else:
                    self.send_live_log(f"[*] {scanner_name}: Completed cleanly with no findings.")
                    
            if hasattr(self.client, 'close'):
                await self.client.close()

        # Execute the asynchronous scanning pipeline
        asyncio.run(run_all_scanners())

        # ==========================================
        # Phase 3: Attack Path Correlation (The Brain)
        # ==========================================
        self.send_live_log("[*] Phase 3: Executing Attack Path Correlation Engine")
        correlation_engine = CorrelationEngine(
            repository=self.repository, 
            log_callback=self.send_live_log
        )
        # This will link isolated findings and inject new "Chain" findings into the repository
        correlation_engine.run_correlation()

        # ==========================================
        # Phase 4: Report Building
        # ==========================================
        self.send_live_log("[*] Phase 4: Generating Final JSON Report")
        
        # Fetch all findings (including the newly generated chains)
        all_findings = self.repository.get_all()
        
        report_json = ReportBuilder.build_json_report(
            scan_id=self.scan_id,
            target_url=self.context.target_url,
            findings=all_findings
        )

        self.send_live_log("[+] Assessment pipeline concluded successfully.")
        return report_json