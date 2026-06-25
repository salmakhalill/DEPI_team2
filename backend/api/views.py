import os
import time
import threading
import traceback
import asyncio
import platform
import tempfile # Secure cross-platform file path handling (Windows/Linux)
from django.utils import timezone
from django.http import FileResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Scan
from engine.orchestrator import Orchestrator
from engine.core.http_client import SafeHttpClient
from reporter.report_generator import generate_pdf 

# 1. Dynamic list of all available scanners.
from engine.scanners.sqli_scanner import SQLInjectionScanner
# from engine.scanners.xss_scanner import XSSScanner  

AVAILABLE_SCANNERS = [
    SQLInjectionScanner,
    # XSSScanner,
]

def run_scan_in_background(scan_id, target_url, dynamic_cookies):
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    time.sleep(10) # TODO: Refactor this blocking call when migrating to Celery

    try:
        scan = Scan.objects.get(id=scan_id)
        orchestrator = Orchestrator(scan_id=scan_id, target_url=target_url, cookies=dynamic_cookies)
        client = SafeHttpClient(cookies=dynamic_cookies, allow_local=True)
        
        # 2. Dynamically register all scanners without code duplication (Open/Closed Principle)
        for ScannerClass in AVAILABLE_SCANNERS:
            scanner_instance = ScannerClass(
                target_url, 
                client, 
                log_callback=orchestrator.send_live_log
            )
            orchestrator.register_scanner(scanner_instance)
        
        final_report_json = orchestrator.run_assessment()
        
        scan.status = 'Completed'
        scan.end_time = timezone.now()
        scan.overall_threat_level = final_report_json.get("executive_summary", {}).get("overall_threat_level", "Unknown")
        scan.full_report_json = final_report_json
        scan.save()
        
        orchestrator.send_live_log(f"[+] Scan {scan_id} Completed Successfully!")
        print(f"[+] Scan {scan_id} Completed Successfully!")
        
    except Exception as e:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'Failed'
        scan.save()
        
        print(f"[-] Scan {scan_id} Failed with exception:")
        traceback.print_exc() 
        
        try:
            orchestrator.send_live_log(f"[-] Fatal Scan Error: {str(e)}")
        except:
            pass
    finally:
        loop.close()

class StartScanView(APIView):
    def post(self, request):
        target_url = request.data.get('target_url')
        raw_cookie_header = request.data.get('raw_cookie_header', '')

        if not target_url:
            return Response({"error": "target_url is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Removed the hardcoded '/dashboard' redirection logic. 
        # It breaks the tool's flexibility across different web applications.
        
        dynamic_cookies = {}
        if raw_cookie_header:
            clean_header = raw_cookie_header.replace("Cookie:", "").replace("cookie:", "").strip()
            for chunk in clean_header.split(';'):
                chunk = chunk.strip()
                if '=' in chunk:
                    key, val = chunk.split('=', 1)
                    if key.strip().lower() not in ['path', 'domain', 'httponly', 'secure', 'samesite']:
                        dynamic_cookies[key.strip()] = val.strip()

        scan = Scan.objects.create(target_url=target_url)
        
        thread = threading.Thread(target=run_scan_in_background, args=(scan.id, target_url, dynamic_cookies))
        thread.start()

        return Response({"message": "Scan started.", "scan_id": scan.id, "status": scan.status}, status=status.HTTP_201_CREATED)
    
class DownloadReportView(APIView):
    def get(self, request, scan_id):
        try:
            scan = Scan.objects.get(id=scan_id)
        except Scan.DoesNotExist:
            return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

        if scan.status != 'Completed' or not scan.full_report_json:
            return Response({"error": "Report not ready"}, status=status.HTTP_400_BAD_REQUEST)

        # 3. Fixed file path using tempfile to ensure cross-platform compatibility (Windows/Linux)
        temp_dir = tempfile.gettempdir()
        output_pdf_path = os.path.join(temp_dir, f"NexusFlow_Report_{scan_id}.pdf")
        
        generate_pdf(scan.full_report_json, output_pdf_path)

        if os.path.exists(output_pdf_path):
            response = FileResponse(open(output_pdf_path, 'rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="Penetration_Test_Report_{scan_id}.pdf"'
            return response
            
        return Response({"error": "Failed to locate generated PDF file"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)