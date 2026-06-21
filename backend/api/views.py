import threading
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Scan
from engine.orchestrator import Orchestrator
from engine.core.http_client import SafeHttpClient
from reporter.report_generator import generate_pdf

# Import Scanners here
# from engine.scanners.xss_scanner import ReflectedXSSScanner
# from engine.scanners.sqli_scanner import SQLInjectionScanner

def run_scan_in_background(scan_id, target_url, dynamic_cookies):
    """
    This function runs in the background. It updates the DB when the scan finishes.
    Later, we will add WebSocket signals here to update the Frontend live.
    """
    try:
        scan = Scan.objects.get(id=scan_id)
        
        # Initialize the Orchestrator
        orchestrator = Orchestrator(target_url=target_url, cookies=dynamic_cookies)
        client = SafeHttpClient(cookies=dynamic_cookies, allow_local=True)
        
        # Register Scanners (Team will add them here)
        # orchestrator.register_scanner(ReflectedXSSScanner(target_url, client))
        # orchestrator.register_scanner(SQLInjectionScanner(target_url, client))
        
        # Run the assessment (This takes time)
        final_report_json = orchestrator.run_assessment()
        
        # Update the database with the results
        scan.status = 'Completed'
        scan.overall_threat_level = final_report_json.get("executive_summary", {}).get("overall_threat_level", "Unknown")
        scan.full_report_json = final_report_json
        scan.save()
        
        print(f"[+] Scan {scan_id} Completed Successfully!")

    except Exception as e:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'Failed'
        scan.save()
        print(f"[-] Scan {scan_id} Failed: {str(e)}")


def parse_raw_cookies(raw_string: str) -> dict:
    parsed = {}
    if not raw_string: return parsed
    for chunk in raw_string.split(';'):
        if '=' in chunk:
            key, val = chunk.split('=', 1)
            parsed[key.strip()] = val.strip()
    return parsed


class StartScanView(APIView):
    def post(self, request):
        target_url = request.data.get('target_url')
        raw_cookie_header = request.data.get('raw_cookie_header', '')

        if not target_url:
            return Response({"error": "target_url is required"}, status=status.HTTP_400_BAD_REQUEST)

        # 1. Parse cookies
        dynamic_cookies = parse_raw_cookies(raw_cookie_header)

        # 2. Create the Scan in the Database (Status: Running)
        scan = Scan.objects.create(target_url=target_url)

        # 3. Start the background thread so the HTTP request doesn't block
        thread = threading.Thread(
            target=run_scan_in_background, 
            args=(scan.id, target_url, dynamic_cookies)
        )
        thread.start()

        # 4. Return the Scan ID to the frontend immediately
        return Response({
            "message": "Scan started successfully.",
            "scan_id": scan.id,
            "status": scan.status
        }, status=status.HTTP_201_CREATED)
    

class DownloadReportView(APIView):
    def get(self, request, scan_id):
        try: scan = Scan.objects.get(id=scan_id)
        except Scan.DoesNotExist: return Response({"error": "Not found"}, status=status.HTTP_404_NOT_FOUND)
        if scan.status != 'Completed' or not scan.full_report_json:
            return Response({"error": "Report not ready"}, status=status.HTTP_400_BAD_REQUEST)

        output_pdf_path = f"/tmp/NexusFlow_Report_{scan_id}.pdf"
        generate_pdf(scan.full_report_json, 'report_template.html', output_pdf_path)

        if os.path.exists(output_pdf_path):
            response = FileResponse(open(output_pdf_path, 'rb'), content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="Penetration_Test_Report.pdf"'
            return response
        return Response({"error": "Generation Failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)