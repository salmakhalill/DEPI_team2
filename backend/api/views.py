import os
import threading
from django.utils import timezone
from django.http import FileResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import Scan
from engine.orchestrator import Orchestrator
from engine.core.http_client import SafeHttpClient
from tests.pdf_test.report_generator import generate_pdf 

def run_scan_in_background(scan_id, target_url, dynamic_cookies):
    try:
        scan = Scan.objects.get(id=scan_id)
        orchestrator = Orchestrator(target_url=target_url, cookies=dynamic_cookies)
        client = SafeHttpClient(cookies=dynamic_cookies, allow_local=True)
        
        # Team will register active scanning plugins here
        # orchestrator.register_scanner(SQLInjectionScanner(target_url, client))
        
        final_report_json = orchestrator.run_assessment()
        
        scan.status = 'Completed'
        scan.end_time = timezone.now()
        scan.overall_threat_level = final_report_json.get("executive_summary", {}).get("overall_threat_level", "Unknown")
        scan.full_report_json = final_report_json
        scan.save()
        print(f"[+] Scan {scan_id} Completed Successfully!")
    except Exception as e:
        scan = Scan.objects.get(id=scan_id)
        scan.status = 'Failed'
        scan.save()
        print(f"[-] Scan {scan_id} Failed: {str(e)}")

class StartScanView(APIView):
    def post(self, request):
        target_url = request.data.get('target_url')
        raw_cookie_header = request.data.get('raw_cookie_header', '')

        if not target_url:
            return Response({"error": "target_url is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Automatic Seed URL Redirection for Authenticated Frameworks (Flask/Django SaaS)
        # If user submits root URL, append /dashboard to puncture the auth layer directly
        from urllib.parse import urlparse
        parsed_target = urlparse(target_url)
        if parsed_target.path == "" or parsed_target.path == "/":
            target_url = f"{parsed_target.scheme}://{parsed_target.netloc}/dashboard"
            print(f"[*] Root URL detected. Automatically routing seed path to: {target_url}")

        # Robust Cookie Sanitization Matrix
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

        output_pdf_path = f"/tmp/NexusFlow_Report_{scan_id}.pdf"
        
        generate_pdf(scan.full_report_json, 'static_content.json', 'report_template.html', output_pdf_path)

        if os.path.exists(output_pdf_path):
            response = FileResponse(open(output_pdf_path, 'rb'), content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="Penetration_Test_Report.pdf"'
            return response
        return Response({"error": "Generation Failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)