from engine.models.http_context import HttpResponse

class FingerprintAnalyzer:
    """
    Identifies target infrastructure components, frameworks, and protective layers (WAFs).
    Used to establish scan contexts and optimize payloads dynamically.
    """

    @staticmethod
    def detect_framework(response: HttpResponse) -> str:
        server_header = response.headers.get('server', '').lower()
        powered_by = response.headers.get('x-powered-by', '').lower()
        text_lower = response.text.lower()
        
        if 'werkzeug' in server_header or 'flask' in text_lower or 'gunicorn' in server_header:
            return 'flask/python'
        elif 'express' in powered_by or 'node' in powered_by:
            return 'express/node'
        elif 'php' in powered_by or 'php' in server_header:
            return 'php'
        return 'unknown'

    @staticmethod
    def detect_waf(response: HttpResponse) -> bool:
        server_header = response.headers.get('server', '').lower()
        
        # Explicit WAF headers
        waf_headers = ['cf-ray', 'x-amz-cf-id', 'x-sucuri-id']
        if 'cloudflare' in server_header:
            return True
        if any(h in response.headers for h in waf_headers):
            return True
            
        # Behavioral block detection
        if response.status_code in [403, 406, 429]:
            text_lower = response.text.lower()
            if 'waf' in text_lower or 'not acceptable' in text_lower or 'forbidden' in text_lower:
                return True
                
        return False