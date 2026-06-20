import time
import requests
import urllib3
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from engine.models.http_context import HttpResponse

# suppress warnings for labs or self-signed cert targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SafeHttpClient:
    def __init__(self, headers=None, cookies=None, delay=0.5, timeout=10):
        self.session = requests.Session()
        self.delay = delay
        self.timeout = timeout

        # spoof user-agent to bypass trivial defense filters
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })

        if headers: self.session.headers.update(headers)
        if cookies: self.session.cookies.update(cookies)

        # network retry loop for flaky services
        retries = Retry(
            total=3, 
            backoff_factor=0.5, 
            status_forcelist=[429, 500, 502, 503, 504]
        )
        self.session.mount('http://', HTTPAdapter(max_retries=retries))
        self.session.mount('https://', HTTPAdapter(max_retries=retries))

    def _is_safe_url(self, url):
        # ssrf mitigation: isolate core server from private subnets
        parsed = urlparse(url)
        forbidden = ['localhost', '127.0.0.1', '0.0.0.0', '192.168.', '10.']
        return not any(host in (parsed.hostname or "") for host in forbidden)

    def request(self, method, url, **kwargs) -> HttpResponse:
        if not self._is_safe_url(url):
            return HttpResponse(success=False, error_message="SSRF Blocked: Destination host is restricted")
        
        if self.delay > 0:
            time.sleep(self.delay)
            
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        
        try:
            res = self.session.request(method, url, **kwargs)
            return HttpResponse(
                success=True,
                status_code=res.status_code,
                text=res.text,
                headers=dict(res.headers)
            )
        except requests.exceptions.Timeout:
            return HttpResponse(success=False, error_message="Target connection timed out")
        except requests.exceptions.RequestException as e:
            # capture connection errors without throwing unhandled failures
            return HttpResponse(success=False, error_message=str(e))

    def get(self, url, **kwargs) -> HttpResponse:
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs) -> HttpResponse:
        return self.request('POST', url, **kwargs)