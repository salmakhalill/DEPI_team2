import time
import requests
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

# Suppress SSL warnings for local or testing targets
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SafeHttpClient:
    def __init__(self, headers=None, cookies=None, delay=0.5, timeout=10):
        self.session = requests.Session()
        self.delay = delay
        self.timeout = timeout

        # Spoof a standard browser to bypass basic WAFs
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })

        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        # Configure retry strategy for flaky connections
        retries = Retry(
            total=3, 
            backoff_factor=0.5, 
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def _is_safe_url(self, url):
        # Basic SSRF protection to prevent internal network scanning
        parsed = urlparse(url)
        forbidden_hosts = ['localhost', '127.0.0.1', '0.0.0.0']
        return parsed.hostname not in forbidden_hosts

    def request(self, method, url, **kwargs):
        if not self._is_safe_url(url):
            return None
        
        # Rate limiting to avoid overloading the target
        if self.delay > 0:
            time.sleep(self.delay)
            
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', False)
        
        try:
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.RequestException:
            # Silently handle network errors to keep the scanner running
            return None

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)