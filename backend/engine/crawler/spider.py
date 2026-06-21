from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

class PlaywrightSpider:
    # FIX: Added log_callback to the constructor to stream real-time logs
    def __init__(self, target_url: str, cookies: dict = None, log_callback=None):
        self.target_url = target_url
        self.domain = urlparse(target_url).hostname 
        self.cookies = cookies or {}
        self.discovered_urls = set()
        self.discovered_forms = []
        self.log_callback = log_callback

    def _format_cookies_for_playwright(self) -> list:
        formatted = []
        for name, value in self.cookies.items():
            formatted.append({
                "name": name,
                "value": value,
                "domain": self.domain,
                "path": "/",
                # Explicitly override security flags to force Chromium state synchronization
                "httpOnly": True,
                "secure": False,
                "sameSite": "Lax"
            })
        return formatted

    def _handle_response(self, response):
        url = response.url
        if urlparse(url).hostname == self.domain:
            self.discovered_urls.add(url)

    def crawl(self, max_pages: int = 60) -> dict:
        to_visit = [self.target_url]
        visited = set()
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            
            # Layer 1: Inject Structural Storage Jar Parameters (Crucial for Flask Sessions)
            if self.cookies:
                context.add_cookies(self._format_cookies_for_playwright())
                
                # Layer 2: Force Global Raw String Headers Injection Fallback
                raw_cookie_string = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
                context.set_extra_http_headers({
                    "Cookie": raw_cookie_string,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9"
                })
                
            page = context.new_page()
            page.on("response", self._handle_response)
            
            try:
                # Local terminal print
                print(f"  [Spider] Injecting forced structural authentication mapping layer...")
                # WebSocket Live Broadcast
                if self.log_callback:
                    self.log_callback("🕸️ [Spider] Injecting forced structural authentication mapping layer...")
                
                # Force browser context execution flow to settle down completely
                page.goto(self.target_url, wait_until="networkidle", timeout=15000)
                page.wait_for_timeout(2000) 
                
                resolved_url = page.url
                if resolved_url not in to_visit:
                    to_visit.append(resolved_url)
            except Exception as e:
                print(f"  [-] Session initialization warning: {str(e)}")
            
            while to_visit and len(visited) < max_pages:
                current_url = to_visit.pop(0)
                normalized_url = current_url.rstrip('/').split('#')[0]
                
                if normalized_url in visited or any(current_url.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.gif']):
                    continue
                    
                visited.add(normalized_url)
                
                # Local terminal print
                print(f"  [Spider] Crawling: {current_url}")
                # WebSocket Live Broadcast (The waterfall effect!)
                if self.log_callback:
                    self.log_callback(f"🕸️ [Spider] Crawling: {current_url}")
                
                try:
                    page.goto(current_url, wait_until="load", timeout=12000)
                    
                    hrefs = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a')).map(a => a.href);
                    }""")
                    
                    for href in hrefs:
                        if href:
                            clean_href = href.split('#')[0].rstrip('/')
                            if urlparse(clean_href).hostname == self.domain:
                                self.discovered_urls.add(href)
                                if clean_href not in visited and href not in to_visit:
                                    to_visit.append(href)
                            
                    forms = page.evaluate("""() => {
                        return Array.from(document.forms).map(f => {
                            return {
                                action: f.action || document.location.href,
                                method: f.method || 'GET',
                                inputs: Array.from(f.elements).filter(e => e.name).map(e => e.name)
                            };
                        });
                    }""")
                    self.discovered_forms.extend(forms)
                            
                except PlaywrightTimeoutError:
                    pass 
                except Exception:
                    pass
                    
            browser.close()
                
        return {
            "links": list(self.discovered_urls),
            "forms": self.discovered_forms
        }