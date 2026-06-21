from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

class PlaywrightSpider:
    def __init__(self, target_url: str, cookies: dict = None):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc
        self.cookies = cookies or {}
        self.discovered_urls = set()
        self.discovered_forms = []

    def _format_cookies_for_playwright(self) -> list:
        formatted = []
        for name, value in self.cookies.items():
            formatted.append({
                "name": name,
                "value": value,
                "domain": self.domain,
                "path": "/"
            })
        return formatted

    def _handle_response(self, response):
        url = response.url
        if urlparse(url).netloc == self.domain:
            self.discovered_urls.add(url)

    def crawl(self, max_pages: int = 20) -> dict:
        to_visit = [self.target_url]
        visited = set()
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            
            if self.cookies:
                context.add_cookies(self._format_cookies_for_playwright())
                
            page = context.new_page()
            page.on("response", self._handle_response)
            
            # Deep Crawl Loop
            while to_visit and len(visited) < max_pages:
                current_url = to_visit.pop(0)
                
                # skip already visited or static files
                if current_url in visited or any(current_url.endswith(ext) for ext in ['.css', '.js', '.png', '.jpg']):
                    continue
                    
                visited.add(current_url)
                print(f"  [Spider] Crawling: {current_url}")
                
                try:
                    # use domcontentloaded for faster crawling instead of networkidle
                    page.goto(current_url, wait_until="domcontentloaded", timeout=10000)
                    
                    # Extract links
                    hrefs = page.evaluate("""() => {
                        return Array.from(document.querySelectorAll('a')).map(a => a.href);
                    }""")
                    
                    for href in hrefs:
                        if href and urlparse(href).netloc == self.domain:
                            self.discovered_urls.add(href)
                            if href not in visited and href not in to_visit:
                                to_visit.append(href)
                            
                    # Extract HTML forms
                    forms = page.evaluate("""() => {
                        return Array.from(document.forms).map(f => {
                            return {
                                action: f.action || document.location.href,
                                method: f.method || 'GET',
                                inputs: Array.from(f.elements)
                                    .filter(e => e.name)
                                    .map(e => e.name)
                            };
                        });
                    }""")
                    self.discovered_forms.extend(forms)
                            
                except PlaywrightTimeoutError:
                    pass # silently skip slow pages during crawl
                except Exception as e:
                    pass
                    
            browser.close()
                
        return {
            "links": list(self.discovered_urls),
            "forms": self.discovered_forms
        }