from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

class PlaywrightSpider:
    """
    Automated web crawler using Playwright.
    Responsible for discovering URLs and HTML forms within the target domain boundaries.
    """

    def __init__(self, target_url: str, cookies: dict = None, log_callback=None):
        self.target_url = target_url
        self.domain = urlparse(target_url).hostname 
        self.cookies = cookies or {}
        self.discovered_urls = set()
        self.discovered_forms = []
        self.log_callback = log_callback

    def _format_cookies_for_playwright(self) -> list:
        """
        Formats the provided cookies for Playwright context injection.
        Relies on the target URL to establish domain and path context natively,
        avoiding explicit secure/httpOnly overrides to preserve true target state.
        """
        formatted = []
        for name, value in self.cookies.items():
            formatted.append({
                "name": name,
                "value": value,
                "url": self.target_url
            })
        return formatted

    def _handle_response(self, response):
        """Event handler for network responses to capture passive URLs."""
        url = response.url
        if urlparse(url).hostname == self.domain:
            self.discovered_urls.add(url)

    def crawl(self, max_pages: int = 60) -> dict:
        """
        Executes the crawling process up to the specified max_pages limit.
        Returns a dictionary containing discovered links and forms.
        """
        to_visit = [self.target_url]
        visited = set()
        
        static_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.woff', '.woff2', '.ttf']
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)
            
            # Inject session cookies if provided
            if self.cookies:
                context.add_cookies(self._format_cookies_for_playwright())
                
                raw_cookie_string = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
                context.set_extra_http_headers({
                    "Cookie": raw_cookie_string,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.9"
                })
                
            page = context.new_page()
            page.on("response", self._handle_response)
            
            try:
                msg = "[Spider] Initializing authenticated browser context..."
                print(f"  {msg}")
                if self.log_callback:
                    self.log_callback(msg)
                
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
                
                # Skip already visited pages and static assets
                if normalized_url in visited or any(current_url.endswith(ext) for ext in static_extensions):
                    continue
                    
                visited.add(normalized_url)
                
                msg = f"[Spider] Crawling: {current_url}"
                print(f"  {msg}")
                if self.log_callback:
                    self.log_callback(msg)
                
                try:
                    page.goto(current_url, wait_until="load", timeout=12000)
                    
                    # Extract URLs
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
                            
                    # Extract HTML Forms and input structural data
                    forms = page.evaluate("""() => {
                        return Array.from(document.forms).map(f => {
                            let file_inputs = Array.from(f.elements).filter(e => e.type === 'file').map(e => e.name);
                            let all_inputs = Array.from(f.elements).filter(e => e.name).map(e => e.name);
                            return {
                                action: f.action || document.location.href,
                                method: f.method || 'GET',
                                inputs: all_inputs,
                                file_inputs: file_inputs
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