from urllib.parse import urlparse, parse_qs

class EndpointExtractor:
    
    @staticmethod
    def extract(links, forms):
        """
        Unify GET links and POST forms into a single standardized 
        structure for the scanners to use directly.
        """
        endpoints = []
        
        # Process standard URLs with query parameters
        for url in links:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if params:
                endpoints.append({
                    "url": url.split('?')[0],
                    "method": "GET",
                    "params": list(params.keys())
                })
                
        # Process HTML forms
        for form in forms:
            if form["params"]:
                endpoints.append({
                    "url": form["url"],
                    "method": form["method"],
                    "params": form["params"]
                })
                
        return endpoints