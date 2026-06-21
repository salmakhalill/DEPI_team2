from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any
from engine.models.endpoint import Endpoint

class ParamExtractor:
    @staticmethod
    def extract(crawl_data: Dict[str, Any]) -> List[Endpoint]:
        endpoints_map = {}
        
        links = crawl_data.get("links", [])
        forms = crawl_data.get("forms", [])
        
        # 1. Process standard URLs with or without query parameters
        for url in links:
            parsed = urlparse(url)
            # extract ?id=1&q=test into a list ['id', 'q']
            params = list(parse_qs(parsed.query).keys())
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # create a unique signature to avoid duplicate scans on the same endpoint
            key = f"GET|{base_url}"
            if key not in endpoints_map:
                endpoints_map[key] = Endpoint(
                    url=base_url, 
                    method="GET", 
                    params=params,
                    original_query=parsed.query
                )
            else:
                # merge params if we found the same URL with different parameters later
                endpoints_map[key].params = list(set(endpoints_map[key].params + params))

        # 2. Process HTML Forms (POST/GET) and their inputs
        for form in forms:
            action_url = form.get("action")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            
            parsed = urlparse(action_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            key = f"{method}|{base_url}"
            if key not in endpoints_map:
                endpoints_map[key] = Endpoint(
                    url=base_url, 
                    method=method, 
                    params=inputs
                )
            else:
                endpoints_map[key].params = list(set(endpoints_map[key].params + inputs))
                
        return list(endpoints_map.values())