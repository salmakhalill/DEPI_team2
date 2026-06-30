import re
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Any
from engine.models.endpoint import Endpoint, Parameter

class ParamExtractor:
    """
    Parses raw crawler data (links and forms) into structured Endpoint and Parameter objects.
    Applies structural deduplication to minimize the attack surface to unique logic paths.
    """
    
    @staticmethod
    def extract(crawl_data: Dict[str, Any]) -> List[Endpoint]:
        endpoints_map = {}
        
        links = crawl_data.get("links", [])
        forms = crawl_data.get("forms", [])
        
        # 1. Process GET Links with Structural Deduplication
        for url in links:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            
            # Map raw query strings to structured Parameter objects
            param_objs = []
            for k, v in qs.items():
                val = v[0] if v else ""
                param_objs.append(Parameter(name=k, value=val, param_type="query"))
            
            structural_path = re.sub(r'/\d+', '/[ID]', parsed.path)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            structural_url = f"{parsed.scheme}://{parsed.netloc}{structural_path}"
            
            key = f"GET|{structural_url}"
            if key not in endpoints_map:
                endpoints_map[key] = Endpoint(
                    url=base_url,
                    method="GET", 
                    params=param_objs,
                    original_query=parsed.query,
                    source="crawler"
                )
            else:
                # Merge logic to avoid parameter duplication across similar structural paths
                existing_names = {p.name for p in endpoints_map[key].params}
                for p in param_objs:
                    if p.name not in existing_names:
                        endpoints_map[key].params.append(p)

        # 2. Process HTML Forms
        for form in forms:
            action_url = form.get("action")
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])
            file_inputs = form.get("file_inputs", [])
            
            # Determine parameter location based on HTTP method
            param_type = "body" if method in ["POST", "PUT", "PATCH"] else "query"
            param_objs = [Parameter(name=inp, value="", param_type=param_type) for inp in inputs]
            
            parsed = urlparse(action_url)
            structural_path = re.sub(r'/\d+', '/[ID]', parsed.path)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            structural_url = f"{parsed.scheme}://{parsed.netloc}{structural_path}"
            
            key = f"{method}|{structural_url}"
            if key not in endpoints_map:
                endpoints_map[key] = Endpoint(
                    url=base_url, 
                    method=method, 
                    params=param_objs,
                    file_inputs=file_inputs,
                    source="form"
                )
            else:
                existing_names = {p.name for p in endpoints_map[key].params}
                for p in param_objs:
                    if p.name not in existing_names:
                        endpoints_map[key].params.append(p)
                endpoints_map[key].file_inputs = list(set(endpoints_map[key].file_inputs + file_inputs))
                
        endpoints_list = list(endpoints_map.values())
        
        # 3. Classification: Tag endpoints based on heuristics
        for ep in endpoints_list:
            url_lower = ep.url.lower()
            if any(kw in url_lower for kw in ['login', 'signin', 'auth']):
                ep.type = 'login'
            elif any(kw in url_lower for kw in ['register', 'signup']):
                ep.type = 'register'
            elif any(kw in url_lower for kw in ['upload', 'import']) or len(ep.file_inputs) > 0:
                ep.type = 'upload'
            else:
                ep.type = 'general'
                
        return endpoints_list