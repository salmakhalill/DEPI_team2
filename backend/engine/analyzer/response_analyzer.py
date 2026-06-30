import html
from engine.models.http_context import HttpResponse

class ResponseAnalyzer:
    """
    Centralized intelligence layer for analyzing HTTP responses.
    Abstracts complex verification logic away from individual scanners to eliminate 
    false positives and enforce strict vulnerability criteria globally.
    """

    @staticmethod
    def is_boolean_variance(baseline: HttpResponse, true_resp: HttpResponse, false_resp: HttpResponse, true_payload: str = "", false_payload: str = "") -> bool:
        """
        Validates Blind SQLi by stripping reflected payloads and filtering CSRF noise.
        """
        # 1. Ignore server crashes (If both are 500, it's just a broken endpoint, not a boolean shift)
        if true_resp.status_code >= 400 and false_resp.status_code >= 400:
            return False

        # 2. Explicit Status Code Shifts (e.g., True is 200, False is 404/500)
        if true_resp.status_code != false_resp.status_code:
            if true_resp.status_code in [200, 201, 301, 302, 303]:
                return True

        # 3. Reflection Stripping: Remove the injected payloads from the response text to cancel out length differences
        true_text = true_resp.text.replace(true_payload, "") if true_payload else true_resp.text
        false_text = false_resp.text.replace(false_payload, "") if false_payload else false_resp.text

        true_size = len(true_text)
        false_size = len(false_text)
        
        # 4. Strict Structural Variance Check
        # A genuine SQLi alters database output (rows returned vs empty).
        # We enforce a strict >150 bytes difference to safely ignore CSRF tokens and timestamps.
        size_diff = abs(true_size - false_size)
        
        if size_diff > 150 or size_diff > (len(baseline.text) * 0.03):
            return True
            
        return False

    @staticmethod
    def get_xss_context(response_text: str, payload: str) -> dict:
        """
        Analyzes DOM context to differentiate raw execution from safe reflections (HTML encoded).
        """
        idx = response_text.find(payload)
        if idx == -1:
            return {"is_reflected": False, "is_escaped": False, "context_snippet": ""}
            
        context_snippet = response_text[max(0, idx-50) : idx+len(payload)+50]
        is_html_escaped = html.escape(payload) in response_text
        
        return {
            "is_reflected": True,
            # If the payload was found but HTML escaped, the framework mitigated it.
            "is_escaped": is_html_escaped, 
            "context_snippet": context_snippet
        }
        
    @staticmethod
    def has_new_signature(baseline_text: str, response_text: str, compiled_regex) -> getattr:
        """
        Checks if a regex matches the response but guarantees it wasn't already in the baseline.
        Perfect for LFI, Error-based SQLi, and Verbose Errors.
        """
        if not compiled_regex:
            return None
            
        match = compiled_regex.search(response_text)
        if match:
            # Ensure it's not a natural false positive from the baseline response
            if not compiled_regex.search(baseline_text):
                return match
        return None
    
    @staticmethod
    def analyze_session_flags(set_cookie_header: str, required_flags: list) -> list:
        header_lower = set_cookie_header.lower()
        return [flag for flag in required_flags if flag.lower() not in header_lower]

    @staticmethod
    def is_auth_successful(status_code: int, headers: dict, body: str) -> bool:
        success_redirect_targets = ["dashboard", "profile", "welcome", "home", "index", "account"]
        success_keywords = ["dashboard", "welcome", "profile", "logout", "account", "success"]
        
        if status_code in [301, 302, 303]:
            redirect_location = headers.get("location", "").lower()
            return any(target in redirect_location for target in success_redirect_targets)
        elif status_code in [200, 201]:
            body_lower = body.lower()
            return any(keyword in body_lower for keyword in success_keywords)
        return False