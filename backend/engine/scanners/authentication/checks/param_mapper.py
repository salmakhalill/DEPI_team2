import random
import string
from typing import List, Dict, Any

def map_auth_payload(params: List[Any], password_payload: str = "InvalidPass123!") -> Dict[str, str]:
    test_data = {}
    entropy = "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
    
    for p in (params or []):
        param_name = getattr(p, 'name', str(p))
        p_lower = param_name.lower()
        
        if any(k in p_lower for k in ["user", "mail", "login", "account"]):
            test_data[param_name] = f"scan_{entropy}@test.local"
        elif any(k in p_lower for k in ["pass", "pwd", "key", "secret"]):
            test_data[param_name] = password_payload
        elif any(k in p_lower for k in ["name", "first", "last"]):
            test_data[param_name] = f"Scanner {entropy}"
        else:
            test_data[param_name] = "test_value"
            
    if not test_data:
        test_data = {"username": f"scan_{entropy}", "password": password_payload}
        
    return test_data