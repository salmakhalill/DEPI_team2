import os
import json
import re
from typing import Dict, Any

class PayloadManager:
    """
    Centralized Payload Manager mapping vulnerability types to their specific family directories.
    Implements pre-compilation of Regex signatures and in-memory caching for high performance.
    """
    BASE_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "definitions"
    )

    FAMILY_MAP = {
        "sqli": "injection",
        "xss": "injection",
        "authentication": "authentication",
        "verbose_error": "disclosure",
        "idor": "authorization",           
        "sensitive_file": "file_security",
        "path_traversal": "file_security",
        "lfi": "file_security",
        "file_upload": "file_security",
    }

    _payloads: Dict[str, Any] = {}
    _is_loaded = False

    @classmethod
    def load_payloads(cls) -> None:
        if cls._is_loaded:
            return

        if not os.path.exists(cls.BASE_DIR):
            print(f"[-] Warning: Knowledge base directory not found at {cls.BASE_DIR}")
            return

        # Load and pre-compile all JSON definitions in the background
        for root, _, files in os.walk(cls.BASE_DIR):
            for file in files:
                if file.endswith('.json'):
                    module_name = file.replace('.json', '')
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            cls._payloads[module_name] = cls._pre_compile_signatures(data)
                    except json.JSONDecodeError:
                        print(f"[-] Error: Invalid JSON format in {file_path}")
                    except Exception as e:
                        print(f"[-] Error loading payload module {file}: {str(e)}")
        
        cls._is_loaded = True

    @classmethod
    def _pre_compile_signatures(cls, data: Any) -> Any:
        """Recursively compiles regex patterns during load time to save CPU cycles during scans."""
        if not isinstance(data, dict):
            return data
        
        cases = data.get("cases", [])
        for case in cases:
            # Compile standard match_regex
            match_regex = case.get("match_regex")
            if match_regex:
                try:
                    case["compiled_regex"] = re.compile(match_regex, re.IGNORECASE)
                except re.error:
                    case["compiled_regex"] = None

            # Compile multiple signatures array (used in Sensitive File Disclosure)
            signatures = case.get("signatures")
            if signatures and isinstance(signatures, list):
                case["compiled_signatures"] = []
                for sig in signatures:
                    try:
                        case["compiled_signatures"].append(re.compile(sig, re.IGNORECASE))
                    except re.error:
                        pass

        return data

    @classmethod
    def get_payloads(cls, vulnerability_type: str) -> Dict[str, Any]:
        if not cls._is_loaded:
            cls.load_payloads()
        return cls._payloads.get(vulnerability_type.lower(), {})