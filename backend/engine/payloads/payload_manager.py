import os
import json
from typing import List, Dict, Any

class PayloadManager:
    """
    Centralized Payload Manager.
    Reads payloads from text files so scanners remain logic-only.
    """
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    @classmethod
    def get_payloads(cls, vulnerability_type: str) -> List[Dict[str, Any]]:
        file_path = os.path.join(cls.BASE_DIR, f"{vulnerability_type.lower()}.json")
        
        if not os.path.exists(file_path):
            print(f"[-] Warning: Payload file {file_path} not found.")
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get("cases", [])
        except json.JSONDecodeError:
            print(f"[-] Error: Invalid JSON format in {file_path}")
            return []