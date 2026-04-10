import requests

def scan_xss(url):
    payload = "<script>alert(1)</script>"
    test_url = url + "?q=" + payload
    response = requests.get(test_url)
    if payload in response.text:
        return {
            "vulnerability_name": "Reflected XSS",
            "is_vulnerable": True,
            "payload_used": payload,
            "technical_steps": [
                {"action": "Request Sent", "details": f"GET {test_url}"},
                {"action": "Server Response", "details": "HTTP 200. Payload reflected."}
            ]
        }
    else:
        return {
            "vulnerability_name": "Reflected XSS",
            "is_vulnerable": False,
            "payload_used": payload,
            "technical_steps": [
                {"action": "Request Sent", "details": f"GET {test_url}"},
                {"action": "Server Response", "details": "Payload not reflected. Safe."}
            ]
        }

if __name__ == "__main__":
    url = input("Enter the URL to scan:")
    result = scan_xss(url)
    print(result)