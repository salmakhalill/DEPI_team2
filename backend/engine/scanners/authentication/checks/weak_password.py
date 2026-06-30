from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from .param_mapper import map_auth_payload
from engine.analyzer.response_analyzer import ResponseAnalyzer 

async def check_weak_password(client, ep: Endpoint, cases: list, log_callback) -> list:
    findings = []
    
    for case in cases:
        payload = case.get("payload", "123")
        test_data = map_auth_payload(ep.params, payload)

        response = await client.request('POST', ep.url, data=test_data, follow_redirects=False)
        if not response.success: 
            continue

        is_vulnerable = ResponseAnalyzer.is_auth_successful(response.status_code, response.headers, response.text)

        if is_vulnerable:
            findings.append(Finding(
                title="Weak Password Policy",
                owasp_category="A07:2021 - Identification and Authentication Failures",
                threat_level=case.get("severity", "Medium"), cvss_score=case.get("cvss", "5.3"),
                affected_path=f"POST {ep.url}",
                description=case.get("description", f"The registration engine accepted the weak password '{payload}'."),
                business_impact="Allows users to anchor accounts with trivial entries.",
                recommendations=["Enforce strict length limits (12+ characters)."],
                references=["https://owasp.org/www-community/vulnerabilities/Weak_password_requirements"],
                proof_of_concept=ProofOfConcept(
                    intro_text=f"The endpoint provisioned a user session utilizing the weak password string '{payload}'.",
                    steps_to_reproduce=[f"1. Transmit account creation data to {ep.url}.", f"2. Pass payload '{payload}'."],
                    evidence=Evidence(type="http_snippet", request=f"POST {ep.url} HTTP/1.1\n[Password Context: {payload}]", response=f"HTTP/1.1 {response.status_code}\nLocation: {response.headers.get('location', 'N/A')}")
                )
            ))
            break 
    return findings