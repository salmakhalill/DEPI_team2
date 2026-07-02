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
                description=(
                    case.get("description") or
                    f"The registration endpoint '{ep.url}' accepted the password '{payload}' without "
                    f"enforcing minimum length or complexity requirements, confirming the absence of "
                    f"server-side password strength validation."
                ),
                business_impact=(
                    "Accounts secured with trivially guessable passwords are highly vulnerable to "
                    "brute-force and dictionary attacks. A single compromised account can serve as an "
                    "entry point for broader unauthorized access to NexusFlow user data."
                ),
                recommendations=["Enforce strict length limits (12+ characters)."],
                references=["https://owasp.org/www-community/vulnerabilities/Weak_password_requirements"],
                proof_of_concept=ProofOfConcept(
                    intro_text=f"Submitted registration data using the weak password '{payload}' to '{ep.url}' and confirmed successful account creation.",
                    steps_to_reproduce=[
                        f"1. Submit a registration request to '{ep.url}' using password '{payload}'.",
                        "2. Confirm the server responds with a success status rather than a validation error."
                    ],
                    evidence=Evidence(type="http_snippet", request=f"POST {ep.url} HTTP/1.1\n[Password Context: {payload}]", response=f"HTTP/1.1 {response.status_code}\nLocation: {response.headers.get('location', 'N/A')}")
                )
            ))
            break 
    return findings