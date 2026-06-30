from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from .param_mapper import map_auth_payload
from engine.analyzer.response_analyzer import ResponseAnalyzer 

async def check_session_flags(client, ep: Endpoint, config: dict, log_callback) -> tuple:
    response = await client.request(ep.method, ep.url, follow_redirects=False)
    set_cookie_header = response.headers.get("set-cookie", "")

    if not set_cookie_header and ep.method == "POST":
        test_data = map_auth_payload(ep.params, "TestPass123!")
        response = await client.request('POST', ep.url, data=test_data, follow_redirects=False)
        set_cookie_header = response.headers.get("set-cookie", "")

    if not set_cookie_header:
        return None, False

    required_flags = config.get("required_flags", ["httponly", "secure", "samesite"])
    missing_flags = ResponseAnalyzer.analyze_session_flags(set_cookie_header, required_flags)

    if missing_flags:
        finding = Finding(
            title="Weak Session Cookie Configuration",
            owasp_category="A05:2021 - Security Misconfiguration",
            threat_level="High", cvss_score="7.3",
            affected_path=f"Session Cookie issued via {ep.method} {ep.url}", 
            description=f"Active session state identifiers are deployed without vital defensive parameters: {', '.join(missing_flags)}.",
            business_impact="Missing HttpOnly allows document object model theft via XSS tokens, while Secure omissions expose strings to non-encrypted transfers.",
            recommendations=["Bind HttpOnly, Secure, and SameSite parameters globally to cookie generation calls."],
            references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            proof_of_concept=ProofOfConcept(
                intro_text="The transaction returned cookie declarations completely lacking required isolation attributes.",
                steps_to_reproduce=[f"1. Generate an execution mapping sequence against {ep.url}.", "2. Capture the server response headers."],
                evidence=Evidence(type="http_snippet", request=f"{ep.method} {ep.url} HTTP/1.1", response=f"Set-Cookie: {set_cookie_header}\n\n[!] Deficiencies Discovered: {', '.join(missing_flags)}")
            )
        )
        return finding, True
    return None, True