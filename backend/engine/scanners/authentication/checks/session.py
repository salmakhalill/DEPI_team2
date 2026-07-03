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
            affected_path=f"{ep.url}", 
            description=(
                f"The session cookie issued by '{ep.url}' is missing the following security "
                f"attribute(s): {', '.join(missing_flags)}. Without these flags, the browser does "
                f"not apply the protections they are designed to enforce."
            ),
            business_impact=(
                "Without the 'HttpOnly' flag, an attacker who successfully injects a script (via XSS) "
                "can read and steal the session cookie directly through JavaScript. Without the "
                "'Secure' flag, the cookie may be transmitted over unencrypted HTTP connections, "
                "exposing it to network eavesdropping. Either gap can lead to session hijacking and "
                "unauthorized account access on NexusFlow."
            ),
            recommendations=["Bind HttpOnly, Secure, and SameSite parameters globally to cookie generation calls."],
            references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
            proof_of_concept=ProofOfConcept(
                intro_text=f"Captured the Set-Cookie header returned by '{ep.method} {ep.url}' and inspected it for required security attributes.",
                steps_to_reproduce=[
                    f"1. Send a {ep.method} request to '{ep.url}'.",
                    "2. Inspect the 'Set-Cookie' header in the response.",
                    f"3. Confirm the following attribute(s) are absent: {', '.join(missing_flags)}."
                ],
                evidence=Evidence(type="http_snippet", request=f"{ep.method} {ep.url} HTTP/1.1", response=f"Set-Cookie: {set_cookie_header}\n\n[!] Deficiencies Discovered: {', '.join(missing_flags)}")
            )
        )
        return finding, True
    return None, True