import re
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from .param_mapper import map_auth_payload

async def check_rate_limit(client, ep: Endpoint, config: dict, log_callback) -> Finding:
    attempt_count = config.get("attempt_count", 15)
    block_keywords = config.get("block_keywords", [])
    failure_keywords = config.get("failure_keywords", [])
    
    pre_flight = await client.request('GET', ep.url, follow_redirects=True)
    hidden_fields = {}
    if pre_flight.success:
        inputs = re.findall(r'<input[^>]+type=[\'"]hidden[\'"][^>]*>', pre_flight.text, re.IGNORECASE)
        for inp in inputs:
            name_m = re.search(r'name=[\'"]([^\'"]+)[\'"]', inp, re.IGNORECASE)
            val_m = re.search(r'value=[\'"]([^\'"]+)[\'"]', inp, re.IGNORECASE)
            if name_m and val_m:
                hidden_fields[name_m.group(1)] = val_m.group(1)

    test_data = map_auth_payload(ep.params, "InvalidBruteForcePass123!")
    test_data.update(hidden_fields)

    baseline_status = None
    rate_limit_triggered = False
    unthrottled_failures = 0

    if log_callback:
        log_callback(f"[*] Executing rate-limit burst attack ({attempt_count} requests) on {ep.url}")

    for i in range(attempt_count):
        response = await client.request('POST', ep.url, data=test_data, follow_redirects=True)
        
        if not response.success: 
            continue
            
        if i == 0: 
            baseline_status = response.status_code

        if response.status_code == 429 or any(kw in response.text.lower() for kw in block_keywords):
            rate_limit_triggered = True
            break

        if any(kw in response.text.lower() for kw in failure_keywords):
            unthrottled_failures += 1

    is_vulnerable = not rate_limit_triggered and (unthrottled_failures >= (attempt_count - 5) or baseline_status in [200, 401, 403])

    if is_vulnerable:
        return Finding(
            title="Missing Rate Limiting (Brute-Force)",
            owasp_category="A07:2021 - Identification and Authentication Failures",
            threat_level="High", cvss_score="7.5",
            affected_path=f"{ep.url}",
            description=(
                f"The authentication endpoint '{ep.url}' accepted {attempt_count} consecutive "
                f"invalid login attempts without triggering any throttling, CAPTCHA challenge, "
                f"or temporary account lockout. The server returned a consistent HTTP {baseline_status} "
                f"response across all attempts with no observable slowdown or blocking mechanism."
            ),
            business_impact=(
                "Attackers can run automated brute-force or credential-stuffing tools against "
                "NexusFlow user accounts at unlimited speed. Combined with weak or reused passwords, "
                "this significantly raises the likelihood of unauthorized account access, "
                "potentially exposing sensitive user data or enabling further attacks from "
                "compromised accounts."
            ),
            recommendations=["Implement server-side rate limiting constraints.", "Enforce progressive delays or CAPTCHA layers upon consecutive authentication failures."],
            references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
            proof_of_concept=ProofOfConcept(
                intro_text=f"Sent {attempt_count} consecutive invalid login requests to '{ep.url}' and monitored for throttling behavior.",
                steps_to_reproduce=[
                    f"1. Send a POST request with invalid credentials to '{ep.url}'.",
                    f"2. Repeat the request {attempt_count} times in immediate succession.",
                    "3. Confirm that no HTTP 429, CAPTCHA prompt, or account lockout is triggered at any point."
                ],
                evidence=Evidence(type="http_snippet", request=f"POST {ep.url} HTTP/1.1\n[Burst Sequence Payload x{attempt_count}]", response=f"Final Status Code: HTTP {baseline_status}\n(Uniform application authentication failure state maintained)")
            )
        )
    return None