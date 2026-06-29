import re
import html
from urllib.parse import parse_qs
from typing import List, Optional, Tuple
from engine.core.base_scanner import BaseScanner
from engine.models.endpoint import Endpoint
from engine.models.finding import Finding, ProofOfConcept, Evidence
from engine.payloads.payload_manager import PayloadManager


def _detect_context(html_source: str, value: str) -> str:
    escaped = re.escape(value)
    if re.search(r"<script[^>]*>.*?" + escaped + r".*?</script>", html_source, re.IGNORECASE | re.DOTALL):
        return "js"
    if re.search(r'[\w-]+\s*=\s*["\'][^"\']*' + escaped + r'[^"\']*["\']', html_source, re.IGNORECASE):
        return "attr"
    return "html"


def _is_raw_reflection(response_text: str, payload: str) -> bool:
    return payload in response_text and html.escape(payload) not in response_text


def _extract_snippet(response_text: str, payload: str, window: int = 120) -> str:
    idx = response_text.find(payload)
    if idx == -1:
        return ""
    start = max(0, idx - window // 2)
    end   = min(len(response_text), idx + len(payload) + window // 2)
    return "..." + response_text[start:end] + "..."


def _score_confidence(context: str, waf_bypass: bool) -> Tuple[str, str]:
    if context == "js":
        return "Critical", "9.3"
    if context == "attr":
        return "High", "8.5"
    if waf_bypass:
        return "Medium", "5.5"
    return "High", "7.2"


class XSSScanner(BaseScanner):
    """
    Multi-vector XSS Scanner.

    Detection layers:
    1. Reflected XSS — GET params, context-aware payloads + WAF bypasses
    2. Stored XSS    — POST forms, verified on the parent view page
    """

    def run_scan(self, endpoints: List[Endpoint]) -> List[Finding]:
        findings = []
        xss_data = PayloadManager.get_payloads("xss")

        reflected_cases  = xss_data.get("reflected_cases", [])
        stored_cases     = xss_data.get("stored_cases", [])
        context_payloads = xss_data.get("context_payloads", {})
        waf_cases        = xss_data.get("waf_bypass_cases", [])

        print(f"[XSS] Starting scan on {len(endpoints)} endpoints...")

        findings += self._scan_reflected(endpoints, reflected_cases, context_payloads, waf_cases)
        findings += self._scan_stored(endpoints, stored_cases)

        print(f"[XSS] Done — {len(findings)} finding(s) confirmed.")
        return findings

    # ── Layer 1: Reflected XSS ──────────────────────────────────────────
    def _scan_reflected(self, endpoints, reflected_cases, context_payloads, waf_cases) -> List[Finding]:
        findings = []

        for ep in endpoints:
            if ep.method != "GET" or not ep.params:
                continue

            parsed_defaults = parse_qs(ep.original_query)
            base_params = {
                p: (parsed_defaults[p][0] if p in parsed_defaults and parsed_defaults[p] else "test")
                for p in ep.params
            }

            baseline_resp = self.client.request("GET", ep.url, params=base_params)
            baseline_text = baseline_resp.text if baseline_resp.success else ""

            for param in ep.params:
                vuln_found = False

                # Step A: Standard payloads from JSON
                for case in reflected_cases:
                    if vuln_found:
                        break
                    result = self._try_reflected(ep, param, case["payload"], base_params, baseline_text)
                    if result:
                        findings.append(result)
                        vuln_found = True

                # Step B: WAF bypass variants
                if not vuln_found:
                    for case in waf_cases:
                        result = self._try_reflected(ep, param, case["payload"], base_params, baseline_text, waf_bypass=True)
                        if result:
                            findings.append(result)
                            vuln_found = True
                            break

                # Step C: Context-aware payloads (canary probe first)
                if not vuln_found:
                    canary = "xsscanary123"
                    canary_params = base_params.copy()
                    canary_params[param] = canary
                    canary_resp = self.client.request("GET", ep.url, params=canary_params)

                    if canary_resp.success and canary in canary_resp.text:
                        ctx = _detect_context(canary_resp.text, canary)
                        print(f"[XSS] Context for '{param}' @ {ep.url}: [{ctx}]")

                        for payload in context_payloads.get(ctx, context_payloads.get("html", [])):
                            result = self._try_reflected(ep, param, payload, base_params, baseline_text, ctx_override=ctx)
                            if result:
                                findings.append(result)
                                break

        return findings

    def _try_reflected(self, ep, param, payload, base_params, baseline_text,
                       waf_bypass=False, ctx_override=None) -> Optional[Finding]:
        test_params = base_params.copy()
        test_params[param] = payload

        resp = self.client.request("GET", ep.url, params=test_params)
        if not resp.success:
            return None

        if payload in baseline_text:
            return None

        if not _is_raw_reflection(resp.text, payload):
            return None

        ctx = ctx_override or _detect_context(resp.text, payload)
        threat, cvss = _score_confidence(ctx, waf_bypass)
        snippet = _extract_snippet(resp.text, payload)

        print(f"[VULN] Reflected XSS | {ep.url} | param='{param}' | context={ctx} | {threat}"
              + (" [WAF-bypass]" if waf_bypass else ""))

        return self._build_finding(
            xss_type="Reflected",
            param=param,
            payload=payload,
            ep_url=ep.url,
            threat=threat,
            cvss=cvss,
            context=ctx,
            snippet=snippet,
            request_line=f"GET {ep.url}?{param}={payload}",
            waf_bypass=waf_bypass,
        )

    # ── Layer 2: Stored XSS ─────────────────────────────────────────────
    def _scan_stored(self, endpoints, stored_cases) -> List[Finding]:
        findings = []

        for ep in endpoints:
            if ep.method != "POST" or "comment" not in ep.url.lower() or not ep.params:
                continue

            verify_url = re.sub(r"/comment.*$", "", ep.url, flags=re.IGNORECASE)

            baseline_resp = self.client.request("GET", verify_url)
            baseline_text = baseline_resp.text if baseline_resp.success else ""

            for case in stored_cases:
                payload   = case["payload"]
                test_data = {p: payload for p in ep.params}

                post_resp = self.client.request("POST", ep.url, data=test_data)
                if not post_resp.success:
                    continue

                verify_resp = self.client.request("GET", verify_url)
                if not verify_resp.success:
                    continue

                if payload in baseline_text:
                    continue

                if not _is_raw_reflection(verify_resp.text, payload):
                    continue

                snippet    = _extract_snippet(verify_resp.text, payload)
                param_name = ep.params[0] if ep.params else "comment_body"

                print(f"[VULN] Stored XSS | POST {ep.url} → verified on {verify_url} | param='{param_name}'")

                findings.append(self._build_finding(
                    xss_type="Stored",
                    param=param_name,
                    payload=payload,
                    ep_url=verify_url,
                    threat="High",
                    cvss="8.1",
                    context="html",
                    snippet=snippet,
                    request_line=f"POST {ep.url} (data={test_data})",
                ))
                break

        return findings

    # ── Shared finding builder ───────────────────────────────────────────
    def _build_finding(self, xss_type, param, payload, ep_url,
                       threat, cvss, context, snippet, request_line,
                       waf_bypass=False) -> Finding:

        safe_payload = html.escape(payload)
        safe_snippet = html.escape(snippet) if snippet else "N/A"
        ctx_label    = {"html": "HTML text node", "attr": "HTML attribute", "js": "JavaScript string"}.get(context, context)
        bypass_note  = " A WAF-bypass variant was required to confirm this." if waf_bypass else ""

        if xss_type == "Stored":
            description = (
                f"The endpoint stores unsanitized input from '{param}' in the database. "
                f"The payload renders in raw form on every subsequent page load, "
                f"affecting all visitors automatically.{bypass_note}"
            )
            impact = (
                "Stored XSS enables mass session hijacking and credential theft. "
                "Every user loading the page becomes a victim with no social engineering needed."
            )
            steps = [
                f"1. Submit payload '{safe_payload}' via '{param}' field at {ep_url} (POST).",
                "2. Navigate to the view page (GET) to confirm the payload renders unencoded.",
                "3. Verify execution in a browser — script triggers automatically on page load.",
            ]
        else:
            description = (
                f"The '{param}' parameter reflects input without encoding inside a "
                f"[{ctx_label}] context. The payload returned raw and unencoded "
                f"in the server response.{bypass_note}"
            )
            impact = (
                "An attacker crafts a malicious URL and tricks a victim into visiting it. "
                "The injected script runs in the victim's browser enabling cookie theft and session hijacking."
            )
            steps = [
                f"1. Navigate to: {ep_url}?{param}={safe_payload}",
                f"2. Observe payload renders unescaped inside [{ctx_label}] context.",
                "3. Verify JavaScript execution in a browser.",
            ]

        return Finding(
            title=f"{xss_type} Cross-Site Scripting (XSS)",
            owasp_category="A03:2021 - Injection",
            threat_level=threat,
            cvss_score=cvss,
            affected_path=f"{ep_url} [parameter={param}]",
            description=description,
            business_impact=impact,
            recommendations=[
                "Apply context-aware output encoding before rendering user input.",
                "Implement a strict Content-Security-Policy (CSP) header.",
                "Use your framework's built-in auto-escaping (e.g., Jinja2, Django templates).",
                "For stored input, sanitize with an allow-list library (e.g., DOMPurify) on output.",
            ],
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
            proof_of_concept=ProofOfConcept(
                intro_text=(
                    f"Injected '{safe_payload}' into '{param}'. "
                    f"Server returned payload raw inside [{ctx_label}] context without entity encoding."
                ),
                steps_to_reproduce=steps,
                evidence=Evidence(
                    type="http_snippet",
                    request=html.escape(request_line),
                    response=f"Payload reflected (raw):\n{safe_payload}\n\nHTML Snippet:\n{safe_snippet}",
                ),
            ),
        )