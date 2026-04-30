/**
 * mockData.js
 * Simulated backend responses for each vulnerability type.
 * Replace simulateScan() with a real fetch() call to your backend API.
 */

export const MOCK_RESPONSES = {
  "Reflected XSS": {
    severity: "High",
    impact:
      "Attacker can execute arbitrary JavaScript in the victim's browser, leading to session hijacking and credential theft.",
    steps: [
      {
        title: "Request Sent",
        desc: "GET /search?q=<script>alert(1)</script> dispatched to target with crafted parameters.",
        icon: "→",
        color: "#22d3ee",
      },
      {
        title: "Payload Injected",
        desc: "Injected <script>alert(document.cookie)</script> into the 'q' parameter via URL encoding bypass.",
        icon: "⚡",
        color: "#a855f7",
      },
      {
        title: "Server Response",
        desc: "Server returned HTTP 200. Raw HTML reflected the payload verbatim without output encoding.",
        icon: "⟵",
        color: "#f59e0b",
      },
      {
        title: "Vulnerability Confirmed",
        desc: "Script tag executed in isolated sandbox. Reflected XSS confirmed — CSP header absent.",
        icon: "✓",
        color: "#10b981",
      },
      {
        title: "Impact: Session Hijack",
        desc: "Full session takeover possible. Attacker can exfiltrate cookies, tokens, and perform actions as victim.",
        icon: "☠",
        color: "#ef4444",
      },
    ],
  },
  "SQL Injection": {
    severity: "Critical",
    impact:
      "Database contents fully accessible. Authentication bypass and data exfiltration confirmed.",
    steps: [
      {
        title: "Request Sent",
        desc: "POST /login with payload ' OR '1'='1 injected into username field.",
        icon: "→",
        color: "#22d3ee",
      },
      {
        title: "Payload Injected",
        desc: "Boolean-based blind SQLi payload: admin'-- bypasses WHERE clause entirely.",
        icon: "⚡",
        color: "#a855f7",
      },
      {
        title: "Server Response",
        desc: "HTTP 302 redirect to /dashboard. Database query returned true for all rows.",
        icon: "⟵",
        color: "#f59e0b",
      },
      {
        title: "Vulnerability Confirmed",
        desc: "Authentication bypassed. UNION SELECT confirmed table enumeration capability.",
        icon: "✓",
        color: "#10b981",
      },
      {
        title: "Impact: Data Breach",
        desc: "Full database read/write access. PII, credentials, and application secrets exposed.",
        icon: "☠",
        color: "#ef4444",
      },
    ],
  },
};

/**
 * Simulates backend scan returning multiple vulnerabilities
 */
export async function simulateScan(url) {
  await new Promise((r) => setTimeout(r, 1200));

  // Always return both for demo (in real app you would detect actual vulns)
  return {
    vulnerabilities: [
      { vuln: "Reflected XSS", data: MOCK_RESPONSES["Reflected XSS"] },
      { vuln: "SQL Injection", data: MOCK_RESPONSES["SQL Injection"] },
    ]
  };
}
