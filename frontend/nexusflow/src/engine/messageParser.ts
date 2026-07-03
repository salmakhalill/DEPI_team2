/**
 * Message Parser Engine
 * WebSocket messages → Structured Events → State
 */
import type { ScanPhase, EventType, ActivityEvent, Finding, Endpoint } from '../types/scan';
import { classifySeverity } from '../types/scan';

let _eventId    = 0;
let _findingId  = 0;
let _endpointId = 0;

export function resetParser() { _eventId = 0; _findingId = 0; _endpointId = 0; }

// ─── Vuln knowledge base ──────────────────────────────────────────────────────
interface VulnKB { type: string; description: string; remediation: string; }

const VULN_KB: Array<{ pattern: string; kb: VulnKB }> = [

  // ── SQL Injection ───────────────────────────────────────────────────────────
  {
    pattern: 'sql',
    kb: {
      type: 'SQL Injection (SQLi)',
      description: 'User input is passed directly into SQL queries without sanitisation, allowing an attacker to read, modify or delete database content and potentially execute OS-level commands.',
      remediation: 'Use parameterised queries and prepared statements. Never concatenate user input into SQL strings. Apply least-privilege database accounts and WAF rules.',
    },
  },

  // ── XSS variants — specific first ──────────────────────────────────────────
  {
    pattern: 'reflected xss',
    kb: {
      type: 'Reflected XSS',
      description: 'User-supplied input is immediately reflected in the HTTP response without sanitisation. An attacker can craft a malicious URL that executes JavaScript in the victim\'s browser, enabling session hijacking and credential theft.',
      remediation: 'HTML-encode all reflected output. Implement a strict Content-Security-Policy. Validate and reject unexpected input server-side.',
    },
  },
  {
    pattern: 'stored xss',
    kb: {
      type: 'Stored XSS',
      description: 'Malicious scripts are permanently stored on the server and executed in every visitor\'s browser. This is more dangerous than Reflected XSS as no user interaction beyond visiting the page is required.',
      remediation: 'Sanitise all stored user content before rendering. Use context-aware output encoding. Apply a strict Content-Security-Policy that blocks inline scripts.',
    },
  },
  {
    pattern: 'dom xss',
    kb: {
      type: 'DOM-Based XSS',
      description: 'JavaScript in the page writes attacker-controlled data to the DOM without sanitisation, executing malicious code entirely client-side without the payload reaching the server.',
      remediation: 'Avoid using dangerous sinks (innerHTML, document.write, eval). Use textContent instead. Sanitise client-side input with a trusted library such as DOMPurify.',
    },
  },
  {
    pattern: 'xss',
    kb: {
      type: 'Cross-Site Scripting (XSS)',
      description: 'Unsanitised input is executed as JavaScript in the victim\'s browser, enabling session hijacking, credential theft, and phishing attacks.',
      remediation: 'HTML-encode all output. Implement a strict Content-Security-Policy. Use modern frameworks that auto-escape output by default.',
    },
  },

  // ── Authentication ──────────────────────────────────────────────────────────
  {
    pattern: 'authentication weakness',
    kb: {
      type: 'Authentication Weaknesses',
      description: 'The application\'s authentication mechanism has weaknesses that could allow attackers to bypass login, brute-force credentials, or hijack sessions without valid credentials.',
      remediation: 'Enforce MFA. Implement account lockout after failed attempts. Use secure, randomly generated session tokens. Rotate tokens after login.',
    },
  },
  {
    pattern: 'missing rate limiting',
    kb: {
      type: 'Missing Rate Limiting',
      description: 'The application does not limit the number of requests a user can make, enabling brute-force attacks on login forms, password reset endpoints, and APIs.',
      remediation: 'Implement rate limiting on all sensitive endpoints. Use CAPTCHA after repeated failures. Return 429 Too Many Requests and apply exponential back-off.',
    },
  },
  {
    pattern: 'weak password policy',
    kb: {
      type: 'Weak Password Policy',
      description: 'The application accepts weak or commonly used passwords, making accounts vulnerable to brute-force and credential-stuffing attacks.',
      remediation: 'Enforce a minimum password length of 12 characters. Require mixed character types. Check passwords against known breach lists (HIBP API). Encourage the use of password managers.',
    },
  },
  {
    pattern: 'weak session cookie',
    kb: {
      type: 'Weak Session Cookie Configuration',
      description: 'Session cookies are missing security flags (HttpOnly, Secure, SameSite), making them vulnerable to theft via XSS, interception over HTTP, or CSRF attacks.',
      remediation: 'Set HttpOnly to prevent JavaScript access. Set Secure to enforce HTTPS-only transmission. Set SameSite=Strict or Lax to prevent CSRF. Use a short expiry and rotate the token after login.',
    },
  },

  // ── File-related ────────────────────────────────────────────────────────────
  {
    pattern: 'local file inclusion',
    kb: {
      type: 'Local File Inclusion (LFI)',
      description: 'The application includes files from the local filesystem based on user-controlled input, allowing an attacker to read sensitive files such as /etc/passwd, private keys, or application source code.',
      remediation: 'Never use user input to construct file paths. Use an allowlist of permitted file names. Disable PHP\'s allow_url_include. Run the application with minimal filesystem permissions.',
    },
  },
  {
    pattern: 'lfi',
    kb: {
      type: 'Local File Inclusion (LFI)',
      description: 'The application includes files from the local filesystem based on user-controlled input, allowing an attacker to read sensitive files such as /etc/passwd, private keys, or application source code.',
      remediation: 'Never use user input to construct file paths. Use an allowlist of permitted file names. Disable PHP\'s allow_url_include. Run the application with minimal filesystem permissions.',
    },
  },
  {
    pattern: 'path traversal',
    kb: {
      type: 'Path Traversal',
      description: 'User-supplied input containing "../" sequences is used to access files outside the intended directory, potentially exposing configuration files, credentials, or OS files.',
      remediation: 'Canonicalise and validate all file paths server-side. Reject paths containing "../". Use chroot jails or containerisation to limit filesystem access.',
    },
  },
  {
    pattern: 'file upload',
    kb: {
      type: 'File Upload Vulnerability',
      description: 'The application allows uploading of dangerous file types (e.g. PHP, JSP, executable) without sufficient validation, enabling an attacker to upload and execute server-side code for full system compromise.',
      remediation: 'Validate file type by magic bytes, not extension. Allowlist safe MIME types. Rename uploaded files. Store uploads outside the web root. Scan files with antivirus before serving.',
    },
  },
  {
    pattern: 'sensitive file disclosure',
    kb: {
      type: 'Sensitive File Disclosure',
      description: 'The application exposes sensitive files (e.g. .env, config files, backups, source code) to unauthenticated users, leaking credentials, API keys, and internal application logic.',
      remediation: 'Remove all sensitive files from the web root. Configure the server to deny access to backup and configuration extensions. Audit publicly accessible directories regularly.',
    },
  },

  // ── Other ───────────────────────────────────────────────────────────────────
  {
    pattern: 'rce',
    kb: {
      type: 'Remote Code Execution',
      description: 'An attacker can run arbitrary system commands on the server, leading to full host compromise, data exfiltration, and lateral movement within the network.',
      remediation: 'Never pass user input to shell commands. Use allowlists for any dynamic execution. Keep all dependencies patched. Run the application as a low-privilege user.',
    },
  },
  {
    pattern: 'ssrf',
    kb: {
      type: 'Server-Side Request Forgery',
      description: 'The server can be induced to make HTTP requests to arbitrary internal or external targets, bypassing firewall rules and potentially accessing cloud metadata endpoints.',
      remediation: 'Validate and allowlist target URLs strictly. Block requests to internal IP ranges (169.254.x.x, 10.x.x.x, 172.16.x.x, 192.168.x.x). Disable unneeded URL schemes.',
    },
  },
  {
    pattern: 'csrf',
    kb: {
      type: 'Cross-Site Request Forgery',
      description: 'An attacker tricks authenticated users into performing unintended state-changing actions by embedding malicious requests in pages the victim visits.',
      remediation: 'Use synchronised CSRF tokens on all state-changing requests. Set SameSite=Strict on session cookies. Verify the Origin and Referer headers server-side.',
    },
  },
  {
    pattern: 'information disclosure',
    kb: {
      type: 'Sensitive File Disclosure',
      description: 'The application leaks sensitive information such as internal paths, software versions, credentials, or debug data that can aid further attacks.',
      remediation: 'Disable debug mode and verbose error messages in production. Strip internal information from HTTP headers and responses. Review all API responses for unnecessary data exposure.',
    },
  },
];

function extractVulnNameFromMessage(msg: string): string {
  // Pattern 1 — "[!] <VulnName> Confirmed! ..."
  // e.g. "[!] SQL Injection Confirmed!" → "SQL Injection"
  //      "[!] Broken Authentication Confirmed!" → "Broken Authentication"
  const confirmedMatch = msg.match(/\[!\]\s+(.+?)\s+(?:Confirmed|Found|Detected|Discovered|Vulnerable|Identified)/i);
  if (confirmedMatch) return confirmedMatch[1].trim();

  // Pattern 2 — "[VULN] <VulnName> | ..."
  // e.g. "[VULN] Open Redirect | Target: ..."
  const vulnTagMatch = msg.match(/\[VULN\]\s+(.+?)\s*[|:]/i);
  if (vulnTagMatch) return vulnTagMatch[1].trim();

  // Pattern 3 — "[ScannerName] <VulnName> Confirmed ..."
  // e.g. "[XSS Scanner] Reflected XSS Confirmed"
  const scannerMatch = msg.match(/\[[^\]]+Scanner\]\s+(.+?)\s+(?:Confirmed|Found|Detected)/i);
  if (scannerMatch) return scannerMatch[1].trim();

  // Pattern 4 — keyword map (longer/more specific phrases first)
  const keywordMap: Record<string, string> = {
    // SQL
    'sql injection':                    'SQL Injection (SQLi)',
    'sqli':                             'SQL Injection (SQLi)',

    // XSS — specific before generic
    'reflected xss':                    'Reflected XSS',
    'stored xss':                       'Stored XSS',
    'dom xss':                          'DOM-Based XSS',
    'dom-based xss':                    'DOM-Based XSS',
    'cross-site scripting':             'Cross-Site Scripting (XSS)',
    'xss':                              'Cross-Site Scripting (XSS)',

    // Authentication
    'authentication weaknesses':        'Authentication Weaknesses',
    'authentication weakness':          'Authentication Weaknesses',
    'broken authentication':            'Authentication Weaknesses',
    'weak authentication':              'Authentication Weaknesses',
    'authentication bypass':            'Authentication Bypass',
    'auth bypass':                      'Authentication Bypass',
    'missing rate limiting':            'Missing Rate Limiting',
    'rate limiting':                    'Missing Rate Limiting',
    'weak password policy':             'Weak Password Policy',
    'password policy':                  'Weak Password Policy',
    'weak session cookie configuration':'Weak Session Cookie Configuration',
    'weak session cookie':              'Weak Session Cookie Configuration',
    'session cookie':                   'Weak Session Cookie Configuration',

    // File
    'local file inclusion':             'Local File Inclusion (LFI)',
    'lfi':                              'Local File Inclusion (LFI)',
    'remote file inclusion':            'Remote File Inclusion (RFI)',
    'rfi':                              'Remote File Inclusion (RFI)',
    'path traversal':                   'Path Traversal',
    'directory traversal':              'Path Traversal',
    'file upload':                      'File Upload Vulnerability',
    'sensitive file disclosure':        'Sensitive File Disclosure',
    'file disclosure':                  'Sensitive File Disclosure',

    // Other high
    'server-side request forgery':      'Server-Side Request Forgery (SSRF)',
    'ssrf':                             'Server-Side Request Forgery (SSRF)',
    'xml external entity':              'XML External Entity (XXE)',
    'xxe':                              'XML External Entity (XXE)',
    'open redirect':                    'Open Redirect',
    'remote code execution':            'Remote Code Execution (RCE)',
    'rce':                              'Remote Code Execution (RCE)',
    'command injection':                'Command Injection',
    'insecure direct object reference': 'Insecure Direct Object Reference (IDOR)',
    'idor':                             'Insecure Direct Object Reference (IDOR)',
    'broken access control':            'Broken Access Control',
    'privilege escalation':             'Privilege Escalation',
    'security misconfiguration':        'Security Misconfiguration',

    // Medium
    'cross-site request forgery':       'Cross-Site Request Forgery (CSRF)',
    'csrf':                             'Cross-Site Request Forgery (CSRF)',
    'clickjacking':                     'Clickjacking',
    'cors misconfiguration':            'CORS Misconfiguration',
    'insecure deserialization':         'Insecure Deserialization',

    // Low
    'information disclosure':           'Information Disclosure',
    'information leakage':              'Information Disclosure',
    'version disclosure':               'Version Disclosure',
  };
  const lower = msg.toLowerCase();
  for (const [keyword, label] of Object.entries(keywordMap)) {
    if (lower.includes(keyword)) return label;
  }

  // Pattern 5 — last resort: grab text between [!] or [VULN] and the first |
  const anyTagMatch = msg.match(/\[(?:!|VULN|FINDING)\]\s+(.+?)(?:\s*\||$)/i);
  if (anyTagMatch) return anyTagMatch[1].trim();

  return 'Security Vulnerability';
}

function lookupVuln(msg: string): VulnKB {
  const lower = msg.toLowerCase();

  // Try KB first (has rich description + remediation)
  for (const { pattern, kb } of VULN_KB) {
    if (lower.includes(pattern)) return kb;
  }

  // KB miss — extract the name from the message itself
  const extractedName = extractVulnNameFromMessage(msg);
  return {
    type: extractedName,
    description: `A ${extractedName} vulnerability was identified. This security weakness may allow an attacker to compromise the confidentiality, integrity, or availability of the application.`,
    remediation: `Review the affected parameter and apply strict input validation, output encoding, and the principle of least privilege. Consult OWASP guidelines for ${extractedName} remediation.`,
  };
}

// ─── Phase rules ──────────────────────────────────────────────────────────────
const PHASE_RULES: Array<{ phase: ScanPhase; patterns: string[] }> = [
  { phase: 2, patterns: ['[spider]', 'crawling:', 'spider]', 'dispatch', 'asynchronous spider', 'structural authentication'] },
  { phase: 3, patterns: ['attack surface', 'endpoints discovered', 'unique endpoints', 'phase 2', 'vulnerability assessment', 'concurrent scans', 'extractor'] },
  { phase: 4, patterns: ['[sqli scanner]', '[xss', '[scanner]', 'assessing attack surface', 'scanner]', 'scanner module', 'registered scanner'] },
  { phase: 5, patterns: ['injection confirmed', 'xss confirmed', 'vulnerability confirmed', '[vuln]', 'confirmed!', 'identified'] },
  { phase: 6, patterns: ['phase 3', 'dynamic payload', 'payload generation', 'aggregating', 'scan engine operations completed', 'report payload is ready'] },
  { phase: 7, patterns: ['generating', 'reporter]', 'compiling report', 'ready for compilation', 'phase 3: aggregating'] },
  { phase: 8, patterns: ['completed successfully', '[done]', 'scan completed', 'completed!'] },
];

export function detectPhase(msg: string): ScanPhase | null {
  const lower = msg.toLowerCase();
  for (const { phase, patterns } of PHASE_RULES) {
    if (patterns.some(p => lower.includes(p))) return phase;
  }
  return null;
}

// ─── Progress % per phase ─────────────────────────────────────────────────────
export function phaseToProgress(phase: ScanPhase): number {
  const map: Record<ScanPhase, number> = { 1:5, 2:18, 3:35, 4:55, 5:72, 6:85, 7:94, 8:100 };
  return map[phase] ?? 0;
}

// ─── Event parser ─────────────────────────────────────────────────────────────
interface ParsedEvent { type: EventType; title: string; detail: string; }

export function parseEvent(msg: string, phase: ScanPhase): ParsedEvent {
  const lower = msg.toLowerCase();

  if (lower.includes('confirmed') || lower.includes('[vuln]') || lower.includes('[!]') && (lower.includes('sql') || lower.includes('xss') || lower.includes('rce'))) {
    const kb     = lookupVuln(msg);
    const target = msg.match(/Target:\s*(https?:\/\/[^\s|]+)/i)?.[1] || '';
    const param  = msg.match(/Param[:\s]+['"]?([^'"|,\n]+)['"]?/i)?.[1]?.trim() || '';
    const path   = target.replace(/https?:\/\/[^/]+/, '') || target;
    return { type: 'finding', title: `${kb.type} Detected`, detail: [path && `Endpoint: ${path}`, param && `Param: ${param}`].filter(Boolean).join(' · ') };
  }
  if (lower.includes('[spider]') || lower.includes('crawling:')) {
    const url  = msg.match(/https?:\/\/[^\s]+/)?.[0] || '';
    const path = url.replace(/https?:\/\/[^/]+/, '') || url || msg.replace(/^\[Spider\]\s*/i, '');
    return { type: 'spider', title: 'Endpoint Discovered', detail: path.slice(0, 65) };
  }
  if (lower.includes('attack surface') || lower.includes('endpoints discovered')) {
    const n = msg.match(/(\d+)\s+(?:unique\s+)?endpoints?/i)?.[1] || '?';
    return { type: 'surface', title: 'Attack Surface Mapped', detail: `${n} endpoints in scope` };
  }
  if (lower.includes('scanner') || lower.includes('assessing')) {
    const n = msg.match(/(\d+)\s+target/i)?.[1] || '';
    return { type: 'scanner', title: 'Scanner Executing', detail: n ? `Probing ${n} targets concurrently` : msg.replace(/^\[.*?\]\s*/, '').slice(0, 70) };
  }
  if (lower.includes('generat') || lower.includes('aggregat') || lower.includes('reporter')) {
    return { type: 'reporter', title: 'Report Generation', detail: msg.replace(/^\[.*?\]\s*/, '').slice(0, 80) };
  }
  if (lower.includes('completed') || lower.includes('[done]')) {
    return { type: 'done', title: 'Scan Complete', detail: 'All phases finished — PDF report ready' };
  }
  if (lower.includes('[error]')) {
    return { type: 'error', title: 'Error Encountered', detail: msg.replace(/^\[.*?\]\s*/, '').slice(0, 80) };
  }
  if (lower.includes('phase')) {
    return { type: 'info', title: 'Phase Transition', detail: msg.replace(/^\[.*?\]\s*/, '').slice(0, 80) };
  }
  return { type: 'info', title: 'System Event', detail: msg.replace(/^\[.*?\]\s*/, '').slice(0, 80) };
}

export function buildActivity(msg: string, phase: ScanPhase): ActivityEvent {
  return { id: ++_eventId, raw: msg, timestamp: new Date(), phase, ...parseEvent(msg, phase) };
}

export function buildFinding(msg: string): Finding | null {
  const lower = msg.toLowerCase();
  const isVuln =
    lower.includes('confirmed') ||
    lower.includes('[vuln]') ||
    (lower.includes('[!]') && (lower.includes('sql') || lower.includes('xss') || lower.includes('rce') || lower.includes('injection')));
  if (!isVuln) return null;

  const kb       = lookupVuln(msg);
  const severity = classifySeverity(msg);
  const endpointRaw = msg.match(/Target:\s*(https?:\/\/[^\s|]+)/i)?.[1]?.trim() || '';
  const param       = msg.match(/Param[:\s]+['"]?([^'"|,\n]+)['"]?/i)?.[1]?.trim() || 'unknown';
  const path        = endpointRaw.replace(/https?:\/\/[^/]+/, '') || endpointRaw || '/unknown';

  return { id: ++_findingId, raw: msg, type: kb.type, severity, endpoint: path, param, status: 'confirmed', timestamp: new Date(), description: kb.description, remediation: kb.remediation, evidence: msg };
}

export function buildEndpoint(msg: string): Endpoint | null {
  if (!msg.toLowerCase().includes('[spider]')) return null;
  const urlMatch = msg.match(/https?:\/\/[^\s]+/);
  if (!urlMatch) return null;
  const url  = urlMatch[0];
  const path = url.replace(/https?:\/\/[^/]+/, '') || '/';
  return { id: ++_endpointId, url, path, method: 'GET', paramCount: 0, scanned: false, vulnerable: false, discoveredAt: new Date() };
}
