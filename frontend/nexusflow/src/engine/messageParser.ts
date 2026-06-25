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
  { pattern: 'sql',   kb: { type: 'SQL Injection',             description: 'Unsanitised user input is passed directly into SQL queries, allowing an attacker to read, modify or delete database content and potentially execute OS-level commands.', remediation: 'Use parameterised queries / prepared statements. Never concatenate user input into SQL strings. Apply least-privilege DB accounts.' } },
  { pattern: 'xss',  kb: { type: 'Cross-Site Scripting (XSS)', description: 'Unsanitised input is reflected or stored and executed in the victim\'s browser, enabling session hijacking, credential theft, and phishing.', remediation: 'HTML-encode all output. Implement a strict Content-Security-Policy. Use modern frameworks that auto-escape output.' } },
  { pattern: 'rce',  kb: { type: 'Remote Code Execution',      description: 'An attacker can run arbitrary system commands on the server, leading to full host compromise.', remediation: 'Never pass user input to shell commands. Allowlist dynamic execution paths. Patch dependencies aggressively.' } },
  { pattern: 'ssrf', kb: { type: 'Server-Side Request Forgery', description: 'The server is induced to make HTTP requests to arbitrary internal or external targets, bypassing network controls.', remediation: 'Validate and allowlist target URLs. Block internal IP ranges at the network layer. Disable unneeded URL schemes.' } },
  { pattern: 'csrf', kb: { type: 'Cross-Site Request Forgery', description: 'An attacker tricks authenticated users into performing unintended actions.', remediation: 'Use synchronised CSRF tokens. Set SameSite=Strict on session cookies. Verify Origin/Referer headers.' } },
];

function lookupVuln(msg: string): VulnKB {
  const lower = msg.toLowerCase();
  for (const { pattern, kb } of VULN_KB) {
    if (lower.includes(pattern)) return kb;
  }
  return { type: 'Security Vulnerability', description: 'A security weakness was identified that may allow an attacker to compromise the application.', remediation: 'Apply input validation, output encoding, and the principle of least privilege to the affected parameter.' };
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
