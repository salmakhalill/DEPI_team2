// ─── Core enums & scalars ────────────────────────────────────────────────────
export type ScanPhase  = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;
export type ScanStatus = 'connecting' | 'running' | 'completed' | 'failed';
export type Severity   = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ─── Centralised severity rules ───────────────────────────────────────────────
export const SEVERITY_RULES: Record<string, Severity> = {

  // ── Critical ───────────────────────────────────────────────────────────────
  'sql injection':                        'critical',
  'sqli':                                 'critical',
  'file upload':                          'critical',
  'remote code execution':                'critical',
  'rce':                                  'critical',
  'authentication bypass':                'critical',
  'auth bypass':                          'critical',
  'command injection':                    'critical',
  'insecure deserialization':             'critical',
  'sfd':                                  'critical',
  'sensitive file disclosure':            'critical',
  // ── High ───────────────────────────────────────────────────────────────────
  'cross-site scripting':                 'high',
  'reflected xss':                        'high',
  'stored xss':                           'high',
  'dom xss':                              'high',
  'xss':                                  'high',
  'authentication weakness':              'high',
  'authentication weaknesses':            'high',
  'weak authentication':                  'high',
  'broken authentication':                'high',
  'missing rate limiting':                'high',
  'rate limiting':                        'high',
  'weak session cookie':                  'high',
  'session cookie':                       'high',
  'local file inclusion':                 'high',
  'lfi':                                  'high',
  'path traversal':                       'high',
  'directory traversal':                  'high',
  'file disclosure':                      'high',
  'ssrf':                                 'high',
  'server-side request forgery':          'high',
  'xxe':                                  'high',
  'xml external entity':                  'high',
  'open redirect':                        'high',
  'remote file inclusion':                'high',
  'rfi':                                  'high',
  'idor':                                 'high',
  'insecure direct object reference':     'high',
  'broken access control':                'high',
  'privilege escalation':                 'high',
  'security misconfiguration':            'high',

  // ── Medium ─────────────────────────────────────────────────────────────────
  'weak password policy':                 'medium',
  'password policy':                      'medium',
  'csrf':                                 'medium',
  'cross-site request forgery':           'medium',
  'clickjacking':                         'medium',
  'missing header':                       'medium',
  'security header':                      'medium',
  'cors misconfiguration':                'medium',
  'cors':                                 'medium',
  'verbose error':                        'medium',
  'error message':                        'medium',

  // ── Low ────────────────────────────────────────────────────────────────────
  'information disclosure':               'low',
  'information leakage':                  'low',
  'version disclosure':                   'low',
  'banner grabbing':                      'low',
};

export function classifySeverity(msg: string): Severity {
  const lower = msg.toLowerCase();
  for (const [pattern, sev] of Object.entries(SEVERITY_RULES)) {
    if (lower.includes(pattern)) return sev;
  }
  return 'medium';
}

// ─── Phase definitions (timeline nodes) ─────────────────────────────────────
export interface PhaseInfo {
  id: ScanPhase;
  label: string;
  shortLabel: string;
  description: string;
  color: string;
  icon: string;
}

export const PHASES: PhaseInfo[] = [
  { id: 1, label: 'Target Submitted',       shortLabel: 'Target',      description: 'Scan target accepted',                   color: '#22d3ee', icon: '⬡' },
  { id: 2, label: 'Spider Crawling',        shortLabel: 'Crawling',    description: 'Discovering pages & routes',              color: '#06b6d4', icon: '⟡' },
  { id: 3, label: 'Attack Surface',         shortLabel: 'Surface',     description: 'Mapping endpoints & parameters',          color: '#a855f7', icon: '◈' },
  { id: 4, label: 'Vulnerability Scan',     shortLabel: 'Scanning',    description: 'Injecting payloads & testing',            color: '#f59e0b', icon: '⚡' },
  { id: 5, label: 'Exploitation Analysis',  shortLabel: 'Exploiting',  description: 'Confirming & ranking findings',           color: '#f97316', icon: '☠' },
  { id: 6, label: 'Payload Generation',     shortLabel: 'Payloads',    description: 'Building dynamic attack payload',         color: '#ef4444', icon: '⊛' },
  { id: 7, label: 'Report Generation',      shortLabel: 'Report',      description: 'Compiling professional PDF report',       color: '#10b981', icon: '◇' },
  { id: 8, label: 'Completed',              shortLabel: 'Done',        description: 'Scan finished — report ready',            color: '#10b981', icon: '✓' },
];

// ─── Event / activity feed ───────────────────────────────────────────────────
export type EventType =
  | 'target'   | 'spider'    | 'surface'  | 'scanner'
  | 'finding'  | 'exploit'   | 'payload'  | 'reporter'
  | 'done'     | 'error'     | 'info';

export interface ActivityEvent {
  id: number;
  raw: string;
  type: EventType;
  title: string;
  detail: string;
  timestamp: Date;
  phase: ScanPhase;
}

// ─── Finding (vulnerability) ─────────────────────────────────────────────────
export interface Finding {
  id: number;
  raw: string;
  type: string;           // e.g. "SQL Injection"
  severity: Severity;
  endpoint: string;
  param: string;
  status: 'confirmed' | 'potential' | 'false-positive';
  timestamp: Date;
  // Enriched fields for detail drawer
  description?: string;
  remediation?: string;
  evidence?: string;
}

// ─── Endpoint (attack surface) ───────────────────────────────────────────────
export interface Endpoint {
  id: number;
  url: string;
  path: string;
  method: string;
  paramCount: number;
  scanned: boolean;
  vulnerable: boolean;
  discoveredAt: Date;
}

// ─── Top-level scan state ─────────────────────────────────────────────────────
export interface ScanState {
  scanId: string;
  status: ScanStatus;
  currentPhase: ScanPhase;
  completedPhases: Set<ScanPhase>;
  connected: boolean;
  elapsedSec: number;
  scanProgress: number;           // 0-100
  endpoints: Endpoint[];
  findings: Finding[];
  activityFeed: ActivityEvent[];
  reportReady: boolean;
  targetUrl: string;
}

// ─── API types (re-exported for compatibility) ────────────────────────────────
export interface StartScanRequest  { target_url: string; raw_cookie_header: string; }
export interface StartScanResponse { scan_id: string; status: string; target_url: string; }
export interface LogEntry {
  id: number; message: string;
  type: 'spider'|'extractor'|'scanner'|'finding'|'reporter'|'done'|'error'|'info';
  timestamp: Date;
}
