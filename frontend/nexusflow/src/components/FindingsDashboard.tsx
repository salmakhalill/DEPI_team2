import { useState } from 'react';
import type { Finding } from '../types/scan';

interface FindingsDashboardProps {
  findings: Finding[];
}

const severityConfig = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.4)', label: 'CRITICAL' },
  high:     { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', label: 'HIGH' },
  medium:   { color: '#a855f7', bg: 'rgba(168,85,247,0.12)', border: 'rgba(168,85,247,0.4)', label: 'MEDIUM' },
  low:      { color: '#22d3ee', bg: 'rgba(34,211,238,0.12)', border: 'rgba(34,211,238,0.4)', label: 'LOW' },
  info:     { color: 'rgba(148,163,184,0.6)', bg: 'rgba(255,255,255,0.04)', border: 'rgba(255,255,255,0.1)', label: 'INFO' },
};

function parseFindings(raw: string) {
  const vuln = raw.includes('SQL') ? 'SQL Injection' : raw.includes('XSS') ? 'XSS' : 'Vulnerability';
  const urlMatch = raw.match(/https?:\/\/[^\s]+/);
  const url = urlMatch ? urlMatch[0].slice(0, 50) : 'Unknown endpoint';
  const paramMatch = raw.match(/param(?:eter)?\s+['":]?\s*(\S+)/i);
  const param = paramMatch ? paramMatch[1] : 'unknown';
  return { vuln, url, param };
}

export default function FindingsDashboard({ findings }: FindingsDashboardProps) {
  const [expanded, setExpanded] = useState<number | null>(null);

  if (findings.length === 0) {
    return (
      <div style={{
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 14,
        padding: '24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        flexDirection: 'column',
        gap: 10,
        minHeight: 120,
      }}>
        <div style={{
          width: 32, height: 32,
          borderRadius: '50%',
          border: '1px solid rgba(34,211,238,0.2)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 14, color: 'rgba(34,211,238,0.4)',
        }}>◈</div>
        <span style={{
          fontSize: 10,
          color: 'rgba(148,163,184,0.35)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
        }}>No findings yet</span>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {findings.map((finding, i) => {
        const sev = severityConfig[finding.severity];
        const parsed = parseFindings(finding.raw);
        const isExpanded = expanded === finding.id;

        return (
          <div
            key={finding.id}
            onClick={() => setExpanded(isExpanded ? null : finding.id)}
            style={{
              background: sev.bg,
              border: `1px solid ${sev.border}`,
              borderLeft: `3px solid ${sev.color}`,
              borderRadius: 10,
              padding: '12px 16px',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              animation: 'findingSlideIn 0.4s ease forwards',
              animationDelay: `${i * 0.05}s`,
              opacity: 0,
              boxShadow: `0 0 20px ${sev.color}11`,
            }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLElement).style.boxShadow = `0 0 20px ${sev.color}33`;
              (e.currentTarget as HTMLElement).style.transform = 'translateX(2px)';
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLElement).style.boxShadow = `0 0 20px ${sev.color}11`;
              (e.currentTarget as HTMLElement).style.transform = 'translateX(0)';
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{
                  padding: '2px 8px',
                  borderRadius: 20,
                  background: sev.bg,
                  border: `1px solid ${sev.color}`,
                  color: sev.color,
                  fontSize: 8,
                  fontWeight: 700,
                  letterSpacing: '0.12em',
                }}>{sev.label}</span>
                <span style={{
                  fontFamily: '"Bebas Neue", sans-serif',
                  fontSize: 15,
                  letterSpacing: '0.06em',
                  color: '#f1f5f9',
                }}>{parsed.vuln}</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  fontSize: 8,
                  color: 'rgba(148,163,184,0.4)',
                  letterSpacing: '0.08em',
                }}>#{String(i + 1).padStart(2, '0')}</span>
                <span style={{ color: 'rgba(148,163,184,0.4)', fontSize: 10 }}>
                  {isExpanded ? '▲' : '▼'}
                </span>
              </div>
            </div>

            {isExpanded && (
              <div style={{
                marginTop: 10,
                paddingTop: 10,
                borderTop: `1px solid ${sev.border}`,
                animation: 'fadeSlideUp 0.2s ease forwards',
              }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8 }}>
                  {[
                    { label: 'Endpoint', value: parsed.url },
                    { label: 'Parameter', value: parsed.param },
                  ].map(item => (
                    <div key={item.label}>
                      <div style={{
                        fontSize: 8, color: 'rgba(148,163,184,0.4)',
                        letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 2,
                      }}>{item.label}</div>
                      <div style={{
                        fontSize: 10, color: '#e2e8f0',
                        fontFamily: '"Space Mono", monospace',
                        wordBreak: 'break-all',
                      }}>{item.value}</div>
                    </div>
                  ))}
                </div>
                <div style={{
                  background: 'rgba(0,0,0,0.3)',
                  borderRadius: 6,
                  padding: '8px 12px',
                  fontSize: 9,
                  color: 'rgba(148,163,184,0.7)',
                  fontFamily: '"Space Mono", monospace',
                  lineHeight: 1.7,
                  borderLeft: `2px solid ${sev.color}55`,
                }}>
                  {finding.raw}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
