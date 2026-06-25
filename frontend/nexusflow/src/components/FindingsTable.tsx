import { useState } from 'react';
import type { Finding, Severity } from '../types/scan';

interface Props { findings: Finding[]; }

const SEV: Record<Severity, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: '#ef4444', bg: 'rgba(239,68,68,0.12)', border: 'rgba(239,68,68,0.4)',  label: 'CRITICAL' },
  high:     { color: '#f59e0b', bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.4)', label: 'HIGH'     },
  medium:   { color: '#a855f7', bg: 'rgba(168,85,247,0.12)', border: 'rgba(168,85,247,0.4)', label: 'MEDIUM'   },
  low:      { color: '#22d3ee', bg: 'rgba(34,211,238,0.12)', border: 'rgba(34,211,238,0.4)', label: 'LOW'      },
  info:     { color: 'rgba(148,163,184,0.6)', bg: 'rgba(255,255,255,0.04)', border: 'rgba(255,255,255,0.1)', label: 'INFO' },
};

const COLS = ['#', 'Vulnerability', 'Severity', 'Affected Endpoint', 'Parameter', 'Status'];

export default function FindingsTable({ findings }: Props) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [sort, setSort]         = useState<'severity' | 'time'>('severity');

  const sorted = [...findings].sort((a, b) => {
    if (sort === 'severity') {
      const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return order[a.severity] - order[b.severity];
    }
    return b.timestamp.getTime() - a.timestamp.getTime();
  });

  if (findings.length === 0) {
    return (
      <div style={{
        padding: '32px', textAlign: 'center',
        background: 'rgba(255,255,255,0.02)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 14,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
      }}>
        <div style={{ fontSize: 24, color: 'rgba(16,185,129,0.4)' }}>◈</div>
        <div style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 18, color: 'rgba(148,163,184,0.3)', letterSpacing: '0.08em' }}>
          No Vulnerabilities Found Yet
        </div>
        <div style={{ fontSize: 9, color: 'rgba(148,163,184,0.25)', fontFamily: '"Space Mono", monospace', letterSpacing: '0.1em' }}>
          Findings will appear here as the scanner discovers them
        </div>
      </div>
    );
  }

  return (
    <>
      {/* Table */}
      <div style={{
        background: 'rgba(0,0,0,0.4)',
        border: '1px solid rgba(255,255,255,0.07)',
        borderRadius: 14, overflow: 'hidden',
      }}>
        {/* Table header */}
        <div style={{
          padding: '10px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.06)',
          background: 'rgba(0,0,0,0.3)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 13, letterSpacing: '0.12em', color: '#ef4444' }}>
            ☠ Security Findings
          </span>
          <div style={{ display: 'flex', gap: 6 }}>
            {(['severity', 'time'] as const).map(s => (
              <button key={s} onClick={() => setSort(s)} style={{
                padding: '3px 10px', borderRadius: 6, fontSize: 8, cursor: 'pointer',
                fontFamily: '"Space Mono", monospace', letterSpacing: '0.1em',
                background: sort === s ? 'rgba(34,211,238,0.15)' : 'rgba(255,255,255,0.04)',
                border: `1px solid ${sort === s ? 'rgba(34,211,238,0.4)' : 'rgba(255,255,255,0.1)'}`,
                color: sort === s ? '#22d3ee' : 'rgba(148,163,184,0.5)',
                textTransform: 'uppercase',
              }}>Sort: {s}</button>
            ))}
          </div>
        </div>

        {/* Column headers */}
        <div style={{
          display: 'grid', gridTemplateColumns: '36px 1fr 90px 1fr 100px 80px',
          padding: '8px 16px',
          borderBottom: '1px solid rgba(255,255,255,0.04)',
          background: 'rgba(255,255,255,0.01)',
        }}>
          {COLS.map(c => (
            <div key={c} style={{
              fontSize: 8, color: 'rgba(148,163,184,0.4)',
              letterSpacing: '0.14em', textTransform: 'uppercase',
              fontFamily: '"Space Mono", monospace',
            }}>{c}</div>
          ))}
        </div>

        {/* Rows */}
        {sorted.map((f, i) => {
          const s = SEV[f.severity];
          return (
            <div
              key={f.id}
              onClick={() => setSelected(f)}
              style={{
                display: 'grid', gridTemplateColumns: '36px 1fr 90px 1fr 100px 80px',
                padding: '10px 16px', cursor: 'pointer',
                borderBottom: i < sorted.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none',
                borderLeft: `3px solid ${s.color}`,
                background: selected?.id === f.id ? `${s.bg}` : 'transparent',
                transition: 'background 0.15s',
                animation: `findingSlideIn 0.4s ease ${i * 0.05}s forwards`,
                opacity: 0,
              }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = s.bg; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = selected?.id === f.id ? s.bg : 'transparent'; }}
            >
              <div style={{ fontSize: 9, color: 'rgba(148,163,184,0.35)', fontFamily: '"Space Mono", monospace', alignSelf: 'center' }}>
                {String(i + 1).padStart(2, '0')}
              </div>
              <div style={{
                fontFamily: '"Bebas Neue", sans-serif', fontSize: 14, letterSpacing: '0.05em',
                color: '#f1f5f9', alignSelf: 'center',
              }}>{f.type}</div>
              <div style={{ alignSelf: 'center' }}>
                <span style={{
                  padding: '2px 8px', borderRadius: 20, fontSize: 8, fontWeight: 700,
                  background: s.bg, border: `1px solid ${s.color}`,
                  color: s.color, letterSpacing: '0.1em',
                }}>{s.label}</span>
              </div>
              <div style={{
                fontSize: 9, color: 'rgba(148,163,184,0.7)', fontFamily: '"Space Mono", monospace',
                alignSelf: 'center', wordBreak: 'break-all',
              }}>{f.endpoint}</div>
              <div style={{
                fontSize: 9, color: 'rgba(148,163,184,0.6)', fontFamily: '"Space Mono", monospace',
                alignSelf: 'center',
              }}>{f.param}</div>
              <div style={{ alignSelf: 'center' }}>
                <span style={{
                  padding: '2px 7px', borderRadius: 20, fontSize: 8,
                  background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.35)',
                  color: '#10b981', letterSpacing: '0.08em',
                }}>✓ {f.status}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Detail Drawer */}
      {selected && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            background: 'rgba(2,8,23,0.7)',
            backdropFilter: 'blur(8px)',
            display: 'flex', justifyContent: 'flex-end',
            animation: 'fadeSlideUp 0.2s ease forwards',
          }}
          onClick={() => setSelected(null)}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              width: '100%', maxWidth: 520, height: '100%',
              background: 'rgba(2,8,23,0.97)',
              borderLeft: `1px solid ${SEV[selected.severity].color}44`,
              overflowY: 'auto', padding: '32px 28px',
              animation: 'findingSlideIn 0.3s ease forwards',
            }}
          >
            {/* Drawer header */}
            <div style={{ marginBottom: 28 }}>
              <button
                onClick={() => setSelected(null)}
                style={{
                  background: 'rgba(255,255,255,0.05)', border: '1px solid rgba(255,255,255,0.1)',
                  color: 'rgba(148,163,184,0.6)', borderRadius: 6, padding: '4px 12px',
                  cursor: 'pointer', fontSize: 10, fontFamily: '"Space Mono", monospace',
                  marginBottom: 16, letterSpacing: '0.06em',
                }}
              >← Close</button>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                <span style={{
                  padding: '3px 10px', borderRadius: 20, fontSize: 9, fontWeight: 700,
                  background: SEV[selected.severity].bg,
                  border: `1px solid ${SEV[selected.severity].color}`,
                  color: SEV[selected.severity].color, letterSpacing: '0.12em',
                }}>{SEV[selected.severity].label}</span>
                <span style={{
                  padding: '3px 10px', borderRadius: 20, fontSize: 9,
                  background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.35)',
                  color: '#10b981', letterSpacing: '0.08em',
                }}>✓ {selected.status}</span>
              </div>
              <h2 style={{
                fontFamily: '"Bebas Neue", sans-serif', fontSize: 30, letterSpacing: '0.06em',
                color: '#f1f5f9', marginBottom: 4,
              }}>{selected.type}</h2>
            </div>

            {/* Fields */}
            {[
              { label: 'Affected Endpoint', value: selected.endpoint, mono: true },
              { label: 'Affected Parameter', value: selected.param, mono: true },
            ].map(row => (
              <div key={row.label} style={{
                padding: '12px 14px', borderRadius: 8, marginBottom: 10,
                background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
              }}>
                <div style={{ fontSize: 8, color: 'rgba(148,163,184,0.4)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 4 }}>{row.label}</div>
                <div style={{ fontSize: 11, color: '#e2e8f0', fontFamily: row.mono ? '"Space Mono", monospace' : 'inherit', wordBreak: 'break-all' }}>{row.value}</div>
              </div>
            ))}

            {/* Description */}
            <div style={{
              padding: '14px', borderRadius: 8, marginBottom: 10,
              background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
            }}>
              <div style={{ fontSize: 8, color: 'rgba(148,163,184,0.4)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 8 }}>Description</div>
              <p style={{ fontSize: 11, color: 'rgba(148,163,184,0.8)', lineHeight: 1.9, fontFamily: '"Space Mono", monospace' }}>
                {selected.description}
              </p>
            </div>

            {/* Remediation */}
            <div style={{
              padding: '14px', borderRadius: 8, marginBottom: 10,
              background: 'rgba(16,185,129,0.04)', border: '1px solid rgba(16,185,129,0.2)',
            }}>
              <div style={{ fontSize: 8, color: 'rgba(16,185,129,0.6)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 8 }}>◈ Remediation</div>
              <p style={{ fontSize: 11, color: 'rgba(148,163,184,0.8)', lineHeight: 1.9, fontFamily: '"Space Mono", monospace' }}>
                {selected.remediation}
              </p>
            </div>

            {/* Evidence */}
            {selected.evidence && (
              <div style={{
                padding: '12px 14px', borderRadius: 8,
                background: 'rgba(0,0,0,0.5)', border: `1px solid ${SEV[selected.severity].color}25`,
                borderLeft: `3px solid ${SEV[selected.severity].color}`,
              }}>
                <div style={{ fontSize: 8, color: 'rgba(148,163,184,0.4)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 6 }}>Evidence</div>
                <code style={{ fontSize: 9, color: 'rgba(148,163,184,0.7)', lineHeight: 1.8, wordBreak: 'break-all', display: 'block' }}>
                  {selected.evidence}
                </code>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
