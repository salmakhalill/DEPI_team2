import { useState } from 'react';
import type { Finding, Severity } from '../types/scan';

interface Props { findings: Finding[]; }

const SEV: Record<Severity, { color: string; bg: string; border: string; label: string }> = {
  critical: { color: '#e93026', bg: 'rgba(192,80,74,0.08)',   border: 'rgba(192,80,74,0.25)',  label: 'CRITICAL' },
  high:     { color: '#e8971e', bg: 'rgba(201,150,74,0.08)',  border: 'rgba(201,150,74,0.25)', label: 'HIGH'     },
  medium:   { color: '#782bef', bg: 'rgba(155,126,200,0.08)', border: 'rgba(155,126,200,0.25)',label: 'MEDIUM'   },
  low:      { color: '#22d3ee', bg: 'rgba(125,211,232,0.08)', border: 'rgba(125,211,232,0.25)',label: 'LOW'      },
  info:     { color: 'rgba(139,148,158,0.5)', bg: 'rgba(255,255,255,0.03)', border: 'rgba(255,255,255,0.08)', label: 'INFO' },
};

const COLS = ['#', 'Vulnerability', 'Severity', 'Endpoint', 'Parameter', 'Status'];

export default function FindingsTable({ findings }: Props) {
  const [selected, setSelected] = useState<Finding | null>(null);
  const [sort, setSort]         = useState<'severity' | 'time'>('severity');

  const sorted = [...findings].sort((a, b) => {
    if (sort === 'severity') {
      const order: Record<Severity, number> = { critical:0, high:1, medium:2, low:3, info:4 };
      return order[a.severity] - order[b.severity];
    }
    return b.timestamp.getTime() - a.timestamp.getTime();
  });

  if (findings.length === 0) return (
    <div style={{
      padding: '28px', textAlign: 'center',
      background: 'rgba(22,27,34,0.5)', border: '1px solid rgba(255,255,255,0.06)',
      borderRadius: 12, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
    }}>
      <div style={{ fontSize: 20, color: 'rgba(77,171,138,0.35)' }}>◈</div>
      <div style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 16, color: 'rgba(139,148,158,0.3)', letterSpacing: '0.06em' }}>
        No Vulnerabilities Found Yet
      </div>
      <div style={{ fontSize: 8, color: 'rgba(139,148,158,0.2)', fontFamily: '"Space Mono", monospace', letterSpacing: '0.1em' }}>
        Findings appear here as the scanner discovers them
      </div>
    </div>
  );

  return (
    <>
      <div style={{
        background: 'rgba(13,17,23,0.55)',
        border: '1px solid rgba(255,255,255,0.06)',
        borderRadius: 12, overflow: 'hidden',
      }}>
        {/* Header bar */}
        <div style={{
          padding: '9px 14px',
          borderBottom: '1px solid rgba(255,255,255,0.05)',
          background: 'rgba(13,17,23,0.4)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 12, letterSpacing: '0.1em', color: '#c0504a' }}>
            Security Findings
          </span>
          <div style={{ display: 'flex', gap: 5 }}>
            {(['severity', 'time'] as const).map(s => (
              <button key={s} onClick={() => setSort(s)} style={{
                padding: '2px 9px', borderRadius: 5, fontSize: 7, cursor: 'pointer',
                fontFamily: '"Space Mono", monospace', letterSpacing: '0.1em',
                background: sort === s ? 'rgba(125,211,232,0.08)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${sort === s ? 'rgba(125,211,232,0.25)' : 'rgba(255,255,255,0.07)'}`,
                color: sort === s ? '#7dd3e8' : 'rgba(139,148,158,0.4)',
                textTransform: 'uppercase',
              }}>Sort: {s}</button>
            ))}
          </div>
        </div>

        {/* Column headers */}
        <div style={{
          display: 'grid', gridTemplateColumns: '32px 1fr 86px 1fr 96px 76px',
          padding: '7px 14px',
          borderBottom: '1px solid rgba(255,255,255,0.04)',
          background: 'rgba(255,255,255,0.01)',
        }}>
          {COLS.map(c => (
            <div key={c} style={{
              fontSize: 7, color: 'rgba(139,148,158,0.35)',
              letterSpacing: '0.14em', textTransform: 'uppercase',
              fontFamily: '"Space Mono", monospace',
            }}>{c}</div>
          ))}
        </div>

        {/* Rows */}
        {sorted.map((f, i) => {
          const s = SEV[f.severity];
          return (
            <div key={f.id} onClick={() => setSelected(f)} style={{
              display: 'grid', gridTemplateColumns: '32px 1fr 86px 1fr 96px 76px',
              padding: '9px 14px', cursor: 'pointer',
              borderBottom: i < sorted.length - 1 ? '1px solid rgba(255,255,255,0.03)' : 'none',
              borderLeft: `2px solid ${s.color}55`,
              transition: 'background 0.12s',
              animation: `findingSlideIn 0.35s ease ${i * 0.04}s forwards`,
              opacity: 0,
            }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = s.bg; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = selected?.id === f.id ? s.bg : 'transparent'; }}
            >
              <div style={{ fontSize: 8, color: 'rgba(139,148,158,0.25)', fontFamily: '"Space Mono", monospace', alignSelf: 'center' }}>
                {String(i + 1).padStart(2, '0')}
              </div>
              <div style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 13, letterSpacing: '0.04em', color: '#c9d1d9', alignSelf: 'center' }}>
                {f.type}
              </div>
              <div style={{ alignSelf: 'center' }}>
                <span style={{
                  padding: '2px 7px', borderRadius: 4, fontSize: 7, fontWeight: 700,
                  background: s.bg, border: `1px solid ${s.border}`,
                  color: s.color, letterSpacing: '0.1em',
                }}>{s.label}</span>
              </div>
              <div style={{ fontSize: 8, color: 'rgba(139,148,158,0.6)', fontFamily: '"Space Mono", monospace', alignSelf: 'center', wordBreak: 'break-all' }}>
                {f.endpoint}
              </div>
              <div style={{ fontSize: 8, color: 'rgba(139,148,158,0.5)', fontFamily: '"Space Mono", monospace', alignSelf: 'center' }}>
                {f.param}
              </div>
              <div style={{ alignSelf: 'center' }}>
                <span style={{
                  padding: '2px 6px', borderRadius: 4, fontSize: 7,
                  background: 'rgba(77,171,138,0.08)', border: '1px solid rgba(77,171,138,0.22)',
                  color: '#4dab8a', letterSpacing: '0.07em',
                }}>✓ {f.status}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Detail drawer */}
      {selected && (
        <div
          style={{
            position: 'fixed', inset: 0, zIndex: 1000,
            background: 'rgba(13,17,23,0.65)',
            backdropFilter: 'blur(6px)',
            display: 'flex', justifyContent: 'flex-end',
            animation: 'fadeSlideUp 0.18s ease forwards',
          }}
          onClick={() => setSelected(null)}
        >
          <div onClick={e => e.stopPropagation()} style={{
            width: '100%', maxWidth: 500, height: '100%',
            background: '#0d1117',
            borderLeft: '1px solid rgba(255,255,255,0.07)',
            overflowY: 'auto', padding: '28px 24px',
            animation: 'findingSlideIn 0.25s ease forwards',
          }}>
            <button onClick={() => setSelected(null)} style={{
              background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)',
              color: 'rgba(139,148,158,0.55)', borderRadius: 5, padding: '3px 10px',
              cursor: 'pointer', fontSize: 9, fontFamily: '"Space Mono", monospace',
              marginBottom: 20, letterSpacing: '0.06em',
            }}>← Close</button>

            <div style={{ display: 'flex', gap: 7, marginBottom: 10 }}>
              <span style={{
                padding: '2px 9px', borderRadius: 4, fontSize: 8, fontWeight: 700,
                background: SEV[selected.severity].bg,
                border: `1px solid ${SEV[selected.severity].border}`,
                color: SEV[selected.severity].color, letterSpacing: '0.1em',
              }}>{SEV[selected.severity].label}</span>
              <span style={{
                padding: '2px 9px', borderRadius: 4, fontSize: 8,
                background: 'rgba(77,171,138,0.08)', border: '1px solid rgba(77,171,138,0.2)',
                color: '#4dab8a', letterSpacing: '0.07em',
              }}>✓ {selected.status}</span>
            </div>

            <h2 style={{
              fontFamily: '"Bebas Neue", sans-serif', fontSize: 26, letterSpacing: '0.05em',
              color: '#e6edf3', marginBottom: 22,
            }}>{selected.type}</h2>

            {[
              { label: 'Affected Endpoint', value: selected.endpoint },
              { label: 'Affected Parameter', value: selected.param },
            ].map(row => (
              <div key={row.label} style={{
                padding: '10px 12px', borderRadius: 7, marginBottom: 8,
                background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
              }}>
                <div style={{ fontSize: 7, color: 'rgba(139,148,158,0.38)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 4 }}>{row.label}</div>
                <div style={{ fontSize: 10, color: '#c9d1d9', fontFamily: '"Space Mono", monospace', wordBreak: 'break-all' }}>{row.value}</div>
              </div>
            ))}

            <div style={{ padding: '12px', borderRadius: 7, marginBottom: 8, background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)' }}>
              <div style={{ fontSize: 7, color: 'rgba(139,148,158,0.38)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 7 }}>Description</div>
              <p style={{ fontSize: 10, color: 'rgba(139,148,158,0.75)', lineHeight: 1.9, fontFamily: '"Space Mono", monospace' }}>{selected.description}</p>
            </div>

            <div style={{ padding: '12px', borderRadius: 7, marginBottom: 8, background: 'rgba(77,171,138,0.04)', border: '1px solid rgba(77,171,138,0.15)' }}>
              <div style={{ fontSize: 7, color: 'rgba(77,171,138,0.55)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 7 }}>Remediation</div>
              <p style={{ fontSize: 10, color: 'rgba(139,148,158,0.75)', lineHeight: 1.9, fontFamily: '"Space Mono", monospace' }}>{selected.remediation}</p>
            </div>

            {selected.evidence && (
              <div style={{
                padding: '10px 12px', borderRadius: 7,
                background: 'rgba(13,17,23,0.8)',
                border: `1px solid ${SEV[selected.severity].border}`,
                borderLeft: `2px solid ${SEV[selected.severity].color}55`,
              }}>
                <div style={{ fontSize: 7, color: 'rgba(139,148,158,0.35)', letterSpacing: '0.14em', textTransform: 'uppercase', marginBottom: 5 }}>Evidence</div>
                <code style={{ fontSize: 8, color: 'rgba(139,148,158,0.6)', lineHeight: 1.8, wordBreak: 'break-all', display: 'block' }}>{selected.evidence}</code>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
