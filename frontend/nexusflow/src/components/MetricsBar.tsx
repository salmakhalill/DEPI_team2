import type { Finding, Endpoint, Severity } from '../types/scan';

interface Props {
  findings: Finding[];
  endpoints: Endpoint[];
  scanProgress: number;
  status: string;
}

interface CardDef { label: string; value: string | number; color: string; bg: string; }

export default function MetricsBar({ findings, endpoints, scanProgress }: Props) {
  const bySev = (sev: Severity) => findings.filter(f => f.severity === sev).length;

  const cards: CardDef[] = [
    { label: 'Critical',    value: bySev('critical'), color: '#ef4444', bg: 'rgba(239,68,68,0.1)'   },
    { label: 'High',        value: bySev('high'),     color: '#f59e0b', bg: 'rgba(245,158,11,0.1)'  },
    { label: 'Medium',      value: bySev('medium'),   color: '#a855f7', bg: 'rgba(168,85,247,0.1)'  },
    { label: 'Low',         value: bySev('low'),      color: '#22d3ee', bg: 'rgba(34,211,238,0.1)'  },
    { label: 'Endpoints',   value: endpoints.length,  color: '#06b6d4', bg: 'rgba(6,182,212,0.1)'   },
    { label: 'Total Vulns', value: findings.length,   color: '#ef4444', bg: 'rgba(239,68,68,0.06)'  },
    { label: 'Attack Size', value: endpoints.length,  color: '#a855f7', bg: 'rgba(168,85,247,0.06)' },
    { label: 'Progress',    value: `${scanProgress}%`,color: '#10b981', bg: 'rgba(16,185,129,0.06)' },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: 8, marginBottom: 16 }}>
      {cards.map((c, i) => (
        <div key={c.label} style={{
          background: c.bg, border: `1px solid ${c.color}30`,
          borderRadius: 10, padding: '10px 12px', textAlign: 'center',
          animation: `fadeSlideUp 0.4s ease ${i * 0.04}s forwards`,
          opacity: 0, position: 'relative', overflow: 'hidden',
        }}>
          {c.label === 'Progress' && (
            <div style={{
              position: 'absolute', bottom: 0, left: 0,
              height: 2, width: `${scanProgress}%`,
              background: '#10b981', transition: 'width 1.2s ease',
            }} />
          )}
          <div style={{
            fontFamily: '"Bebas Neue", sans-serif', fontSize: 24,
            color: c.color, lineHeight: 1, textShadow: `0 0 12px ${c.color}55`,
          }}>{c.value}</div>
          <div style={{
            fontSize: 7, color: 'rgba(148,163,184,0.45)',
            letterSpacing: '0.12em', textTransform: 'uppercase',
            fontFamily: '"Space Mono", monospace', marginTop: 3,
          }}>{c.label}</div>
        </div>
      ))}
    </div>
  );
}
