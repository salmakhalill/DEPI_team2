import type { Endpoint } from '../types/scan';

interface Props { endpoints: Endpoint[]; }

export default function AttackSurface({ endpoints }: Props) {
  const vulnCount    = endpoints.filter(e => e.vulnerable).length;
  const scannedCount = endpoints.filter(e => e.scanned).length;

  return (
    <div style={{
      background: 'rgba(0,0,0,0.4)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 16, overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 18px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        background: 'rgba(0,0,0,0.3)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 13, letterSpacing: '0.12em', color: '#22d3ee' }}>
          ⬡ Attack Surface
        </span>
        <div style={{ display: 'flex', gap: 8 }}>
          <div style={{
            padding: '2px 8px', borderRadius: 20, fontSize: 8,
            background: 'rgba(34,211,238,0.1)', border: '1px solid rgba(34,211,238,0.3)',
            color: '#22d3ee', letterSpacing: '0.1em',
          }}>{endpoints.length} ENDPOINTS</div>
          {vulnCount > 0 && (
            <div style={{
              padding: '2px 8px', borderRadius: 20, fontSize: 8,
              background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)',
              color: '#ef4444', letterSpacing: '0.1em',
            }}>{vulnCount} VULNERABLE</div>
          )}
        </div>
      </div>

      {/* Endpoint grid */}
      <div style={{ padding: '12px 14px', maxHeight: 220, overflowY: 'auto' }}>
        {endpoints.length === 0 ? (
          <div style={{
            textAlign: 'center', padding: '24px 0',
            fontSize: 9, color: 'rgba(148,163,184,0.35)', letterSpacing: '0.12em',
          }}>AWAITING SPIDER...</div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {endpoints.map((ep, i) => (
              <div key={ep.id} style={{
                padding: '5px 10px',
                borderRadius: 7,
                border: `1px solid ${ep.vulnerable ? 'rgba(239,68,68,0.45)' : ep.scanned ? 'rgba(168,85,247,0.3)' : 'rgba(34,211,238,0.2)'}`,
                background: ep.vulnerable ? 'rgba(239,68,68,0.08)' : ep.scanned ? 'rgba(168,85,247,0.06)' : 'rgba(34,211,238,0.04)',
                display: 'flex', alignItems: 'center', gap: 6,
                animation: 'findingSlideIn 0.3s ease forwards',
                animationDelay: `${Math.min(i * 0.04, 0.3)}s`,
                opacity: 0,
                cursor: 'default',
                transition: 'border-color 0.3s, background 0.3s',
              }}>
                {/* Status dot */}
                <div style={{
                  width: 5, height: 5, borderRadius: '50%', flexShrink: 0,
                  background: ep.vulnerable ? '#ef4444' : ep.scanned ? '#a855f7' : '#22d3ee',
                  boxShadow: ep.vulnerable ? '0 0 6px #ef4444' : 'none',
                  animation: ep.vulnerable ? 'statusPulse 1.2s ease-in-out infinite' : 'none',
                }} />
                <span style={{
                  fontFamily: '"Space Mono", monospace', fontSize: 9,
                  color: ep.vulnerable ? '#fca5a5' : ep.scanned ? '#d8b4fe' : 'rgba(148,163,184,0.8)',
                  letterSpacing: '0.04em',
                }}>{ep.path.length > 28 ? ep.path.slice(0, 25) + '…' : ep.path}</span>
                {ep.vulnerable && (
                  <span style={{ fontSize: 8, color: '#ef4444', marginLeft: 2 }}>☠</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Progress bar */}
      {endpoints.length > 0 && (
        <div style={{
          padding: '0 14px 12px',
        }}>
          <div style={{
            display: 'flex', justifyContent: 'space-between',
            fontSize: 7, color: 'rgba(148,163,184,0.4)',
            fontFamily: '"Space Mono", monospace', letterSpacing: '0.1em',
            marginBottom: 5,
          }}>
            <span>SCAN COVERAGE</span>
            <span>{endpoints.length > 0 ? Math.round((scannedCount / endpoints.length) * 100) : 0}%</span>
          </div>
          <div style={{ height: 3, background: 'rgba(255,255,255,0.05)', borderRadius: 2 }}>
            <div style={{
              height: '100%',
              width: `${endpoints.length > 0 ? (scannedCount / endpoints.length) * 100 : 0}%`,
              background: 'linear-gradient(90deg, #a855f7, #22d3ee)',
              borderRadius: 2, transition: 'width 0.8s ease',
            }} />
          </div>
        </div>
      )}
    </div>
  );
}
