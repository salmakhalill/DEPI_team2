import type { Endpoint } from '../types/scan';

interface Props { endpoints: Endpoint[]; }

export default function AttackSurface({ endpoints }: Props) {
  const vulnCount    = endpoints.filter(e => e.vulnerable).length;
  const scannedCount = endpoints.filter(e => e.scanned).length;

  return (
    <div style={{
      background: 'rgba(13,17,23,0.6)',
      border: '1px solid rgba(255,255,255,0.06)',
      borderRadius: 12, overflow: 'hidden',
    }}>
      <div style={{
        padding: '10px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        background: 'rgba(13,17,23,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      }}>
        <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 12, letterSpacing: '0.1em', color: '#16c072' }}>
          Attack Surface
        </span>
        <div style={{ display: 'flex', gap: 6 }}>
          <span style={{
            padding: '1px 7px', borderRadius: 20, fontSize: 7,
            background: 'rgba(125,211,232,0.07)', border: '1px solid rgba(125,211,232,0.18)',
            color: 'rgba(125,211,232,0.7)', letterSpacing: '0.1em',
          }}>{endpoints.length} endpoints</span>
          {vulnCount > 0 && (
            <span style={{
              padding: '1px 7px', borderRadius: 20, fontSize: 7,
              background: 'rgba(192,80,74,0.08)', border: '1px solid rgba(192,80,74,0.2)',
              color: '#d4231a', letterSpacing: '0.1em',
            }}>{vulnCount} vuln</span>
          )}
        </div>
      </div>

      <div style={{ padding: '10px 12px', maxHeight: 210, overflowY: 'auto' }}>
        {endpoints.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '20px 0', fontSize: 8, color: 'rgba(139,148,158,0.3)', letterSpacing: '0.12em' }}>
            AWAITING SPIDER
          </div>
        ) : (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
            {endpoints.map((ep, i) => (
              <div key={ep.id} style={{
                padding: '4px 9px', borderRadius: 6,
                border: `1px solid ${ep.vulnerable ? 'rgba(192,80,74,0.3)' : ep.scanned ? 'rgba(155,126,200,0.2)' : 'rgba(125,211,232,0.15)'}`,
                background: ep.vulnerable ? 'rgba(192,80,74,0.06)' : ep.scanned ? 'rgba(155,126,200,0.05)' : 'rgba(125,211,232,0.04)',
                display: 'flex', alignItems: 'center', gap: 5,
                animation: 'findingSlideIn 0.3s ease forwards',
                animationDelay: `${Math.min(i * 0.035, 0.25)}s`,
                opacity: 0,
              }}>
                <div style={{
                  width: 4, height: 4, borderRadius: '50%', flexShrink: 0,
                  background: ep.vulnerable ? '#d4231a' : ep.scanned ? '#7028e0' : '#16c072',
                  opacity: ep.vulnerable ? 0.9 : 0.5,
                }} />
                <span style={{
                  fontFamily: '"Space Mono", monospace', fontSize: 8,
                  color: ep.vulnerable ? 'rgba(192,80,74,0.85)' : ep.scanned ? 'rgba(155,126,200,0.7)' : 'rgba(139,148,158,0.65)',
                }}>{ep.path.length > 26 ? ep.path.slice(0, 23) + '…' : ep.path}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {endpoints.length > 0 && (
        <div style={{ padding: '0 12px 10px' }}>
          <div style={{
            display: 'flex', justifyContent: 'space-between', marginBottom: 4,
            fontSize: 7, color: 'rgba(139,148,158,0.35)',
            fontFamily: '"Space Mono", monospace', letterSpacing: '0.1em',
          }}>
            <span>COVERAGE</span>
            <span>{endpoints.length > 0 ? Math.round((scannedCount / endpoints.length) * 100) : 0}%</span>
          </div>
          <div style={{ height: 2, background: 'rgba(255,255,255,0.04)', borderRadius: 2 }}>
            <div style={{
              height: '100%',
              width: `${endpoints.length > 0 ? (scannedCount / endpoints.length) * 100 : 0}%`,
              background: '#7028e0', opacity: 0.5,
              borderRadius: 2, transition: 'width 0.8s ease',
            }} />
          </div>
        </div>
      )}
    </div>
  );
}
