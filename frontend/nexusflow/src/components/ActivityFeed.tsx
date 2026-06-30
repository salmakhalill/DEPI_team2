import { useRef, useEffect } from 'react';
import type { ActivityEvent, EventType } from '../types/scan';

interface Props { events: ActivityEvent[]; }

const EVENT_CONFIG: Record<EventType, { icon: string; color: string; bg: string }> = {
  spider:   { icon: '⟡', color: '#22d3ee', bg: 'rgba(34,211,238,0.07)' },
  surface:  { icon: '◈', color: '#a855f7', bg: 'rgba(168,85,247,0.07)' },
  scanner:  { icon: '⚡', color: '#f59e0b', bg: 'rgba(245,158,11,0.07)' },
  finding:  { icon: '☠', color: '#ef4444', bg: 'rgba(239,68,68,0.09)'  },
  exploit:  { icon: '⊛', color: '#f97316', bg: 'rgba(249,115,22,0.07)' },
  payload:  { icon: '⊗', color: '#ef4444', bg: 'rgba(239,68,68,0.07)'  },
  reporter: { icon: '◇', color: '#10b981', bg: 'rgba(16,185,129,0.07)' },
  done:     { icon: '✓', color: '#10b981', bg: 'rgba(16,185,129,0.09)' },
  error:    { icon: '✗', color: '#ef4444', bg: 'rgba(239,68,68,0.09)'  },
  target:   { icon: '⬡', color: '#22d3ee', bg: 'rgba(34,211,238,0.07)' },
  info:     { icon: '·', color: 'rgba(148,163,184,0.6)', bg: 'transparent' },
};

function fmt(d: Date) {
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export default function ActivityFeed({ events }: Props) {
  const topRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    topRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }, [events.length]);

  return (
    <div style={{
      background: 'rgba(0,0,0,0.45)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 16,
      display: 'flex', flexDirection: 'column',
      overflow: 'hidden', height: '100%',
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 18px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: 'rgba(0,0,0,0.3)', flexShrink: 0,
      }}>
        <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 13, letterSpacing: '0.12em', color: '#a855f7' }}>
          ⟡ Live Activity
        </span>
        <div style={{
          padding: '2px 8px', borderRadius: 20, fontSize: 8,
          background: 'rgba(168,85,247,0.1)', border: '1px solid rgba(168,85,247,0.3)',
          color: '#a855f7', letterSpacing: '0.1em',
        }}>{events.length} EVENTS</div>
      </div>

      {/* Events list — newest on top */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: 6 }}>
        <div ref={topRef} />

        {events.length === 0 ? (
          <div style={{
            flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexDirection: 'column', gap: 10,
          }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%',
              border: '2px solid rgba(168,85,247,0.3)', borderTopColor: '#a855f7',
              animation: 'scanLine 0.9s linear infinite',
            }} />
            <span style={{ fontSize: 9, color: 'rgba(148,163,184,0.35)', letterSpacing: '0.14em' }}>
              WAITING FOR EVENTS...
            </span>
          </div>
        ) : events.map((ev, i) => {
          const cfg  = EVENT_CONFIG[ev.type] || EVENT_CONFIG.info;
          const isFinding = ev.type === 'finding';
          const isDone    = ev.type === 'done';

          return (
            <div key={ev.id} style={{
              display: 'flex', gap: 10, alignItems: 'flex-start',
              padding: '8px 10px', borderRadius: 8,
              background: isFinding ? 'rgba(239,68,68,0.06)' : isDone ? 'rgba(16,185,129,0.06)' : cfg.bg,
              border: isFinding ? '1px solid rgba(239,68,68,0.2)' : isDone ? '1px solid rgba(16,185,129,0.2)' : '1px solid transparent',
              animation: i === 0 ? 'findingSlideIn 0.35s ease forwards' : 'none',
              transition: 'all 0.2s',
            }}>
              {/* Icon badge */}
              <div style={{
                width: 26, height: 26, borderRadius: 6, flexShrink: 0,
                background: `${cfg.color}15`, border: `1px solid ${cfg.color}35`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 11, color: cfg.color,
              }}>{cfg.icon}</div>

              {/* Content */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 2 }}>
                  <span style={{
                    fontFamily: '"Bebas Neue", sans-serif', fontSize: 12, letterSpacing: '0.06em',
                    color: isFinding ? '#fca5a5' : isDone ? '#86efac' : '#e2e8f0',
                  }}>{ev.title}</span>
                  <span style={{
                    fontSize: 8, color: 'rgba(148,163,184,0.35)',
                    fontFamily: '"Space Mono", monospace', letterSpacing: '0.06em', flexShrink: 0, marginLeft: 8,
                  }}>{fmt(ev.timestamp)}</span>
                </div>
                <div style={{
                  fontSize: 9, color: isFinding ? 'rgba(252,165,165,0.8)' : 'rgba(148,163,184,0.6)',
                  fontFamily: '"Space Mono", monospace', lineHeight: 1.6,
                  wordBreak: 'break-all',
                }}>{ev.detail}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
