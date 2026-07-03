import { useRef, useEffect } from 'react';
import type { ActivityEvent, EventType } from '../types/scan';

interface Props { events: ActivityEvent[]; }

const CFG: Record<EventType, { icon: string; color: string }> = {
  spider:   { icon: '⟡', color: '#7dd3e8' },
  surface:  { icon: '◈', color: '#9b7ec8' },
  scanner:  { icon: '⚡', color: '#c9964a' },
  finding:  { icon: '☠', color: '#c0504a' },
  exploit:  { icon: '⊛', color: '#c0504a' },
  payload:  { icon: '⊗', color: '#c0504a' },
  reporter: { icon: '◇', color: '#4dab8a' },
  done:     { icon: '✓', color: '#4dab8a' },
  error:    { icon: '✗', color: '#c0504a' },
  target:   { icon: '⬡', color: '#7dd3e8' },
  info:     { icon: '·', color: 'rgba(139,148,158,0.45)' },
};

function fmt(d: Date) {
  return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export default function ActivityFeed({ events }: Props) {
  const topRef = useRef<HTMLDivElement>(null);
  useEffect(() => { topRef.current?.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); }, [events.length]);

  return (
    <div style={{
      background: 'rgba(13,17,23,0.5)',
      border: '1px solid rgba(255,255,255,0.06)',
      borderRadius: 12, display: 'flex', flexDirection: 'column', overflow: 'hidden', height: '100%',
    }}>
      {/* Header */}
      <div style={{
        padding: '10px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.05)',
        background: 'rgba(13,17,23,0.5)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
      }}>
        <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 12, letterSpacing: '0.1em', color: '#9b7ec8' }}>
          Activity Feed
        </span>
        <span style={{
          padding: '1px 7px', borderRadius: 20, fontSize: 7,
          background: 'rgba(155,126,200,0.08)', border: '1px solid rgba(155,126,200,0.2)',
          color: 'rgba(155,126,200,0.7)', letterSpacing: '0.1em',
        }}>{events.length}</span>
      </div>

      {/* Events */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        <div ref={topRef} />
        {events.length === 0 ? (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 8 }}>
            <div style={{
              width: 22, height: 22, borderRadius: '50%',
              border: '1.5px solid rgba(125,211,232,0.15)', borderTopColor: 'rgba(125,211,232,0.5)',
              animation: 'spinLoader 1s linear infinite',
            }} />
            <span style={{ fontSize: 8, color: 'rgba(139,148,158,0.3)', letterSpacing: '0.14em' }}>WAITING...</span>
          </div>
        ) : events.map((ev, i) => {
          const cfg     = CFG[ev.type] || CFG.info;
          const isFinding = ev.type === 'finding';
          const isDone    = ev.type === 'done';
          return (
            <div key={ev.id} style={{
              display: 'flex', gap: 9, alignItems: 'flex-start',
              padding: '7px 9px', borderRadius: 7,
              background: isFinding
                ? 'rgba(192,80,74,0.06)'
                : isDone ? 'rgba(77,171,138,0.06)' : 'rgba(255,255,255,0.02)',
              border: isFinding
                ? '1px solid rgba(192,80,74,0.15)'
                : isDone ? '1px solid rgba(77,171,138,0.15)' : '1px solid transparent',
              animation: i === 0 ? 'findingSlideIn 0.3s ease forwards' : 'none',
            }}>
              <div style={{
                width: 22, height: 22, borderRadius: 5, flexShrink: 0,
                background: `${cfg.color}10`,
                border: `1px solid ${cfg.color}22`,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 9, color: cfg.color, opacity: 0.85,
              }}>{cfg.icon}</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 2 }}>
                  <span style={{
                    fontFamily: '"Bebas Neue", sans-serif', fontSize: 11, letterSpacing: '0.05em',
                    color: isFinding ? '#d97b76' : isDone ? '#4dab8a' : '#c9d1d9',
                  }}>{ev.title}</span>
                  <span style={{
                    fontSize: 7, color: 'rgba(139,148,158,0.3)',
                    fontFamily: '"Space Mono", monospace', flexShrink: 0, marginLeft: 6,
                  }}>{fmt(ev.timestamp)}</span>
                </div>
                <div style={{
                  fontSize: 8, color: isFinding ? 'rgba(217,123,118,0.7)' : 'rgba(139,148,158,0.5)',
                  fontFamily: '"Space Mono", monospace', lineHeight: 1.6, wordBreak: 'break-all',
                }}>{ev.detail}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
