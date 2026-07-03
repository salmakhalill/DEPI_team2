import { useEffect, useRef } from 'react';
import type { LogEntry } from '../types/scan';

interface LogTerminalProps {
  logs: LogEntry[];
  connected: boolean;
}

const typeStyle: Record<LogEntry['type'], { color: string; prefix: string }> = {
  spider:    { color: '#22d3ee',  prefix: '→' },
  extractor: { color: '#8e27f0', prefix: '⟡' },
  scanner:   { color: '#f59e0b', prefix: '⚡' },
  finding:   { color: '#e62424', prefix: '☠' },
  reporter:  { color: '#10b981', prefix: '◈' },
  done:      { color: '#10b981', prefix: '✓' },
  error:     { color: '#e62424', prefix: '✗' },
  info:      { color: 'rgba(148,163,184,0.6)', prefix: '·' },
};

export default function LogTerminal({ logs, connected }: LogTerminalProps) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs.length]);

  return (
    <div style={{
      background: 'rgba(0,0,0,0.5)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 14,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      height: '100%',
    }}>
      {/* Terminal header */}
      <div style={{
        padding: '10px 16px',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        background: 'rgba(0,0,0,0.3)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ display: 'flex', gap: 5 }}>
            {['#ef4444', '#f59e0b', '#10b981'].map((c, i) => (
              <div key={i} style={{
                width: 10, height: 10,
                borderRadius: '50%',
                background: c,
                opacity: 0.7,
              }} />
            ))}
          </div>
          <span style={{
            fontFamily: '"Space Mono", monospace',
            fontSize: 10,
            color: 'rgba(148,163,184,0.5)',
            letterSpacing: '0.1em',
            marginLeft: 8,
          }}>nexusflow — scan log</span>
        </div>

        {/* Connection indicator */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <div style={{
            width: 5, height: 5, borderRadius: '50%',
            background: connected ? '#10b981' : '#ef4444',
            boxShadow: `0 0 6px ${connected ? '#10b981' : '#ef4444'}`,
            animation: connected ? 'statusPulse 1.2s ease-in-out infinite' : 'none',
          }} />
          <span style={{
            fontSize: 8,
            color: 'rgba(148,163,184,0.4)',
            letterSpacing: '0.12em',
            textTransform: 'uppercase',
          }}>{connected ? 'Live' : 'Disconnected'}</span>
        </div>
      </div>

      {/* Log output */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '12px 16px',
        fontFamily: '"Space Mono", monospace',
        fontSize: 11,
        lineHeight: 1.9,
      }}>
        {logs.length === 0 ? (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            height: '100%',
            flexDirection: 'column',
            gap: 8,
          }}>
            <div style={{
              width: 20, height: 20,
              border: '2px solid rgba(34,211,238,0.3)',
              borderTopColor: '#22d3ee',
              borderRadius: '50%',
              animation: 'scanLine 0.8s linear infinite',
            }} />
            <span style={{
              fontSize: 10,
              color: 'rgba(148,163,184,0.35)',
              letterSpacing: '0.12em',
            }}>ESTABLISHING CONNECTION...</span>
          </div>
        ) : (
          logs.map((log) => {
            const style = typeStyle[log.type];
            return (
              <div
                key={log.id}
                style={{
                  display: 'flex',
                  gap: 8,
                  animation: 'findingSlideIn 0.3s ease forwards',
                  borderBottom: log.type === 'finding' ? '1px solid rgba(239,68,68,0.1)' : 'none',
                  paddingBottom: log.type === 'finding' ? 4 : 0,
                  marginBottom: log.type === 'finding' ? 4 : 0,
                  background: log.type === 'finding'
                    ? 'rgba(239,68,68,0.04)'
                    : log.type === 'done'
                    ? 'rgba(16,185,129,0.04)'
                    : 'transparent',
                  borderRadius: 4,
                  padding: '1px 4px',
                }}
              >
                <span style={{ color: style.color, flexShrink: 0, width: 12, textAlign: 'center' }}>
                  {style.prefix}
                </span>
                <span style={{
                  color: log.type === 'finding'
                    ? '#fca5a5'
                    : log.type === 'done'
                    ? '#86efac'
                    : log.type === 'error'
                    ? '#fca5a5'
                    : style.color,
                  wordBreak: 'break-all',
                }}>
                  {log.message}
                </span>
              </div>
            );
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
