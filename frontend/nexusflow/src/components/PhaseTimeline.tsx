import { useEffect, useState } from 'react';
import type { ScanPhase, ScanStatus } from '../types/scan';
import { PHASES } from '../types/scan';

interface Props {
  currentPhase: ScanPhase;
  completedPhases: Set<ScanPhase>;
  status: ScanStatus;
  scanProgress: number;
}

export default function PhaseTimeline({ currentPhase, completedPhases, status, scanProgress }: Props) {
  const [animated, setAnimated] = useState<Set<number>>(new Set());

  useEffect(() => {
    completedPhases.forEach(pid => {
      if (!animated.has(pid)) {
        setTimeout(() => setAnimated(prev => new Set([...prev, pid])), 250);
      }
    });
  }, [completedPhases]);

  const isDone   = status === 'completed';
  const isActive = (id: number) => currentPhase === id && !isDone;
  const isDoneP  = (id: number) => completedPhases.has(id as ScanPhase) || isDone;

  const lineProgress = (idx: number): number => {
    const from = idx + 1, to = idx + 2;
    if (isDoneP(from) && isDoneP(to)) return 100;
    if (isDoneP(from) && isActive(to)) return 60;
    if (isDoneP(from)) return 30;
    if (isActive(from)) return 10;
    return 0;
  };

  return (
    <div style={{
      background: 'rgba(255,255,255,0.018)',
      backdropFilter: 'blur(24px)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 20,
      padding: '0 32px 28px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Global progress bar */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: 'rgba(255,255,255,0.04)' }}>
        <div style={{
          height: '100%',
          width: `${scanProgress}%`,
          background: isDone
            ? 'linear-gradient(90deg,#22d3ee,#a855f7,#10b981)'
            : 'linear-gradient(90deg,#22d3ee,#a855f7)',
          transition: 'width 1.4s cubic-bezier(0.4,0,0.2,1)',
          boxShadow: '0 0 14px rgba(34,211,238,0.6)',
          borderRadius: '0 3px 3px 0',
        }} />
      </div>

      {/* Sweep shimmer */}
      {status === 'running' && (
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          background: 'linear-gradient(90deg, transparent, rgba(34,211,238,0.025), transparent)',
          backgroundSize: '200% 100%', animation: 'shimmer 4s linear infinite',
        }} />
      )}

      {/* Phases row */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', paddingTop: 28 }}>
        {PHASES.map((phase, idx) => {
          const active    = isActive(phase.id);
          const completed = isDoneP(phase.id);
          const anim      = animated.has(phase.id) || isDone;
          const c         = phase.color;

          return (
            <div key={phase.id} style={{ display: 'flex', alignItems: 'flex-start', flex: idx < PHASES.length - 1 ? 1 : 0 }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>

                {/* Ripple ring */}
                {active && (
                  <div style={{
                    position: 'absolute', marginTop: -8,
                    width: 60, height: 60, borderRadius: '50%',
                    border: `1px solid ${c}44`, animation: 'ripple 2s ease-out infinite',
                    pointerEvents: 'none', zIndex: 0,
                  }} />
                )}

                {/* Circle */}
                <div style={{
                  width: 40, height: 40, borderRadius: '50%', flexShrink: 0, position: 'relative', zIndex: 1,
                  border: `2px solid ${completed ? '#10b981' : active ? c : 'rgba(255,255,255,0.09)'}`,
                  background: completed
                    ? 'radial-gradient(circle at 40% 40%, rgba(16,185,129,0.22), rgba(16,185,129,0.04))'
                    : active
                    ? `radial-gradient(circle at 40% 40%, ${c}22, ${c}04)`
                    : 'rgba(255,255,255,0.02)',
                  boxShadow: completed ? '0 0 20px rgba(16,185,129,0.4)' : active ? `0 0 24px ${c}70, 0 0 48px ${c}20` : 'none',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all 0.6s ease',
                }}>
                  {completed ? (
                    <svg width="18" height="18" viewBox="0 0 18 18">
                      <polyline points="3,9 7,13 15,4" fill="none" stroke="#10b981" strokeWidth="2.5"
                        strokeLinecap="round" strokeLinejoin="round"
                        strokeDasharray="22" strokeDashoffset={anim ? 0 : 22}
                        style={{ transition: 'stroke-dashoffset 0.5s ease 0.1s' }} />
                    </svg>
                  ) : active ? (
                    <div style={{
                      width: 9, height: 9, borderRadius: '50%',
                      background: c, boxShadow: `0 0 12px ${c}`,
                      animation: 'statusPulse 1.2s ease-in-out infinite',
                    }} />
                  ) : (
                    <div style={{ width: 5, height: 5, borderRadius: '50%', background: 'rgba(148,163,184,0.18)' }} />
                  )}
                </div>

                {/* Label */}
                <div style={{ textAlign: 'center', width: 72 }}>
                  <div style={{
                    fontSize: 7, letterSpacing: '0.18em', textTransform: 'uppercase',
                    fontFamily: '"Space Mono", monospace',
                    color: completed ? '#10b981' : active ? c : 'rgba(148,163,184,0.3)',
                    marginBottom: 2, transition: 'color 0.4s',
                  }}>P{phase.id}</div>
                  <div style={{
                    fontFamily: '"Bebas Neue", sans-serif', fontSize: 11, letterSpacing: '0.06em',
                    color: completed ? '#e2e8f0' : active ? '#f1f5f9' : 'rgba(148,163,184,0.25)',
                    transition: 'color 0.4s', lineHeight: 1.2,
                  }}>{phase.shortLabel}</div>

                  {/* Status pill */}
                  <div style={{ height: 18, marginTop: 5, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                    {completed && anim ? (
                      <div style={{
                        padding: '1px 6px', borderRadius: 20, fontSize: 7,
                        background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.3)',
                        color: '#10b981', letterSpacing: '0.1em', textTransform: 'uppercase',
                        animation: 'fadeSlideUp 0.4s ease forwards',
                      }}>✓ Done</div>
                    ) : active ? (
                      <div style={{
                        padding: '1px 6px', borderRadius: 20, fontSize: 7,
                        background: `${c}14`, border: `1px solid ${c}40`,
                        color: c, letterSpacing: '0.1em', textTransform: 'uppercase',
                        display: 'flex', alignItems: 'center', gap: 3,
                      }}>
                        <div style={{ width: 3, height: 3, borderRadius: '50%', background: c, animation: 'statusPulse 1.2s ease-in-out infinite' }} />
                        Live
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>

              {/* Connector */}
              {idx < PHASES.length - 1 && (
                <div style={{
                  flex: 1, height: 2, marginTop: 19,
                  background: 'rgba(255,255,255,0.05)', position: 'relative', overflow: 'hidden',
                }}>
                  <div style={{
                    position: 'absolute', top: 0, left: 0, bottom: 0,
                    width: `${lineProgress(idx)}%`,
                    background: `linear-gradient(90deg, ${PHASES[idx].color}, ${PHASES[idx+1].color})`,
                    transition: 'width 1.2s cubic-bezier(0.4,0,0.2,1)',
                    boxShadow: lineProgress(idx) > 0 ? `0 0 6px ${PHASES[idx].color}88` : 'none',
                  }} />
                  {isActive(phase.id) && lineProgress(idx) > 0 && (
                    <div style={{
                      position: 'absolute', top: '50%', transform: 'translateY(-50%)',
                      left: `${Math.max(0, lineProgress(idx) - 8)}%`,
                      width: 5, height: 5, borderRadius: '50%',
                      background: phase.color, boxShadow: `0 0 6px ${phase.color}`,
                      animation: 'statusPulse 1s ease-in-out infinite',
                    }} />
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Completion banner */}
      {isDone && (
        <div style={{
          marginTop: 16, textAlign: 'center',
          animation: 'fadeSlideUp 0.5s ease forwards',
        }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 8,
            padding: '5px 16px', borderRadius: 20,
            background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)',
            fontFamily: '"Bebas Neue", sans-serif', fontSize: 13, letterSpacing: '0.1em', color: '#10b981',
          }}>✓ All Phases Complete — Report Ready</div>
        </div>
      )}
    </div>
  );
}
