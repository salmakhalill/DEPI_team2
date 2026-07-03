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
      if (!animated.has(pid)) setTimeout(() => setAnimated(prev => new Set([...prev, pid])), 200);
    });
  }, [completedPhases]);

  const isDone   = status === 'completed';
  const isActive = (id: number) => currentPhase === id && !isDone;
  const isDoneP  = (id: number) => completedPhases.has(id as ScanPhase) || isDone;

  const lineProgress = (idx: number): number => {
    const from = idx + 1, to = idx + 2;
    if (isDoneP(from) && isDoneP(to)) return 100;
    if (isDoneP(from) && isActive(to)) return 55;
    if (isDoneP(from)) return 25;
    if (isActive(from)) return 8;
    return 0;
  };

  return (
    <div style={{
      background: 'rgba(6,20,41,0.7)',
      border: '1px solid rgba(255,255,255,0.06)',
      borderRadius: 14,
      padding: '0 28px 24px',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Progress bar — top, single color, no gradient rainbow */}
      <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 2, background: 'rgba(255,255,255,0.04)' }}>
        <div style={{
          height: '100%',
          width: `${scanProgress}%`,
          background: isDone ? '#15cc44' : '#1bbbe2',
          transition: 'width 1.2s cubic-bezier(0.4,0,0.2,1)',
          opacity: 0.7,
        }} />
      </div>

      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', paddingTop: 26 }}>
        {PHASES.map((phase, idx) => {
          const active    = isActive(phase.id);
          const completed = isDoneP(phase.id);
          const anim      = animated.has(phase.id) || isDone;

          // Per-phase color — muted versions
          const phaseColors: Record<number, string> = {
            1: '#1bbbe2', 2: '#1bbbe2', 3: '#7028e0',
            4: '#ec9e2a', 5: '#eb3228', 6: '#eb3228',
            7: '#15cc44', 8: '#15cc44',
          };
          const c = phaseColors[phase.id] || '#1bbbe2';

          return (
            <div key={phase.id} style={{ display: 'flex', alignItems: 'flex-start', flex: idx < PHASES.length - 1 ? 1 : 0 }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>

                {/* Ripple — very subtle on active */}
                {active && (
                  <div style={{
                    position: 'absolute', marginTop: -7,
                    width: 52, height: 52, borderRadius: '50%',
                    border: `1px solid ${c}28`,
                    animation: 'ripple 2.5s ease-out infinite',
                    pointerEvents: 'none',
                  }} />
                )}

                {/* Circle */}
                <div style={{
                  width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
                  border: `1.5px solid ${completed ? '#15cc44' : active ? c : 'rgba(255,255,255,0.08)'}`,
                  background: completed
                    ? 'rgba(77,171,138,0.1)'
                    : active
                    ? `rgba(${c === '#1bbbe2' ? '125,211,232' : c === '#7028e0' ? '155,126,200' : c === '#ec9e2a' ? '201,150,74' : '192,80,74'},0.1)`
                    : 'rgba(255,255,255,0.02)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all 0.5s ease', position: 'relative', zIndex: 1,
                  /* No glow on inactive, minimal glow on active */
                  boxShadow: completed ? 'none' : active ? `0 0 12px ${c}30` : 'none',
                }}>
                  {completed ? (
                    <svg width="15" height="15" viewBox="0 0 15 15">
                      <polyline points="2,8 6,12 13,4" fill="none" stroke="#15cc44" strokeWidth="2"
                        strokeLinecap="round" strokeLinejoin="round"
                        strokeDasharray="20" strokeDashoffset={anim ? 0 : 20}
                        style={{ transition: 'stroke-dashoffset 0.45s ease 0.08s' }}/>
                    </svg>
                  ) : active ? (
                    <div style={{
                      width: 7, height: 7, borderRadius: '50%',
                      background: c, opacity: 0.9,
                      animation: 'statusPulse 1.8s ease-in-out infinite',
                    }} />
                  ) : (
                    <div style={{ width: 4, height: 4, borderRadius: '50%', background: 'rgba(139,148,158,0.15)' }} />
                  )}
                </div>

                {/* Labels */}
                <div style={{ textAlign: 'center', width: 68 }}>
                  <div style={{
                    fontSize: 7, letterSpacing: '0.16em', textTransform: 'uppercase',
                    fontFamily: '"Space Mono", monospace',
                    color: completed ? '#15cc44' : active ? c : 'rgba(139,148,158,0.28)',
                    marginBottom: 2, transition: 'color 0.35s',
                  }}>P{phase.id}</div>
                  <div style={{
                    fontFamily: '"Bebas Neue", sans-serif', fontSize: 10, letterSpacing: '0.05em',
                    color: completed ? '#e2ecf7' : active ? '#e6edf3' : 'rgba(139,148,158,0.22)',
                    transition: 'color 0.35s', lineHeight: 1.25,
                  }}>{phase.shortLabel}</div>

                  {/* Status pill */}
                  <div style={{ height: 17, marginTop: 4, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
                    {completed && anim ? (
                      <div style={{
                        padding: '1px 5px', borderRadius: 20, fontSize: 6,
                        background: 'rgba(77,171,138,0.1)', border: '1px solid rgba(77,171,138,0.25)',
                        color: '#15cc44', letterSpacing: '0.1em', textTransform: 'uppercase',
                        animation: 'fadeSlideUp 0.35s ease forwards',
                      }}>✓ Done</div>
                    ) : active ? (
                      <div style={{
                        padding: '1px 5px', borderRadius: 20, fontSize: 6,
                        background: `${c}10`, border: `1px solid ${c}30`,
                        color: c, letterSpacing: '0.1em', textTransform: 'uppercase',
                        display: 'flex', alignItems: 'center', gap: 3,
                      }}>
                        <div style={{ width: 3, height: 3, borderRadius: '50%', background: c, animation: 'statusPulse 1.8s ease-in-out infinite' }} />
                        Live
                      </div>
                    ) : null}
                  </div>
                </div>
              </div>

              {/* Connector */}
              {idx < PHASES.length - 1 && (
                <div style={{
                  flex: 1, height: 1, marginTop: 17,
                  background: 'rgba(255,255,255,0.05)', position: 'relative', overflow: 'hidden',
                }}>
                  <div style={{
                    position: 'absolute', top: 0, left: 0, bottom: 0,
                    width: `${lineProgress(idx)}%`,
                    background: isDoneP(idx + 1) ? '#15cc44' : '#1bbbe2',
                    opacity: 0.45,
                    transition: 'width 1.1s cubic-bezier(0.4,0,0.2,1)',
                  }} />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {isDone && (
        <div style={{ marginTop: 14, textAlign: 'center', animation: 'fadeSlideUp 0.45s ease forwards' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '4px 14px', borderRadius: 20,
            background: 'rgba(77,171,138,0.08)', border: '1px solid rgba(77,171,138,0.2)',
            fontFamily: '"Space Mono", monospace',
            fontSize: 9, letterSpacing: '0.1em', color: '#15cc44',
          }}>✓ All phases complete — report ready</div>
        </div>
      )}
    </div>
  );
}
