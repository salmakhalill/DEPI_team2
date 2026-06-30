import { useEffect, useRef, useState } from 'react';
import type { Endpoint, Finding } from '../types/scan';

interface Props {
  endpoints: Endpoint[];
  findings: Finding[];
  phase: number;
  status: string;
}

interface Particle { id: number; x: number; y: number; tx: number; ty: number; color: string; t: number; label: string; }
let _pid = 0;

const PHASE_COLOR: Record<number, string> = {1:'#22d3ee',2:'#06b6d4',3:'#a855f7',4:'#f59e0b',5:'#f97316',6:'#ef4444',7:'#10b981',8:'#10b981'};
const PHASE_LABEL: Record<number, string> = {1:'TARGET SUBMITTED',2:'SPIDER CRAWLING',3:'ATTACK SURFACE',4:'SCANNING VULNS',5:'EXPLOITING',6:'PAYLOAD GEN',7:'REPORTING',8:'COMPLETE'};

// Layout endpoints in a circle around center
function placeNode(i: number, total: number, cx: number, cy: number, r: number) {
  const angle = (i / Math.max(total, 1)) * Math.PI * 2 - Math.PI / 2;
  return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
}

export default function ScanAnimations({ endpoints, findings, phase, status }: Props) {
  const [particles, setParticles] = useState<Particle[]>([]);
  const animRef = useRef<number>(0);
  const prevCount = useRef(0);
  const color = PHASE_COLOR[phase] || '#22d3ee';

  // spawn particles when new findings arrive
  useEffect(() => {
    if (findings.length > prevCount.current) {
      const newest = findings[findings.length - 1];
      for (let i = 0; i < 3; i++) {
        setParticles(prev => [...prev.slice(-14), {
          id: _pid++,
          x: 15 + Math.random() * 20, y: 20 + Math.random() * 60,
          tx: 65 + Math.random() * 20, ty: 20 + Math.random() * 60,
          color: '#ef4444', t: 0,
          label: newest.param || 'param',
        }]);
      }
    }
    prevCount.current = findings.length;
  }, [findings.length]);

  // animate particles
  useEffect(() => {
    const tick = () => {
      setParticles(prev => prev.map(p => ({ ...p, t: p.t + 0.015 })).filter(p => p.t < 1.2));
      animRef.current = requestAnimationFrame(tick);
    };
    animRef.current = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animRef.current);
  }, []);

  const W = 100, H = 100;
  const cx = 12, cy = 50;
  const nodeRadius = 30;
  const visibleEndpoints = endpoints.slice(0, 12);

  const vulnPaths = new Set(findings.map(f => f.endpoint));

  return (
    <div style={{
      background: 'rgba(0,0,0,0.45)',
      border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 16, padding: '16px',
      display: 'flex', flexDirection: 'column', gap: 10,
      height: '100%', minHeight: 320,
      position: 'relative', overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
          <div style={{
            width: 6, height: 6, borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}`,
            animation: status === 'completed' ? 'none' : 'statusPulse 1.2s ease-in-out infinite',
          }} />
          <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 11, letterSpacing: '0.15em', color }}>
            {PHASE_LABEL[phase] || 'SCANNING'}
          </span>
        </div>
        <span style={{ fontSize: 8, color: 'rgba(148,163,184,0.35)', letterSpacing: '0.1em', fontFamily: '"Space Mono",monospace' }}>
          NETWORK MAP
        </span>
      </div>

      {/* SVG Network */}
      <div style={{ flex: 1, position: 'relative', borderRadius: 10, background: 'rgba(2,8,23,0.65)', border: '1px solid rgba(255,255,255,0.05)', overflow: 'hidden' }}>
        {/* grid */}
        <div style={{
          position: 'absolute', inset: 0,
          backgroundImage: 'linear-gradient(rgba(34,211,238,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(34,211,238,0.025) 1px, transparent 1px)',
          backgroundSize: '18px 18px',
        }} />

        <svg viewBox="0 0 100 100" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} preserveAspectRatio="xMidYMid meet">
          {/* Connection lines */}
          {visibleEndpoints.map((ep, i) => {
            const pos = placeNode(i, visibleEndpoints.length, 72, 50, nodeRadius);
            const isVuln = vulnPaths.has(ep.path);
            return (
              <line key={`l${ep.id}`}
                x1={cx} y1={cy} x2={pos.x} y2={pos.y}
                stroke={isVuln ? '#ef4444' : ep.scanned ? '#a855f7' : '#22d3ee'}
                strokeWidth={isVuln ? 0.5 : 0.3}
                strokeOpacity={isVuln ? 0.4 : 0.18}
                strokeDasharray={isVuln ? 'none' : '2 4'}
              />
            );
          })}

          {/* Particle paths */}
          {particles.map(p => {
            const t2 = Math.min(p.t, 1);
            const e  = t2 < 0.5 ? 2*t2*t2 : -1+(4-2*t2)*t2;
            const px = p.x + (p.tx - p.x) * e;
            const py = p.y + (p.ty - p.y) * e;
            const alpha = p.t < 0.7 ? 1 : 1 - (p.t - 0.7) / 0.5;
            return (
              <g key={p.id} opacity={alpha}>
                <circle cx={px} cy={py} r={1.2} fill={p.color} />
                <circle cx={px} cy={py} r={2.5} fill={p.color} opacity={0.25} />
              </g>
            );
          })}

          {/* Central target node */}
          <circle cx={cx} cy={cy} r={4} fill="rgba(34,211,238,0.15)" stroke="#22d3ee" strokeWidth={0.8} />
          <circle cx={cx} cy={cy} r={1.5} fill="#22d3ee" />

          {/* Endpoint nodes */}
          {visibleEndpoints.map((ep, i) => {
            const pos    = placeNode(i, visibleEndpoints.length, 72, 50, nodeRadius);
            const isVuln = vulnPaths.has(ep.path);
            const nc     = isVuln ? '#ef4444' : ep.scanned ? '#a855f7' : '#22d3ee';
            return (
              <g key={ep.id}>
                <circle cx={pos.x} cy={pos.y} r={3.5} fill={`${nc}18`} stroke={nc} strokeWidth={0.7} />
                <circle cx={pos.x} cy={pos.y} r={1} fill={nc} />
                {isVuln && <circle cx={pos.x} cy={pos.y} r={5.5} fill="none" stroke={nc} strokeWidth={0.4} opacity={0.5} />}
                <text x={pos.x} y={pos.y + 7} textAnchor="middle" fontSize="3.5" fill={`${nc}bb`} fontFamily="monospace">
                  {ep.path.length > 10 ? ep.path.slice(0, 9) + '…' : ep.path}
                </text>
              </g>
            );
          })}

          {/* Empty state spinner */}
          {visibleEndpoints.length === 0 && (
            <circle cx="50" cy="50" r="8" fill="none" stroke="rgba(34,211,238,0.3)" strokeWidth="1"
              strokeDasharray="15 35" style={{ transformOrigin: '50px 50px', animation: 'scanLine 1.2s linear infinite' }} />
          )}
        </svg>

        {endpoints.length === 0 && (
          <div style={{
            position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexDirection: 'column', gap: 8,
          }}>
            <span style={{ fontSize: 8, color: 'rgba(148,163,184,0.35)', letterSpacing: '0.12em' }}>AWAITING SPIDER</span>
          </div>
        )}
      </div>

      {/* Stats */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6 }}>
        {[
          { label: 'Endpoints', value: endpoints.length, color: '#22d3ee' },
          { label: 'Scanned',   value: endpoints.filter(e=>e.scanned).length, color: '#a855f7' },
          { label: 'Vulnerable', value: findings.length, color: '#ef4444' },
        ].map(s => (
          <div key={s.label} style={{
            background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.05)',
            borderRadius: 8, padding: '7px 10px', textAlign: 'center',
          }}>
            <div style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 20, color: s.color, lineHeight: 1, textShadow: `0 0 8px ${s.color}55` }}>
              {s.value}
            </div>
            <div style={{ fontSize: 7, color: 'rgba(148,163,184,0.45)', letterSpacing: '0.1em', textTransform: 'uppercase', marginTop: 2 }}>
              {s.label}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
