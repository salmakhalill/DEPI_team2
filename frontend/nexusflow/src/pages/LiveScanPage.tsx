import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Background      from '../components/Background';
import Navbar          from '../components/Navbar';
import PhaseTimeline   from '../components/PhaseTimeline';
import ScanAnimations  from '../components/ScanAnimations';
import ActivityFeed    from '../components/ActivityFeed';
import MetricsBar      from '../components/MetricsBar';
import FindingsTable   from '../components/FindingsTable';
import AttackSurface   from '../components/AttackSurface';
import { useScanWebSocket } from '../hooks/useScanWebSocket';
import { getReportUrl } from '../api/client';

function fmtTime(s: number) {
  return `${Math.floor(s/60)}:${String(s%60).padStart(2,'0')}`;
}

export default function LiveScanPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate   = useNavigate();
  const { state, reconnect } = useScanWebSocket(scanId);
  const [activeTab, setActiveTab] = useState<'findings' | 'surface' | 'activity'>('activity');

  useEffect(() => { if (!scanId) navigate('/scan/new'); }, [scanId]);

  // Auto-switch to findings tab when first vuln arrives
  useEffect(() => {
    if (state.findings.length === 1) setActiveTab('findings');
  }, [state.findings.length]);

  const { status, currentPhase, completedPhases, connected, elapsedSec,
          scanProgress, endpoints, findings, activityFeed, reportReady } = state;

  const isDone   = status === 'completed';
  const isFailed = status === 'failed';

  const statusCfg = isDone   ? { color: '#10b981', border: 'rgba(16,185,129,0.4)', bg: 'rgba(16,185,129,0.1)', label: '✓ Complete' }
                  : isFailed ? { color: '#ef4444', border: 'rgba(239,68,68,0.4)',  bg: 'rgba(239,68,68,0.1)',  label: '✗ Failed'   }
                  : connected ? { color: '#22d3ee', border: 'rgba(34,211,238,0.3)', bg: 'rgba(34,211,238,0.08)', label: '⬡ Running' }
                  :             { color: '#f59e0b', border: 'rgba(245,158,11,0.3)', bg: 'rgba(245,158,11,0.08)', label: '… Connecting' };

  const tabs = [
    { id: 'activity' as const,  label: 'Activity',  count: activityFeed.length, color: '#a855f7' },
    { id: 'findings' as const,  label: 'Findings',  count: findings.length,     color: '#ef4444' },
    { id: 'surface'  as const,  label: 'Attack Surface', count: endpoints.length, color: '#22d3ee' },
  ];

  return (
    <div style={{ minHeight: '100vh', position: 'relative' }}>
      <Background isScanning={status === 'running'} />
      <Navbar />

      <main style={{ position: 'relative', zIndex: 1, padding: '74px 24px 60px', maxWidth: 1360, margin: '0 auto' }}>

        {/* ── Page header ─────────────────────────────────────────────── */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          marginBottom: 18, animation: 'fadeSlideUp 0.4s ease forwards',
        }}>
          <div>
            <div style={{
              fontSize: 8, color: 'rgba(34,211,238,0.45)',
              letterSpacing: '0.18em', textTransform: 'uppercase',
              fontFamily: '"Space Mono",monospace', marginBottom: 3,
            }}>Scan ID: {scanId}</div>
            <h1 style={{
              fontFamily: '"Michroma", sans-serif', fontSize: 30, letterSpacing: '0.06em', margin: 0,
              background: 'linear-gradient(135deg, #1badc3, #1badc3)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
            }}>Live Scan Dashboard</h1>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {/* Findings counter */}
            {findings.length > 0 && (
              <div style={{
                padding: '6px 14px', borderRadius: 20,
                background: 'rgba(239,68,68,0.12)', border: '1px solid rgba(239,68,68,0.4)',
                display: 'flex', alignItems: 'center', gap: 6,
                animation: 'fadeSlideUp 0.3s ease forwards',
              }}>
                <div style={{
                  width: 5, height: 5, borderRadius: '50%', background: '#ef4444',
                  boxShadow: '0 0 8px #ef4444', animation: 'statusPulse 1.2s ease-in-out infinite',
                }} />
                <span style={{ fontFamily: '"Bebas Neue",sans-serif', fontSize: 16, color: '#ef4444', letterSpacing: '0.06em' }}>
                  {findings.length} VULN{findings.length !== 1 ? 'S' : ''}
                </span>
              </div>
            )}

            {/* Timer */}
            {status === 'running' && (
              <div style={{
                fontSize: 12, color: 'rgba(148,163,184,0.5)',
                fontFamily: '"Space Mono",monospace', letterSpacing: '0.1em',
                background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
                padding: '5px 12px', borderRadius: 8,
              }}>{fmtTime(elapsedSec)}</div>
            )}

            {/* Status badge */}
            <div style={{
              padding: '6px 14px', borderRadius: 20, fontSize: 9,
              fontFamily: '"Space Mono",monospace', letterSpacing: '0.12em',
              background: statusCfg.bg, border: `1px solid ${statusCfg.border}`, color: statusCfg.color,
            }}>{statusCfg.label}</div>
          </div>
        </div>

        {/* Reconnect banner */}
        {!connected && status !== 'completed' && (
          <div style={{
            padding: '10px 16px', borderRadius: 10, marginBottom: 14,
            background: 'rgba(239,68,68,0.07)', border: '1px solid rgba(239,68,68,0.22)',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <span style={{ fontSize: 10, color: 'rgba(239,68,68,0.8)', fontFamily: '"Space Mono",monospace' }}>
              ✗ Connection lost {status === 'connecting' ? '— Retrying...' : ''}
            </span>
            {status !== 'connecting' && (
              <button onClick={reconnect} style={{
                padding: '4px 14px', borderRadius: 6, fontSize: 9, cursor: 'pointer',
                background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.4)',
                color: '#fca5a5', fontFamily: '"Space Mono",monospace',
              }}>↺ Reconnect</button>
            )}
          </div>
        )}

        {/* ── Timeline ────────────────────────────────────────────────── */}
        <div style={{ marginBottom: 14, animation: 'fadeSlideUp 0.5s ease 0.05s forwards', opacity: 0 }}>
          <PhaseTimeline
            currentPhase={currentPhase}
            completedPhases={completedPhases}
            status={status}
            scanProgress={scanProgress}
          />
        </div>

        {/* ── Metrics bar ─────────────────────────────────────────────── */}
        <div style={{ animation: 'fadeSlideUp 0.5s ease 0.1s forwards', opacity: 0 }}>
          <MetricsBar findings={findings} endpoints={endpoints} scanProgress={scanProgress} status={status} />
        </div>

        {/* ── Main 2-col grid: viz + tabs ─────────────────────────────── */}
        <div style={{
          display: 'grid', gridTemplateColumns: '340px 1fr', gap: 14,
          marginBottom: 14, animation: 'fadeSlideUp 0.5s ease 0.15s forwards', opacity: 0,
        }}>
          {/* Left: network visualisation */}
          <ScanAnimations endpoints={endpoints} findings={findings} phase={currentPhase} status={status} />

          {/* Right: tabbed panel */}
          <div style={{ display: 'flex', flexDirection: 'column', minHeight: 320 }}>
            {/* Tab bar */}
            <div style={{
              display: 'flex', gap: 4, marginBottom: 10,
              background: 'rgba(255,255,255,0.02)',
              border: '1px solid rgba(255,255,255,0.06)',
              borderRadius: 10, padding: 4,
            }}>
              {tabs.map(tab => (
                <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
                  flex: 1, padding: '7px 10px', borderRadius: 7, cursor: 'pointer',
                  border: 'none', transition: 'all 0.2s',
                  background: activeTab === tab.id ? `${tab.color}15` : 'transparent',
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                }}>
                  <span style={{
                    fontFamily: '"Bebas Neue",sans-serif', fontSize: 12, letterSpacing: '0.1em',
                    color: activeTab === tab.id ? tab.color : 'rgba(148,163,184,0.4)',
                    transition: 'color 0.2s',
                  }}>{tab.label}</span>
                  {tab.count > 0 && (
                    <span style={{
                      padding: '1px 6px', borderRadius: 20, fontSize: 8,
                      background: `${tab.color}20`, color: tab.color, letterSpacing: '0.06em',
                    }}>{tab.count}</span>
                  )}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div style={{ flex: 1 }}>
              {activeTab === 'activity' && <ActivityFeed events={activityFeed} />}
              {activeTab === 'surface'  && <AttackSurface endpoints={endpoints} />}
              {activeTab === 'findings' && (
                <div style={{
                  background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(255,255,255,0.07)',
                  borderRadius: 16, padding: '14px', height: '100%', overflowY: 'auto',
                }}>
                  <FindingsTable findings={findings} />
                </div>
              )}
            </div>
          </div>
        </div>

        {/* ── Full findings table (always visible) ─────────────────────── */}
        {findings.length > 0 && (
          <div style={{ marginBottom: 14, animation: 'fadeSlideUp 0.4s ease forwards' }}>
            <FindingsTable findings={findings} />
          </div>
        )}

        {/* ── Completion card ───────────────────────────────────────────── */}
        {isDone && (
          <div style={{
            padding: '28px 32px',
            background: 'rgba(16,185,129,0.05)',
            border: '1px solid rgba(16,185,129,0.25)',
            borderRadius: 16,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16,
            animation: 'fadeSlideUp 0.5s cubic-bezier(0.34,1.56,0.64,1) forwards',
          }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 5 }}>
                <svg width="22" height="22" viewBox="0 0 22 22">
                  <circle cx="11" cy="11" r="10" fill="none" stroke="#10b981" strokeWidth="1.5"/>
                  <polyline points="6,11 9,14 16,7" fill="none" stroke="#10b981" strokeWidth="2.2"
                    strokeLinecap="round" strokeLinejoin="round" strokeDasharray="18" strokeDashoffset="0"
                    style={{ animation: 'checkmarkDraw 0.5s ease forwards' }}/>
                </svg>
                <span style={{ fontFamily: '"Bebas Neue",sans-serif', fontSize: 24, letterSpacing: '0.06em', color: '#10b981' }}>
                  Scan Complete
                </span>
              </div>
              <p style={{ fontSize: 11, color: 'rgba(148,163,184,0.6)', fontFamily: '"Space Mono",monospace', lineHeight: 1.7 }}>
                {findings.length} vulnerabilit{findings.length !== 1 ? 'ies' : 'y'} found across {endpoints.length} endpoints.
                Total scan time: {fmtTime(elapsedSec)}.
              </p>
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <button onClick={() => navigate(`/scan/${scanId}/report`)} style={{
                padding: '12px 24px', borderRadius: 10,
                fontFamily: '"Bebas Neue",sans-serif', fontSize: 16, letterSpacing: '0.1em',
                background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(16,185,129,0.5)',
                color: '#10b981', cursor: 'pointer', transition: 'all 0.2s',
              }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow = '0 0 20px rgba(16,185,129,0.3)'; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow = 'none'; }}
              >View Full Report →</button>
              <a href={getReportUrl(scanId!)} target="_blank" rel="noreferrer" style={{
                padding: '12px 24px', borderRadius: 10,
                fontFamily: '"Bebas Neue",sans-serif', fontSize: 16, letterSpacing: '0.1em',
                background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.3)',
                color: '#22d3ee', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 6,
              }}>⬇ Download PDF</a>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
