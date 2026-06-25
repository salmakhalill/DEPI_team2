import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import Background from '../components/Background';
import Navbar from '../components/Navbar';
import { getReportUrl } from '../api/client';

export default function ReportPage() {
  const { scanId } = useParams<{ scanId: string }>();
  const navigate   = useNavigate();
  const [pdfError, setPdfError] = useState(false);
  const [loading,  setLoading]  = useState(true);

  useEffect(() => { if (!scanId) navigate('/scan/new'); }, [scanId]);

  const reportUrl = scanId ? getReportUrl(scanId) : '';

  const summaryStats = [
    { label: 'Scan ID', value: (scanId?.slice(0, 14) || '') + '…', color: '#22d3ee' },
    { label: 'Status',  value: 'Completed',                          color: '#10b981' },
    { label: 'Report',  value: 'PDF Ready',                          color: '#a855f7' },
  ];

  return (
    <div style={{ minHeight: '100vh', position: 'relative' }}>
      <Background />
      <Navbar />

      <main style={{
        position: 'relative', zIndex: 1,
        padding: '80px 24px 60px',
        maxWidth: 1280, margin: '0 auto',
      }}>

        {/* ── Header ─────────────────────────────────────────────────── */}
        <div style={{ marginBottom: 28, animation: 'fadeSlideUp 0.5s ease forwards' }}>
          <button
            onClick={() => navigate(-1)}
            style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'rgba(148,163,184,0.5)', fontSize: 11,
              fontFamily: '"Space Mono", monospace', letterSpacing: '0.08em',
              marginBottom: 14, display: 'flex', alignItems: 'center', gap: 6,
              transition: 'color 0.2s', padding: 0,
            }}
            onMouseEnter={e => (e.currentTarget.style.color = '#22d3ee')}
            onMouseLeave={e => (e.currentTarget.style.color = 'rgba(148,163,184,0.5)')}
          >← Back to scan</button>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <div style={{
                fontSize: 9, color: 'rgba(34,211,238,0.5)',
                letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 4,
              }}>Scan Report</div>
              <h1 style={{
                fontFamily: '"Bebas Neue", sans-serif', fontSize: 36, letterSpacing: '0.06em', margin: 0,
                background: 'linear-gradient(135deg, #f1f5f9, #10b981)',
                WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
              }}>Security Report</h1>
            </div>

            <div style={{ display: 'flex', gap: 10 }}>
              <a
                href={reportUrl}
                download
                style={{
                  padding: '10px 22px', borderRadius: 10,
                  fontFamily: '"Bebas Neue", sans-serif', fontSize: 16, letterSpacing: '0.1em',
                  background: 'rgba(16,185,129,0.12)', border: '1px solid rgba(16,185,129,0.4)',
                  color: '#10b981', textDecoration: 'none',
                  display: 'inline-flex', alignItems: 'center', gap: 6, transition: 'all 0.2s',
                }}
                onMouseEnter={e => {
                  (e.currentTarget as HTMLElement).style.background = 'rgba(16,185,129,0.22)';
                  (e.currentTarget as HTMLElement).style.boxShadow  = '0 0 20px rgba(16,185,129,0.25)';
                }}
                onMouseLeave={e => {
                  (e.currentTarget as HTMLElement).style.background = 'rgba(16,185,129,0.12)';
                  (e.currentTarget as HTMLElement).style.boxShadow  = 'none';
                }}
              >⬇ Download PDF</a>

              <button onClick={() => navigate('/scan/new')} style={{
                padding: '10px 22px', borderRadius: 10,
                fontFamily: '"Bebas Neue", sans-serif', fontSize: 16, letterSpacing: '0.1em',
                background: 'rgba(34,211,238,0.06)', border: '1px solid rgba(34,211,238,0.25)',
                color: '#22d3ee', cursor: 'pointer', transition: 'all 0.2s',
              }}>New Scan →</button>
            </div>
          </div>
        </div>

        {/* ── Summary cards ───────────────────────────────────────────── */}
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12,
          marginBottom: 24,
          animation: 'fadeSlideUp 0.5s ease 0.1s forwards', opacity: 0,
        }}>
          {summaryStats.map(s => (
            <div key={s.label} className="glass-card" style={{ padding: '16px 20px' }}>
              <div style={{
                fontSize: 8, color: 'rgba(148,163,184,0.4)',
                letterSpacing: '0.15em', textTransform: 'uppercase', marginBottom: 6,
              }}>{s.label}</div>
              <div style={{
                fontFamily: '"Bebas Neue", sans-serif', fontSize: 18, letterSpacing: '0.06em',
                color: s.color, textShadow: `0 0 10px ${s.color}44`,
              }}>{s.value}</div>
            </div>
          ))}
        </div>

        {/* ── Report viewer ────────────────────────────────────────────── */}
        <div style={{ animation: 'fadeSlideUp 0.6s ease 0.2s forwards', opacity: 0 }}>
          {/* Section label */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <span style={{
              fontFamily: '"Bebas Neue", sans-serif', fontSize: 14, letterSpacing: '0.1em', color: '#a855f7',
            }}>◈ Full Report</span>
            <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.06)' }} />
            {!loading && !pdfError && (
              <span style={{
                fontSize: 8, color: 'rgba(16,185,129,0.6)', letterSpacing: '0.12em',
                fontFamily: '"Space Mono", monospace', textTransform: 'uppercase',
              }}>✓ Loaded</span>
            )}
          </div>

          {/* Wrapper — this is what contains the spinner + iframe */}
          <div
            className="glass"
            style={{
              padding: 0,
              overflow: 'hidden',
              /* ← key fix: explicit height + position:relative so the
                 absolutely-positioned overlay fills exactly this box */
              position: 'relative',
              minHeight: 700,
            }}
          >

            {/* ── Loading overlay ── */}
            {loading && !pdfError && (
              <div style={{
                position: 'absolute',
                inset: 0,                        /* fills the parent exactly */
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',        /* true centre of the card */
                gap: 14,
                background: 'rgba(2,8,23,0.85)',
                zIndex: 10,
                borderRadius: 'inherit',
              }}>
                {/* ── Spinner: spin-in-place, never moves ── */}
                <div style={{
                  width: 40,
                  height: 40,
                  borderRadius: '50%',
                  border: '2.5px solid rgba(168,85,247,0.2)',
                  borderTopColor: '#a855f7',
                  /* use 'spin' not 'scanLine' — scanLine translates Y */
                  animation: 'spinLoader 0.85s linear infinite',
                  flexShrink: 0,
                }} />
                <span style={{
                  fontSize: 10,
                  color: 'rgba(148,163,184,0.5)',
                  fontFamily: '"Space Mono", monospace',
                  letterSpacing: '0.14em',
                  textTransform: 'uppercase',
                }}>Loading report…</span>
              </div>
            )}

            {/* ── Error state ── */}
            {pdfError ? (
              <div style={{
                display: 'flex', flexDirection: 'column', alignItems: 'center',
                justifyContent: 'center', gap: 14,
                padding: '60px 24px', textAlign: 'center',
              }}>
                <div style={{ fontSize: 32, color: 'rgba(245,158,11,0.6)' }}>⚠</div>
                <div style={{
                  fontFamily: '"Bebas Neue", sans-serif', fontSize: 22, letterSpacing: '0.06em', color: '#f1f5f9',
                }}>Report Not Ready Yet</div>
                <p style={{
                  fontSize: 11, color: 'rgba(148,163,184,0.5)',
                  fontFamily: '"Space Mono", monospace', lineHeight: 1.8, maxWidth: 380,
                }}>
                  The scan may still be running or the PDF is still being generated.
                  Please wait a moment and try again.
                </p>
                <div style={{ display: 'flex', gap: 10 }}>
                  <button onClick={() => { setPdfError(false); setLoading(true); }} style={{
                    padding: '9px 22px', borderRadius: 8,
                    fontFamily: '"Bebas Neue", sans-serif', fontSize: 14, letterSpacing: '0.08em',
                    background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.3)',
                    color: '#f59e0b', cursor: 'pointer',
                  }}>↺ Retry</button>
                  <button onClick={() => navigate(-1)} style={{
                    padding: '9px 22px', borderRadius: 8,
                    fontFamily: '"Bebas Neue", sans-serif', fontSize: 14, letterSpacing: '0.08em',
                    background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.1)',
                    color: 'rgba(148,163,184,0.6)', cursor: 'pointer',
                  }}>← Back to Scan</button>
                </div>
              </div>
            ) : (
              /* ── PDF / HTML iframe ── */
              <iframe
                key={reportUrl}           /* remount when URL changes (Retry) */
                src={reportUrl}
                style={{
                  display: 'block',
                  width: '100%',
                  height: '85vh',         /* tall enough to read the report */
                  minHeight: 700,
                  border: 'none',
                  borderRadius: 'inherit',
                  /* show below the loading overlay while it fades in */
                  opacity: loading ? 0 : 1,
                  transition: 'opacity 0.4s ease',
                }}
                title="Scan Report"
                onLoad={() => setLoading(false)}
                onError={() => { setPdfError(true); setLoading(false); }}
              />
            )}
          </div>
        </div>

        {/* Footer */}
        <div style={{
          marginTop: 18, textAlign: 'center',
          fontSize: 9, color: 'rgba(148,163,184,0.22)',
          fontFamily: '"Space Mono", monospace', letterSpacing: '0.08em',
        }}>
          Report generated by NexusFlow · For authorized security testing only
        </div>
      </main>

      {/* ── spinLoader keyframe injected inline ────────────────────────
          Keeps it isolated from the scanLine animation used elsewhere   */}
      <style>{`
        @keyframes spinLoader {
          from { transform: rotate(0deg);   }
          to   { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
