import { useNavigate } from 'react-router-dom';
import Background from '../components/Background';
import Navbar from '../components/Navbar';

export default function LandingPage() {
  const navigate = useNavigate();

  return (
    <div style={{ minHeight: '100vh', position: 'relative' }}>
      <Background />
      <Navbar />

      <main style={{
        position: 'relative', zIndex: 1,
        paddingTop: 100,
        paddingBottom: 80,
        maxWidth: 1100,
        margin: '0 auto',
        padding: '100px 32px 80px',
      }}>
        {/* Hero */}
        <div style={{ textAlign: 'center', animation: 'fadeSlideUp 0.8s ease forwards', marginBottom: 80 }}>
          {/* Pill */}
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '4px 14px',
            borderRadius: 100,
            background: 'rgba(34,211,238,0.08)',
            border: '1px solid rgba(34,211,238,0.25)',
            fontSize: 10, letterSpacing: '0.15em',
            color: '#22d3ee', textTransform: 'uppercase',
            marginBottom: 24,
             marginTop: 24,
          }}>
            <div style={{
              width: 5, height: 5, borderRadius: '50%',
             
              background: '#22d3ee', boxShadow: '0 0 6px #22d3ee',
              animation: 'statusPulse 1.2s ease-in-out infinite',
            }} />
            Automated Web Penetration Testing
          </div>

          {/* Headline */}
          <h1 style={{
            fontFamily: '"Michroma", sans-serif',
            letterSpacing: '0.04em',
            lineHeight: 1.02,
            marginBottom: 24,
          }}>
            <span style={{
              background: 'linear-gradient(135deg, #22d3ee 00%, #1d6999 100%)',
              WebkitBackgroundClip: 'text',
              fontWeight: 600,
              fontSize: 'clamp(92px, 8vw, 76px)',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text',
            }}>Find Vulns.</span>
            <br />
            <span style={{ color: 'rgba(148,163,184,0.5)' , fontSize: 'clamp(22px, 8vw, 50px)' }}>Before They Do</span>
          </h1>

          <p style={{
            fontSize: 14,
            color: 'rgba(148,163,184,0.7)',
            lineHeight: 1.8,
            maxWidth: 480,
            margin: '0 auto 36px',
            fontFamily: '"Space Mono", monospace',
          }}>
            SQL injection and XSS vulnerabilities found in minutes.
            Live scan progress. Professional PDF report.
          </p>

          {/* CTA buttons */}
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button
              className="scan-btn"
              onClick={() => navigate('/scan/new')}
              style={{
                padding: '14px 36px',
                borderRadius: 12,
                fontSize: 16,
                cursor: 'pointer',
                border: 'none',
              }}
            >
              Start a Scan →
            </button>
            <a
              href="#how-it-works"
              style={{
                padding: '14px 28px',
                borderRadius: 12,
                fontSize: 12,
                fontFamily: '"Space Mono", monospace',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.1)',
                color: 'rgba(148,163,184,0.7)',
                textDecoration: 'none',
                transition: 'all 0.2s',
                display: 'inline-flex', alignItems: 'center',
              }}
            >
              See how it works ↓
            </a>
          </div>
        </div>

        {/* Mock terminal preview */}
        <div style={{
          maxWidth: 700, margin: '0 auto 80px',
          animation: 'fadeSlideUp 0.9s ease 0.2s forwards',
          opacity: 0,
        }}>
          <div className="glass" style={{ padding: 0, overflow: 'hidden' }}>
            {/* Terminal bar */}
            <div style={{
              padding: '10px 16px',
              background: 'rgba(0,0,0,0.4)',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              display: 'flex', alignItems: 'center', gap: 6,
            }}>
              {['#ef4444','#f59e0b','#10b981'].map((c,i)=>(
                <div key={i} style={{width:10,height:10,borderRadius:'50%',background:c,opacity:0.7}}/>
              ))}
              <span style={{fontSize:10,color:'rgba(148,163,184,0.4)',marginLeft:8,fontFamily:'"Space Mono",monospace'}}>
                nexusflow — live scan
              </span>
            </div>
            {/* Mock log lines */}
            {[
              { c: '#22d3ee',  t: '→', m: '[Spider] Crawling page 12/60: /dashboard/users' },
              { c: '#22d3ee',  t: '→', m: '[Spider] Crawling page 13/60: /api/search?q=test' },
              { c: '#a855f7', t: '⟡', m: '[Extractor] Extracted 4 parameters from /api/search' },
              { c: '#f59e0b', t: '⚡', m: "[Scanner] Testing 'q' with payload: ' OR 1=1--" },
              { c: '#ef4444', t: '☠', m: '[FINDING] SQL Injection confirmed on /api/search — param: q' },
              { c: '#10b981', t: '◈', m: '[Reporter] Generating PDF report...' },
            ].map((l, i) => (
              <div key={i} style={{
                padding: '3px 16px',
                display: 'flex', gap: 10,
                fontFamily: '"Space Mono", monospace', fontSize: 11,
                background: l.t === '☠' ? 'rgba(239,68,68,0.05)' : 'transparent',
                animation: `fadeSlideUp 0.4s ease ${0.5 + i*0.08}s forwards`,
                opacity: 0,
              }}>
                <span style={{ color: l.c }}>{l.t}</span>
                <span style={{ color: l.t === '☠' ? '#fca5a5' : 'rgba(148,163,184,0.8)' }}>{l.m}</span>
              </div>
            ))}
            <div style={{ height: 12 }} />
          </div>
        </div>

        {/* How It Works */}
        <div id="how-it-works" style={{ marginBottom: 80 }}>
          <div style={{ textAlign: 'center', marginBottom: 40 }}>
            <div style={{
              fontSize: 10, color: 'rgba(34,211,238,0.6)',
              letterSpacing: '0.2em', textTransform: 'uppercase', marginBottom: 8,
            }}>— Process —</div>
            <h2 style={{
              fontFamily: '"Bebas Neue", sans-serif',
              fontSize: 36, letterSpacing: '0.06em', color: '#f1f5f9',
            }}>How It Works</h2>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 16 }}>
            {[
              {
                num: '01', color: '#22d3ee',
                title: 'Submit Target',
                desc: 'Enter the URL you want to scan and optional session cookies for authenticated scans.',
                icon: '⬡',
              },
              {
                num: '02', color: '#a855f7',
                title: 'Watch Live',
                desc: 'Monitor the crawler and scanner in real time. See every endpoint, payload, and finding as it happens.',
                icon: '⚡',
              },
              {
                num: '03', color: '#10b981',
                title: 'Download Report',
                desc: 'Get a professional PDF with findings, CVSS scores, affected endpoints, and remediation advice.',
                icon: '◈',
              },
            ].map(step => (
              <div
                key={step.num}
                className="glass-card"
                style={{ padding: 24, position: 'relative', overflow: 'hidden' }}
              >
                <div style={{
                  position: 'absolute', top: -10, right: -5,
                  fontFamily: '"Bebas Neue", sans-serif',
                  fontSize: 72, color: `${step.color}08`,
                  letterSpacing: '0.06em',
                }}>{step.num}</div>

                <div style={{
                  width: 36, height: 36, borderRadius: '50%',
                  border: `1.5px solid ${step.color}`,
                  background: `radial-gradient(circle, ${step.color}22, transparent)`,
                  boxShadow: `0 0 12px ${step.color}44`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 14, color: step.color, marginBottom: 14,
                }}>{step.icon}</div>

                <div style={{
                  fontFamily: '"Bebas Neue", sans-serif',
                  fontSize: 20, letterSpacing: '0.06em', color: '#f1f5f9', marginBottom: 8,
                }}>{step.title}</div>
                <p style={{
                  fontSize: 11, color: 'rgba(148,163,184,0.65)',
                  lineHeight: 1.8, fontFamily: '"Space Mono", monospace',
                }}>{step.desc}</p>
              </div>
            ))}
          </div>
        </div>

        
      </main>

      {/* Footer */}
      <footer style={{
        position: 'relative', zIndex: 1,
        textAlign: 'center',
        padding: '24px 32px',
        borderTop: '1px solid rgba(255,255,255,0.05)',
        color: 'rgba(148,163,184,0.35)',
        fontSize: 10,
        fontFamily: '"Space Mono", monospace',
        letterSpacing: '0.08em',
      }}>
        <span style={{
          fontFamily: '"Bebas Neue", sans-serif',
          fontSize: 14, letterSpacing: '0.1em',
          color: 'rgba(34,211,238,0.4)', marginRight: 8,
        }}>NexusFlow</span>
        · For authorized security testing only. Unauthorized scanning is illegal.
      </footer>
    </div>
  );
}
