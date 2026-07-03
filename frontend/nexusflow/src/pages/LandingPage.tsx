import { useNavigate } from 'react-router-dom';
import Background from '../components/Background';
import Navbar from '../components/Navbar';

export default function LandingPage() {
  const navigate = useNavigate();

  return (
    <div style={{ minHeight: '100vh', position: 'relative' }}>
      <Background />
      <Navbar />

      <main style={{ position: 'relative', zIndex: 1, maxWidth: 1100, margin: '0 auto', padding: '100px 32px 80px' }}>

        {/* Hero */}
        <div style={{ textAlign: 'center', marginBottom: 80, animation: 'fadeSlideUp 0.7s ease forwards' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '3px 12px', borderRadius: 100,
            background: 'rgba(125,211,232,0.06)', border: '1px solid rgba(125,211,232,0.18)',
            fontSize: 9, letterSpacing: '0.16em', color: 'rgba(125,211,232,0.7)',
            textTransform: 'uppercase', marginBottom: 28,
          }}>
            <div style={{ width: 4, height: 4, borderRadius: '50%', background: '#7dd3e8', opacity: 0.7, animation: 'statusPulse 2.5s ease-in-out infinite' }} />
            Automated Web Penetration Testing
          </div>

          <h1 style={{
            fontFamily: '"Bebas Neue", sans-serif',
            fontSize: 'clamp(88px, 7vw, 106px)',
            letterSpacing: '0.04em', lineHeight: 0.96,
            marginBottom: 22,
          }}>
            <span style={{ color: '#e6edf3' }}>Find Vulns.</span>
            <br />
            <span style={{ color: 'rgba(139,148,158,0.35)' }}>Before They Do</span>
          </h1>

          <p style={{
            fontSize: 13, color: 'rgba(139,148,158,0.6)', lineHeight: 1.9,
            maxWidth: 440, margin: '0 auto 32px',
            fontFamily: '"Space Mono", monospace',
          }}>
            SQL injection and XSS vulnerabilities detected in minutes.
            Live scan progress. Professional PDF report.
          </p>

          <div style={{ display: 'flex', gap: 10, justifyContent: 'center', flexWrap: 'wrap' }}>
            <button className="scan-btn" onClick={() => navigate('/scan/new')} style={{
              padding: '13px 32px', borderRadius: 10, fontSize: 15, cursor: 'pointer', border: 'none',
            }}>Start a Scan →</button>
            <a href="#how-it-works" style={{
              padding: '13px 24px', borderRadius: 10, fontSize: 11,
              fontFamily: '"Space Mono", monospace',
              background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.07)',
              color: 'rgba(139,148,158,0.55)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center',
              transition: 'border-color 0.2s, color 0.2s',
            }}>How it works ↓</a>
          </div>
        </div>

        {/* Mock terminal */}
        <div style={{ maxWidth: 680, margin: '0 auto 80px', animation: 'fadeSlideUp 0.8s ease 0.15s forwards', opacity: 0 }}>
          <div className="glass" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{
              padding: '9px 14px', background: 'rgba(13,17,23,0.6)',
              borderBottom: '1px solid rgba(255,255,255,0.05)',
              display: 'flex', alignItems: 'center', gap: 5,
            }}>
              {['rgba(192,80,74,0.6)','rgba(201,150,74,0.6)','rgba(77,171,138,0.6)'].map((c, i) => (
                <div key={i} style={{ width: 9, height: 9, borderRadius: '50%', background: c }} />
              ))}
              <span style={{ fontSize: 9, color: 'rgba(139,148,158,0.35)', marginLeft: 8, fontFamily: '"Space Mono",monospace' }}>
                nexusflow — live scan
              </span>
            </div>
            {[
              { c: '#7dd3e8', t: '→', m: '[Spider] Crawling: http://127.0.0.1:5004/dashboard' },
              { c: '#7dd3e8', t: '→', m: '[Spider] Crawling: http://127.0.0.1:5004/login' },
              { c: '#9b7ec8', t: '⟡', m: '[+] Attack Surface Extracted: 7 unique endpoints' },
              { c: '#c9964a', t: '⚡', m: "[SQLi Scanner] Assessing attack surface across 7 targets..." },
              { c: '#c0504a', t: '☠', m: "[!] SQL Injection Confirmed! Target: /login | Param: 'username'" },
              { c: '#4dab8a', t: '◈', m: '[Reporter] Generating PDF report...' },
            ].map((l, i) => (
              <div key={i} style={{
                padding: '3px 14px', display: 'flex', gap: 10,
                fontFamily: '"Space Mono", monospace', fontSize: 10,
                background: l.t === '☠' ? 'rgba(192,80,74,0.04)' : 'transparent',
                animation: `fadeSlideUp 0.4s ease ${0.4 + i * 0.07}s forwards`, opacity: 0,
              }}>
                <span style={{ color: l.c, opacity: 0.8 }}>{l.t}</span>
                <span style={{ color: l.t === '☠' ? 'rgba(192,80,74,0.85)' : 'rgba(139,148,158,0.65)' }}>{l.m}</span>
              </div>
            ))}
            <div style={{ height: 10 }} />
          </div>
        </div>

        {/* How it works */}
        <div id="how-it-works" style={{ marginBottom: 72 }}>
          <div style={{ textAlign: 'center', marginBottom: 36 }}>
            <div style={{ fontSize: 8, color: 'rgba(125,211,232,0.45)', letterSpacing: '0.2em', textTransform: 'uppercase', marginBottom: 8 }}>Process</div>
            <h2 style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 30, letterSpacing: '0.05em', color: '#c9d1d9' }}>How It Works</h2>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 12 }}>
            {[
              { num: '01', color: '#7dd3e8', title: 'Submit Target',    desc: 'Enter the URL and optional session cookies for an authenticated scan.', icon: '⬡' },
              { num: '02', color: '#9b7ec8', title: 'Watch Live',       desc: 'Monitor the 8-phase scan in real time. Every endpoint and finding appears instantly.', icon: '⚡' },
              { num: '03', color: '#4dab8a', title: 'Download Report',  desc: 'Receive a professional PDF with findings, severity scores, and remediation guidance.', icon: '◈' },
            ].map(step => (
              <div key={step.num} className="glass-card" style={{ padding: 22, position: 'relative', overflow: 'hidden' }}>
                <div style={{
                  position: 'absolute', top: -8, right: 2,
                  fontFamily: '"Bebas Neue", sans-serif', fontSize: 60,
                  color: `${step.color}06`, letterSpacing: '0.06em',
                }}>{step.num}</div>
                <div style={{
                  width: 32, height: 32, borderRadius: 8, marginBottom: 14,
                  border: `1px solid ${step.color}28`,
                  background: `${step.color}08`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 13, color: step.color, opacity: 0.8,
                }}>{step.icon}</div>
                <div style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 17, letterSpacing: '0.05em', color: '#c9d1d9', marginBottom: 7 }}>
                  {step.title}
                </div>
                <p style={{ fontSize: 10, color: 'rgba(139,148,158,0.55)', lineHeight: 1.8, fontFamily: '"Space Mono", monospace' }}>{step.desc}</p>
              </div>
            ))}
          </div>
        </div>

      </main>

      <footer style={{
        position: 'relative', zIndex: 1, textAlign: 'center',
        padding: '20px 32px', borderTop: '1px solid rgba(255,255,255,0.05)',
        color: 'rgba(139,148,158,0.25)', fontSize: 9,
        fontFamily: '"Space Mono", monospace', letterSpacing: '0.07em',
      }}>
        <span style={{ fontFamily: '"Bebas Neue", sans-serif', fontSize: 12, letterSpacing: '0.1em', color: 'rgba(125,211,232,0.3)', marginRight: 8 }}>
          NexusFlow
        </span>
        · For authorized security testing only. Unauthorized scanning is illegal.
      </footer>
    </div>
  );
}
