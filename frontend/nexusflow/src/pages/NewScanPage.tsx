import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Background from '../components/Background';
import Navbar from '../components/Navbar';
import { startScan } from '../api/client';

export default function NewScanPage() {
  const navigate = useNavigate();
  const [targetUrl, setTargetUrl]     = useState('');
  const [cookieHeader, setCookieHeader] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError]             = useState<string | null>(null);
  const [urlError, setUrlError]       = useState<string | null>(null);

  const validate = () => {
    if (!targetUrl.trim()) {
      setUrlError('Target URL is required.');
      return false;
    }
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      setUrlError('Please enter a valid URL starting with http:// or https://');
      return false;
    }
    setUrlError(null);
    return true;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    setIsSubmitting(true);
    setError(null);

    try {
      const res = await startScan({ target_url: targetUrl.trim(), raw_cookie_header: cookieHeader.trim() });
      navigate(`/scan/${res.data.scan_id}/live`);
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 400) {
        setError('Invalid URL or request. Please check the target URL.');
      } else {
        setError('Server error. Please try again.');
      }
      setIsSubmitting(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', position: 'relative' }}>
      <Background />
      <Navbar />

      <main style={{
        position: 'relative', zIndex: 1,
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '100px 24px 60px',
      }}>
        <div style={{
          width: '100%', maxWidth: 560,
          animation: 'fadeSlideUp 0.6s ease forwards',
        }}>
          {/* Header */}
          <div style={{ textAlign: 'center', marginBottom: 32 }}>
            <div style={{
              display: 'inline-flex', alignItems: 'center', gap: 6,
              padding: '4px 12px', borderRadius: 100,
              background: 'rgba(34,211,238,0.08)', border: '1px solid rgba(34,211,238,0.2)',
              fontSize: 9, letterSpacing: '0.15em', color: '#22d3ee', textTransform: 'uppercase',
              marginBottom: 16,
            }}>
              <div style={{
                width: 4, height: 4, borderRadius: '50%',
                background: '#22d3ee', boxShadow: '0 0 6px #22d3ee',
              }} />
              New Scan
            </div>
            <h1 style={{
              fontFamily: '"Bebas Neue", sans-serif',
              fontSize: 40, letterSpacing: '0.06em',
              background: 'linear-gradient(135deg, #f1f5f9, #22d3ee)',
              WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', backgroundClip: 'text',
              marginBottom: 8,
            }}>Configure Target</h1>
            <p style={{
              fontSize: 11, color: 'rgba(148,163,184,0.55)',
              fontFamily: '"Space Mono", monospace', lineHeight: 1.7,
            }}>Enter the target URL and optional session cookies below.</p>
          </div>

          {/* Warning banner */}
          <div style={{
            padding: '10px 16px',
            borderRadius: 10,
            background: 'rgba(245,158,11,0.08)',
            border: '1px solid rgba(245,158,11,0.25)',
            marginBottom: 20,
            display: 'flex', alignItems: 'flex-start', gap: 10,
          }}>
            <span style={{ color: '#f59e0b', fontSize: 14, flexShrink: 0 }}>⚠</span>
            <span style={{
              fontSize: 10, color: 'rgba(245,158,11,0.8)',
              fontFamily: '"Space Mono", monospace', lineHeight: 1.7,
              letterSpacing: '0.04em',
            }}>
              Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.
            </span>
          </div>

          {/* Form */}
          <div className="glass" style={{ padding: 28 }}>
            {/* Target URL */}
            <div style={{ marginBottom: 20 }}>
              <label style={{
                display: 'block',
                fontSize: 9, letterSpacing: '0.15em', textTransform: 'uppercase',
                color: urlError ? '#ef4444' : '#22d3ee',
                fontFamily: '"Space Mono", monospace',
                marginBottom: 8,
              }}>
                Target URL <span style={{ color: '#ef4444' }}>*</span>
              </label>
              <input
                className="cyber-input"
                type="url"
                placeholder="https://target-app.example.com/login"
                value={targetUrl}
                onChange={e => { setTargetUrl(e.target.value); if (urlError) setUrlError(null); }}
                onKeyDown={e => e.key === 'Enter' && handleSubmit()}
                style={{
                  borderColor: urlError ? 'rgba(239,68,68,0.5)' : undefined,
                }}
              />
              {urlError ? (
                <div style={{
                  marginTop: 6, fontSize: 10, color: '#ef4444',
                  fontFamily: '"Space Mono", monospace', letterSpacing: '0.04em',
                }}>{urlError}</div>
              ) : (
                <div style={{
                  marginTop: 6, fontSize: 9, color: 'rgba(148,163,184,0.35)',
                  fontFamily: '"Space Mono", monospace', letterSpacing: '0.04em',
                }}>
                  Include the full URL. The scanner will crawl from this page.
                </div>
              )}
            </div>

            {/* Cookie header */}
            <div style={{ marginBottom: 28 }}>
              <label style={{
                display: 'block',
                fontSize: 9, letterSpacing: '0.15em', textTransform: 'uppercase',
                color: 'rgba(168,85,247,0.8)',
                fontFamily: '"Space Mono", monospace',
                marginBottom: 8,
              }}>
                Session Cookies{' '}
                <span style={{ color: 'rgba(148,163,184,0.35)', textTransform: 'none', letterSpacing: 0 }}>
                  (optional)
                </span>
              </label>
              <textarea
                className="cyber-input"
                placeholder="session=abc123; csrftoken=xyz789"
                value={cookieHeader}
                onChange={e => setCookieHeader(e.target.value)}
                rows={3}
                style={{ resize: 'vertical', minHeight: 70 }}
              />
              <div style={{
                marginTop: 6, fontSize: 9, color: 'rgba(148,163,184,0.35)',
                fontFamily: '"Space Mono", monospace', lineHeight: 1.7, letterSpacing: '0.04em',
              }}>
                DevTools → Network → any request → copy the "Cookie" header.
              </div>
            </div>

            {/* Error */}
            {error && (
              <div style={{
                padding: '10px 14px',
                borderRadius: 8,
                background: 'rgba(239,68,68,0.1)',
                border: '1px solid rgba(239,68,68,0.3)',
                color: '#fca5a5',
                fontSize: 11,
                fontFamily: '"Space Mono", monospace',
                marginBottom: 16,
              }}>✗ {error}</div>
            )}

            {/* Submit */}
            <button
              className="scan-btn"
              onClick={handleSubmit}
              disabled={isSubmitting}
              style={{
                width: '100%',
                padding: '14px',
                borderRadius: 12,
                fontSize: 18,
                cursor: isSubmitting ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 10,
                border: 'none',
              }}
            >
              {isSubmitting ? (
                <>
                  <div style={{
                    width: 16, height: 16,
                    borderRadius: '50%',
                    border: '2px solid rgba(34,211,238,0.3)',
                    borderTopColor: '#22d3ee',
                    animation: 'scanLine 0.7s linear infinite',
                  }} />
                  Initializing Scan...
                </>
              ) : (
                'Launch Scan →'
              )}
            </button>
          </div>

          {/* Tips */}
          <div style={{ marginTop: 20 }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10,
            }}>
              <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.06)' }} />
              <span style={{
                fontSize: 8, color: 'rgba(148,163,184,0.3)', letterSpacing: '0.15em', textTransform: 'uppercase',
              }}>What to expect</span>
              <div style={{ flex: 1, height: 1, background: 'rgba(255,255,255,0.06)' }} />
            </div>
            {[
              'Scan may take several minutes — the crawler visits up to 60 pages.',
              'Keep this tab open during the scan.',
              'A professional PDF report is generated at the end.',
            ].map((tip, i) => (
              <div key={i} style={{
                display: 'flex', gap: 8,
                fontSize: 10, color: 'rgba(148,163,184,0.4)',
                fontFamily: '"Space Mono", monospace', lineHeight: 1.7, marginBottom: 4,
              }}>
                <span style={{ color: 'rgba(34,211,238,0.4)', flexShrink: 0 }}>·</span>
                <span>{tip}</span>
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
