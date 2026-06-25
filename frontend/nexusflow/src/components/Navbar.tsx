import { Link, useLocation } from 'react-router-dom';

export default function Navbar() {
  const { pathname } = useLocation();

  return (
    <nav
      style={{
        position: 'fixed', top: 0, left: 0, right: 0,
        zIndex: 100,
        background: 'rgba(2,8,23,0.85)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(34,211,238,0.1)',
        padding: '0 32px',
        height: 60,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}
    >
      {/* Logo */}
      <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{
          width: 28, height: 28,
          borderRadius: '50%',
          border: '2px solid #22d3ee',
          background: 'radial-gradient(circle at 40% 40%, rgba(34,211,238,0.25), rgba(34,211,238,0.05))',
          boxShadow: '0 0 12px rgba(34,211,238,0.4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 11,
          color: '#22d3ee',
        }}>⬡</div>
        <span style={{
          fontFamily: '"Bebas Neue", sans-serif',
          fontSize: 22,
          letterSpacing: '0.1em',
          background: 'linear-gradient(135deg, #f1f5f9, #22d3ee)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          backgroundClip: 'text',
        }}>NexusFlow</span>
      </Link>

      {/* Right side */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <div style={{
          width: 6, height: 6,
          borderRadius: '50%',
          background: '#10b981',
          boxShadow: '0 0 6px #10b981',
          animation: 'statusPulse 1.2s ease-in-out infinite',
        }} />
        <span style={{
          fontSize: 10,
          color: 'rgba(148,163,184,0.6)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
        }}>System Online</span>

        {pathname !== '/scan/new' && (
          <Link
            to="/scan/new"
            style={{
              marginLeft: 16,
              padding: '6px 18px',
              borderRadius: 8,
              fontSize: 11,
              fontFamily: '"Bebas Neue", sans-serif',
              letterSpacing: '0.12em',
              background: 'rgba(34,211,238,0.08)',
              border: '1px solid rgba(34,211,238,0.3)',
              color: '#22d3ee',
              textDecoration: 'none',
              transition: 'all 0.2s',
            }}
            onMouseEnter={e => {
              (e.target as HTMLElement).style.background = 'rgba(34,211,238,0.15)';
              (e.target as HTMLElement).style.boxShadow = '0 0 15px rgba(34,211,238,0.2)';
            }}
            onMouseLeave={e => {
              (e.target as HTMLElement).style.background = 'rgba(34,211,238,0.08)';
              (e.target as HTMLElement).style.boxShadow = 'none';
            }}
          >
            New Scan
          </Link>
        )}
      </div>
    </nav>
  );
}
