interface BackgroundProps {
  isScanning?: boolean;
}

export default function Background({ isScanning = false }: BackgroundProps) {
  return (
    <div className="fixed inset-0 overflow-hidden pointer-events-none z-0">
      {/* Base radial gradient */}
      <div
        style={{
          position: 'absolute', inset: 0,
          background: `
            radial-gradient(ellipse at 60% 50%, #0c1445 0%, transparent 60%),
            radial-gradient(ellipse at 90% 20%, #0d0d2b 0%, transparent 80%),
            #020817
          `,
        }}
      />

      {/* Blob 1 — Cyan */}
      <div
        style={{
          position: 'absolute',
          top: '10%', left: '15%',
          width: 500, height: 500,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(34,211,238,0.25), transparent 70%)',
          filter: 'blur(80px)',
          opacity: 0.15,
          animation: 'blobFloat 12s ease-in-out infinite',
          animationDelay: '0s',
        }}
      />

      {/* Blob 2 — Purple */}
      <div
        style={{
          position: 'absolute',
          top: '40%', right: '10%',
          width: 400, height: 400,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(168,85,247,0.3), transparent 70%)',
          filter: 'blur(80px)',
          opacity: 0.15,
          animation: 'blobFloat 12s ease-in-out infinite',
          animationDelay: '4s',
        }}
      />

      {/* Blob 3 — Navy depth */}
      <div
        style={{
          position: 'absolute',
          bottom: '15%', left: '40%',
          width: 300, height: 300,
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(12,20,69,0.8), transparent 70%)',
          filter: 'blur(60px)',
          opacity: 0.15,
          animation: 'blobFloat 12s ease-in-out infinite',
          animationDelay: '8s',
        }}
      />

      {/* Grid overlay */}
      <div className="grid-overlay" />

      {/* Scan line — only during active scan */}
      {isScanning && (
        <div
          style={{
            position: 'absolute',
            left: 0, right: 0,
            height: 2,
            background: 'linear-gradient(90deg, transparent, rgba(34,211,238,0.6), transparent)',
            animation: 'scanLine 2s linear infinite',
            opacity: 0.6,
            zIndex: 1,
          }}
        />
      )}
    </div>
  );
}
