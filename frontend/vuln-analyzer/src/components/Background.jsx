
import React from "react";

function Blob({ style }) {
  return (
    <div
      style={{
        position: "absolute",
        borderRadius: "50%",
        filter: "blur(80px)",
        opacity: 0.15,
        animation: "blobFloat 12s ease-in-out infinite",
        ...style,
      }}
    />
  );
}

export default function Background({ isScanning }) {
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 0, overflow: "hidden" }}>
      {/* Base gradient */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "radial-gradient(ellipse at 20% 50%, #0c1445 0%, #020817 60%), radial-gradient(ellipse at 80% 20%, #0d0d2b 0%, transparent 60%)",
        }}
      />

      {/* Blobs */}
      <Blob style={{ width: 500, height: 500, top: "-10%", left: "-10%", background: "#22d3ee" }} />
      <Blob style={{ width: 400, height: 400, bottom: "10%", right: "-5%", background: "#a855f7", animationDelay: "4s" }} />
      <Blob style={{ width: 300, height: 300, top: "50%", left: "40%", background: "#1e40af", animationDelay: "8s" }} />

      {/* Grid */}
      <div
        style={{
          position: "absolute",
          inset: 0,
          pointerEvents: "none",
          backgroundImage: `
            linear-gradient(rgba(34,211,238,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(34,211,238,0.04) 1px, transparent 1px)
          `,
          backgroundSize: "40px 40px",
        }}
      />

      {/* Scan line */}
      {isScanning && (
        <div
          style={{
            position: "absolute",
            inset: "0 0 auto",
            height: 2,
            background: "linear-gradient(90deg, transparent, #22d3ee, transparent)",
            animation: "scanLine 2s linear infinite",
            opacity: 0.6,
          }}
        />
      )}
    </div>
  );
}
