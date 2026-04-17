/**
 * ScannerDashboard.js
 * Target input, Launch Scan button, phase progress bar, and status dot.
 * All displayed user strings pass through sanitize() before render.
 */

import React from "react";
import { sanitize } from "../utils/sanitize";

function StatusDot({ phase }) {
  const phases = {
    idle:       { label: "Ready",      color: "#64748b" },
    scanning:   { label: "Scanning",   color: "#22d3ee" },
    analyzing:  { label: "Analyzing",  color: "#a855f7" },
    finalizing: { label: "Finalizing", color: "#10b981" },
    done:       { label: "Complete",   color: "#10b981" },
    error:      { label: "Error",      color: "#ef4444" },
  };
  const p = phases[phase] || phases.idle;
  const isAnimating = phase !== "idle" && phase !== "done" && phase !== "error";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: p.color,
          boxShadow: `0 0 8px ${p.color}`,
          animation: isAnimating ? "statusPulse 1.2s ease-in-out infinite" : "none",
        }}
      />
      <span
        style={{
          fontFamily: "'Michroma', sans-serif",
          fontSize: 11,
          letterSpacing: "0.12em",
          color: p.color,
          textTransform: "uppercase",
        }}
      >
        {p.label}
      </span>
    </div>
  );
}

function ProgressBar({ phase }) {
  const widthMap = {
    scanning: "33%",
    analyzing: "66%",
    finalizing: "85%",
    done: "100%",
    error: "100%",
  };
  const width = widthMap[phase] || "0%";
  const color = phase === "error" ? "#ef4444" : "linear-gradient(90deg, #22d3ee, #a855f7)";

  if (phase === "idle") return null;

  return (
    <div style={{ marginTop: 16 }}>
      <div style={{ height: 2, borderRadius: 1, background: "rgba(255,255,255,0.06)", overflow: "hidden" }}>
        <div
          style={{
            height: "100%",
            borderRadius: 1,
            background: phase === "error" ? "#ef4444" : "linear-gradient(90deg, #22d3ee, #a855f7)",
            width,
            transition: "width 0.8s ease",
            boxShadow: phase === "error" ? "0 0 8px rgba(239,68,68,0.6)" : "0 0 8px rgba(34,211,238,0.6)",
          }}
        />
      </div>
    </div>
  );
}

export default function ScannerDashboard({
  url, setUrl, phase, error, isScanning, handleScan,
}) {
  const btnLabel =
    phase === "scanning"   ? "Scanning..."   :
    phase === "analyzing"  ? "Analyzing..."  :
    phase === "finalizing" ? "Finalizing..." : "⬡ Launch Scan";

  return (
    <div
      style={{
        background: "rgba(255,255,255,0.03)",
        backdropFilter: "blur(24px)",
        WebkitBackdropFilter: "blur(24px)",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 20,
        padding: "28px 28px 24px",
        marginBottom: 32,
      }}
    >
      {/* Header row */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 20 }}>
        <span
          style={{
            fontFamily: "'Michroma', sans-serif",
            fontSize: 14,
            letterSpacing: "0.14em",
            color: "rgba(148,163,184,0.6)",
          }}
        >
          Target Configuration
        </span>
        <StatusDot phase={phase} />
      </div>

      {/* Input row */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        <input
          style={{
            flex: 1,
            minWidth: 200,
            background: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(34,211,238,0.25)",
            borderRadius: 12,
            padding: "14px 18px",
            color: "#e2e8f0",
            fontFamily: "'Michroma', sans-serif",
            fontSize: 13,
            outline: "none",
          }}
          type="text"
          placeholder="https://target.example.com/search?q="
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleScan()}
          disabled={isScanning}
          spellCheck={false}
          autoComplete="off"
        />
        <button
          className="scan-btn"
          onClick={handleScan}
          disabled={isScanning}
        >
          {btnLabel}
        </button>
      </div>

      {/* Error */}
      {error && (
        <p style={{ fontSize: 12, color: "#fca5a5", fontFamily: "'Michroma', sans-serif", marginTop: 10 }}>
          ⚠ {sanitize(error)}
        </p>
      )}

      <ProgressBar phase={phase} />
    </div>
  );
}
