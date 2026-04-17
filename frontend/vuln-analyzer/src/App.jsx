/**
 * App.js
 * Root component. Composes Background, ScannerDashboard,
 * and AttackTimeline using state from the useScan hook.
 */

import React from "react";
import GlobalStyles from "./components/GlobalStyles";
import Background from "./components/Background";
import ScannerDashboard from "./components/ScannerDashboard";
import AttackTimeline from "./components/AttackTimeline";
import { useScan } from "./hooks/useScan";

export default function App() {
  const {
    url, setUrl,
    phase,
    result,
    activeStations,
    error,
    isScanning,
    handleScan,
    selectedVulnIndex,
    selectVulnerability,
  } = useScan();

  return (
    <>
      <GlobalStyles />
      <Background isScanning={isScanning} />

      <div
        style={{
          position: "relative",
          zIndex: 1,
          maxWidth: 780,
          margin: "0 auto",
          padding: "48px 24px 80px",
          animation: "fadeSlideUp 0.8s ease both",
        }}
      >
        {/* ── Header ── */}
        <div style={{ marginBottom: 48, textAlign: "center" }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              padding: "6px 16px",
              borderRadius: 100,
              background: "rgba(34,211,238,0.08)",
              border: "1px solid rgba(34,211,238,0.2)",
              marginBottom: 20,
            }}
          >
            <div
              style={{
                width: 6, height: 6,
                borderRadius: "50%",
                background: "#22d3ee",
                boxShadow: "0 0 8px #22d3ee",
              }}
            />
            <span style={{ fontSize: 11, letterSpacing: "0.15em", color: "#22d3ee", textTransform: "uppercase" }}>
              PenTest Suite v2.4
            </span>
          </div>

          <h1
            style={{
              fontFamily: "'Michroma', sans-serif",
              fontSize: "clamp(36px, 6vw, 64px)",
              letterSpacing: "0.06em",
              lineHeight: 1,
              background: "linear-gradient(135deg, #f1f5f9 0%, #22d3ee 50%, #a855f7 100%)",
              WebkitBackgroundClip: "text",
              WebkitTextFillColor: "transparent",
              backgroundClip: "text",
              marginBottom: 12,
            }}
          >
            Vulnerability Analyzer
          </h1>

          <p style={{ color: "rgba(148,163,184,0.7)", fontSize: 13, maxWidth: 420, margin: "0 auto", lineHeight: 1.7 }}>
            Real-time attack chain visualization &amp; penetration testing intelligence
          </p>
        </div>

        {/* ── Scanner input panel ── */}
        <ScannerDashboard
          url={url}
          setUrl={setUrl}
          phase={phase}
          error={error}
          isScanning={isScanning}
          handleScan={handleScan}
        />

        {/* ── Attack chain timeline ── */}
        <AttackTimeline
          result={result}
          activeStations={activeStations}
          selectedVulnIndex={selectedVulnIndex}
          selectVulnerability={selectVulnerability}
        />
      </div>
    </>
  );
}
