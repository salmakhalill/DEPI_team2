/**
 * AttackTimeline.jsx
 * Supports multiple vulnerabilities with horizontal glassmorphic tabs
 */

import React from "react";
import Station from "./Station";
import { sanitize } from "../utils/sanitize";

// ── SeverityBadge Component (Defined once) ──
function SeverityBadge({ severity }) {
  const palette = {
    Critical: { bg: "rgba(239,68,68,0.2)",   border: "#ef4444", text: "#fca5a5" },
    High:     { bg: "rgba(245,158,11,0.2)",   border: "#f59e0b", text: "#fcd34d" },
    Medium:   { bg: "rgba(168,85,247,0.15)",  border: "#a855f7", text: "#d8b4fe" },
    Low:      { bg: "rgba(34,211,238,0.15)",  border: "#22d3ee", text: "#67e8f9" },
  };
  const c = palette[severity] || palette.Low;

  return (
    <span
      style={{
        padding: "3px 12px",
        borderRadius: 20,
        fontSize: 11,
        fontWeight: 700,
        letterSpacing: "0.12em",
        textTransform: "uppercase",
        background: c.bg,
        border: `1px solid ${c.border}`,
        color: c.text,
        fontFamily: "'Michroma', sans-serif",
        whiteSpace: "nowrap",
      }}
    >
      {severity}
    </span>
  );
}

export default function AttackTimeline({ 
  result, 
  activeStations, 
  selectedVulnIndex, 
  selectVulnerability 
}) {
  if (!result || !result.vulnerabilities) return null;

  const vulnerabilities = result.vulnerabilities;
  const current = vulnerabilities[selectedVulnIndex];
  const { vuln, data } = current;

  return (
    <div style={{ animation: "fadeSlideUp 0.6s ease both" }}>
      {/* ── Vulnerability Tabs ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ 
          fontSize: 12, 
          letterSpacing: "0.15em", 
          color: "rgba(148,163,184,0.6)", 
          marginBottom: 12,
          textTransform: "uppercase"
        }}>
          DETECTED VULNERABILITIES
        </div>

        <div 
          style={{
            display: "flex",
            gap: 12,
            overflowX: "auto",
            paddingBottom: 12,
            scrollbarWidth: "none",
            msOverflowStyle: "none",
          }}
          className="vuln-tabs"
        >
          {vulnerabilities.map((item, index) => {
            const isSelected = index === selectedVulnIndex;
            return (
              <div
                key={index}
                onClick={() => selectVulnerability(index)}
                style={{
                  minWidth: "260px",
                  padding: "18px 22px",
                  borderRadius: 16,
                  background: isSelected 
                    ? "rgba(34,211,238,0.15)" 
                    : "rgba(255,255,255,0.04)",
                  border: isSelected 
                    ? "1px solid rgba(34,211,238,0.6)" 
                    : "1px solid rgba(255,255,255,0.1)",
                  backdropFilter: "blur(20px)",
                  cursor: "pointer",
                  transition: "all 0.3s ease",
                  flexShrink: 0,
                  boxShadow: isSelected 
                    ? "0 0 25px rgba(34,211,238,0.2)" 
                    : "none",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ 
                      fontFamily: "'Michroma', sans-serif",
                      fontSize: 17,
                      color: isSelected ? "#22d3ee" : "#e2e8f0",
                      marginBottom: 8,
                      lineHeight: 1.3
                    }}>
                      {sanitize(item.vuln)}
                    </div>
                    <SeverityBadge severity={item.data.severity} />
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Selected Vulnerability Summary Card ── */}
      <div
        style={{
          background: "rgba(203, 47, 47, 0.2)",
          backdropFilter: "blur(24px)",
          border: "1px solid rgba(239,68,68,0.25)",
          borderRadius: 20,
          padding: "26px 28px",
          marginBottom: 32,
          boxShadow: "0 0 40px rgba(239,68,68,0.1)",
        }}
      >
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <div style={{ flex: 1 }}>
            <div style={{ 
              fontSize: 12, 
              letterSpacing: "0.15em", 
              color: "rgba(245, 103, 78, 0.6)", 
              marginBottom: 8, 
              textTransform: "uppercase" 
            }}>
              SELECTED VULNERABILITY
            </div>
            <h2
              style={{
                fontFamily: "'Michroma', sans-serif",
                fontSize: 32,
                letterSpacing: "0.06em",
                color: "#f2d9d9",
                marginBottom: 12,
              }}
            >
              {sanitize(vuln)}
            </h2>
            <p
              style={{ 
                fontSize: 13.5, 
                color: "rgba(148,163,184,0.8)", 
                lineHeight: 1.75,
                maxWidth: 560 
              }}
              dangerouslySetInnerHTML={{ __html: sanitize(data.impact) }}
            />
          </div>
          <SeverityBadge severity={data.severity} />
        </div>
      </div>

      {/* ── Attack Chain Header ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 28 }}>
        <div style={{ height: 1, flex: 1, background: "rgba(34,211,238,0.15)" }} />
        <span
          style={{
            fontFamily: "'Michroma', sans-serif",
            fontSize: 15,
            letterSpacing: "0.22em",
            color: "rgba(34,211,238,0.75)",
            textTransform: "uppercase",
            whiteSpace: "nowrap",
          }}
        >
          ◈ ATTACK CHAIN
        </span>
        <div style={{ height: 1, flex: 1, background: "rgba(34,211,238,0.15)" }} />
      </div>

      {/* ── Attack Stations ── */}
      {data.steps.map((step, i) => (
        <Station
          key={i}
          step={step}
          index={i}
          isLast={i === data.steps.length - 1}
          isVisible={activeStations > i}
          delay={i * 80}
        />
      ))}
    </div>
  );
}