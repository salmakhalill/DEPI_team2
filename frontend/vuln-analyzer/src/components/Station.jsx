/**
 * Station.js
 * A single "train station" node in the attack chain timeline.
 * Reveals itself via CSS transition after a delay prop.
 * The particle animates down the connector line.
 */

import React, { useState, useEffect } from "react";
import { sanitize } from "../utils/sanitize";

export default function Station({ step, index, isVisible, delay, isLast }) {
  const [show, setShow]   = useState(false);
  const [pulse, setPulse] = useState(false);

  useEffect(() => {
    if (!isVisible) return;
    const t1 = setTimeout(() => setShow(true),  delay);
    const t2 = setTimeout(() => setPulse(true), delay + 300);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, [isVisible, delay]);

  return (
    <div
      style={{
        display: "flex",
        gap: 20,
        opacity: show ? 1 : 0,
        transform: show ? "translateX(0)" : "translateX(-24px)",
        transition: "opacity 0.6s ease, transform 0.6s ease",
      }}
    >
      {/* ── Left column: node + connector line ── */}
      <div style={{ display: "flex", flexDirection: "column", alignItems: "center", minWidth: 48 }}>
        {/* Node */}
        <div
          style={{
            width: 48,
            height: 48,
            borderRadius: "50%",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 20,
            background: `radial-gradient(circle at 40% 40%, ${step.color}22, ${step.color}08)`,
            border: `1.5px solid ${step.color}`,
            boxShadow: pulse
              ? `0 0 20px ${step.color}55, inset 0 0 12px ${step.color}22`
              : `0 0 8px ${step.color}33`,
            transition: "box-shadow 0.8s ease",
            position: "relative",
            zIndex: 2,
          }}
        >
          {step.icon}
        </div>

        {/* Connector line (hidden on last station) */}
        {!isLast && (
          <div
            style={{
              width: 1.5,
              flex: 1,
              minHeight: 32,
              marginTop: 4,
              background: `linear-gradient(to bottom, ${step.color}88, ${step.color}11)`,
              position: "relative",
            }}
          >
            {show && (
              <div
                style={{
                  position: "absolute",
                  top: 0,
                  left: "50%",
                  transform: "translateX(-50%)",
                  width: 4,
                  height: 4,
                  borderRadius: "50%",
                  background: step.color,
                  boxShadow: `0 0 6px ${step.color}`,
                  animation: "particleDown 2s ease-in-out infinite",
                  animationDelay: `${index * 0.4}s`,
                }}
              />
            )}
          </div>
        )}
      </div>

      {/* ── Right column: info card ── */}
      <div
        style={{
          flex: 1,
          marginBottom: isLast ? 0 : 20,
          padding: "16px 20px",
          borderRadius: 14,
          background: "rgba(255,255,255,0.03)",
          backdropFilter: "blur(20px)",
          WebkitBackdropFilter: "blur(20px)",
          border: `1px solid ${step.color}30`,
          boxShadow: pulse
            ? `0 4px 32px rgba(0,0,0,0.3), inset 0 1px 0 ${step.color}20`
            : "0 2px 16px rgba(0,0,0,0.2)",
          transition: "box-shadow 0.8s ease",
          position: "relative",
          overflow: "hidden",
        }}
      >
        {/* Corner glow accent */}
        <div
          style={{
            position: "absolute",
            top: 0, right: 0,
            width: 60, height: 60,
            background: `radial-gradient(circle at top right, ${step.color}18, transparent)`,
            pointerEvents: "none",
          }}
        />

        {/* Station label */}
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <span
            style={{
              fontFamily: "'Michroma', sans-serif",
              fontSize: 11,
              letterSpacing: "0.15em",
              color: step.color,
              textTransform: "uppercase",
            }}
          >
            Station {String(index + 1).padStart(2, "0")}
          </span>
          <div style={{ flex: 1, height: 1, background: `${step.color}30` }} />
        </div>

        {/* Title */}
        <h3
          style={{
            margin: "0 0 6px",
            fontFamily: "'Michroma', sans-serif",
            fontSize: 22,
            letterSpacing: "0.08em",
            color: step.color,
          }}
        >
          {step.title}
        </h3>

        {/* Description — sanitized before rendering */}
        <p
          style={{
            margin: 0,
            fontFamily: "sans-serif",
            fontSize: 17,
            lineHeight: 1.7,
            color: "rgba(148,163,184,0.9)",
          }}
          dangerouslySetInnerHTML={{ __html: sanitize(step.desc) }}
        />
      </div>
    </div>
  );
}
