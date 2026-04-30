/**
 * GlobalStyles.js
 * Injects all keyframe animations and base CSS resets
 * as a single <style> tag into the document head.
 */

import React from "react";

export default function GlobalStyles() {
  return (
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=Michroma&display=swap');

      *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

      body {
        background: #020817;
        min-height: 100vh;
        font-family: 'Michroma', sans-serif;
        color: #e2e8f0;
        overflow-x: hidden;
      }
      .vuln-tabs::-webkit-scrollbar {
        display: none;
      }
      /* ── Keyframes ── */

      @keyframes blobFloat {
        0%, 100% { transform: translate(0, 0) scale(1); }
        33%       { transform: translate(30px, -20px) scale(1.08); }
        66%       { transform: translate(-20px, 15px) scale(0.95); }
      }

      @keyframes statusPulse {
        0%, 100% { opacity: 1; transform: scale(1); }
        50%       { opacity: 0.4; transform: scale(1.4); }
      }

      @keyframes particleDown {
        0%   { top: 0%;   opacity: 1; }
        80%  { top: 90%;  opacity: 0.3; }
        100% { top: 100%; opacity: 0; }
      }

      @keyframes scanLine {
        0%   { transform: translateY(-100%); }
        100% { transform: translateY(100vh); }
      }

      @keyframes fadeSlideUp {
        from { opacity: 0; transform: translateY(20px); }
        to   { opacity: 1; transform: translateY(0); }
      }

      @keyframes shimmer {
        0%   { background-position: -200% center; }
        100% { background-position:  200% center; }
      }

      /* ── Reusable classes ── */

      .scan-btn {
        position: relative;
        padding: 14px 36px;
        border: none;
        border-radius: 12px;
        cursor: pointer;
        font-family: 'Michroma', sans-serif;
        font-size: 18px;
        letter-spacing: 0.14em;
        color: #020817;
        background: linear-gradient(135deg, #22d3ee, #a855f7, #22d3ee);
        background-size: 200% 100%;
        transition: all 0.3s ease;
        overflow: hidden;
        white-space: nowrap;
      }

      .scan-btn:hover:not(:disabled) {
        animation: shimmer 1.5s linear infinite;
        transform: translateY(-2px);
        box-shadow: 0 8px 32px rgba(34,211,238,0.4), 0 4px 16px rgba(168,85,247,0.3);
      }

      .scan-btn:active:not(:disabled) { transform: translateY(0); }

      .scan-btn:disabled {
        opacity: 0.6;
        cursor: not-allowed;
      }

      /* ── Scrollbar ── */
      ::-webkit-scrollbar       { width: 6px; }
      ::-webkit-scrollbar-track { background: transparent; }
      ::-webkit-scrollbar-thumb { background: rgba(34,211,238,0.2); border-radius: 3px; }
    `}</style>
  );
}
