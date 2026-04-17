# Vulnerability Analyzer — Setup & Run Guide

## Prerequisites
- Node.js 16+ → https://nodejs.org
- npm (comes with Node)

---

## 1. Install

```bash
cd vuln-analyzer
npm install
```

---

## 2. Run (Development)

```bash
npm start
```

Opens at **http://localhost:3000** automatically.

---

## 3. Build (Production)

```bash
npm run build
# Output goes to /build — deploy to any static host (Netlify, Vercel, etc.)
```

---

## Project Structure

```
vuln-analyzer/
├── public/
│   └── index.html              # HTML shell
├── src/
│   ├── App.jsx                  # Root component — wires everything together
│   ├── index.jsx                # React entry point
│   │
│   ├── components/
│   │   ├── GlobalStyles.jsx     # All keyframes + base CSS injected as <style>
│   │   ├── Background.jsx       # Animated blobs, grid overlay, scan-line
│   │   ├── ScannerDashboard.jsx # URL input, Launch button, progress bar
│   │   ├── AttackTimeline.jsx   # Vuln summary card + station list
│   │   └── Station.jsx          # Single attack-chain step card
│   │
│   ├── hooks/
│   │   └── useScan.jsx          # All scan state & async logic (custom hook)
│   │
│   ├── data/
│   │   └── mockData.jsx         # Mock responses + simulateScan() function
│   │
│   └── utils/
│       └── sanitize.js         # HTML-entity encoder (Self-XSS prevention)
│
├── package.json
└── README.md
```

---

## Connecting a Real Backend

Open `src/data/mockData.js` and replace `simulateScan()`:

```js
export async function simulateScan(url) {
  const res = await fetch(`/api/scan?url=${encodeURIComponent(url)}`);
  if (!res.ok) throw new Error("Scan failed");
  return await res.json(); // expects { vuln: string, data: { severity, impact, steps[] } }
}
```

---

## Test Scenarios

| URL contains | Triggered scan        |
|---|---|
| `sql`        | SQL Injection (Critical) |
| anything else | Reflected XSS (High)   |

Example URLs to try:
- `https://example.com/search?q=test`        → Reflected XSS
- `https://example.com/login?id=1 OR 1=1`   → SQL Injection (contains "sql")
