/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          cyan: '#22d3ee',
          purple: '#a855f7',
          green: '#10b981',
          amber: '#f59e0b',
          red: '#ef4444',
          navy: '#0c1445',
          obsidian: '#020817',
        }
      },
      fontFamily: {
        display: ['"Bebas Neue"', 'sans-serif'],
        mono: ['"Space Mono"', 'monospace'],
      },
      animation: {
        'blob-float': 'blobFloat 12s ease-in-out infinite',
        'status-pulse': 'statusPulse 1.2s ease-in-out infinite',
        'fade-slide-up': 'fadeSlideUp 0.6s ease forwards',
        'scan-line': 'scanLine 2s linear infinite',
        'shimmer': 'shimmer 1.5s linear infinite',
      },
      keyframes: {
        blobFloat: {
          '0%,100%': { transform: 'translate(0,0) scale(1)' },
          '33%': { transform: 'translate(30px,-20px) scale(1.08)' },
          '66%': { transform: 'translate(-20px,15px) scale(0.95)' },
        },
        statusPulse: {
          '0%,100%': { opacity: '1', transform: 'scale(1)' },
          '50%': { opacity: '0.4', transform: 'scale(1.4)' },
        },
        fadeSlideUp: {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        scanLine: {
          from: { transform: 'translateY(-100%)' },
          to: { transform: 'translateY(100vh)' },
        },
        shimmer: {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
    },
  },
  plugins: [],
}
