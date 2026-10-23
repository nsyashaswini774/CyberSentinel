/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
        display: ['"Syne"', '"Plus Jakarta Sans"', 'sans-serif'],
      },
      colors: {
        void: {
          950: '#02040a',
          900: '#030712',
          850: '#060b18',
          800: '#0b1224',
          750: '#0f172a',
        },
        cyber: {
          cyan: '#00f0ff',
          blue: '#38bdf8',
          violet: '#8b5cf6',
          indigo: '#6366f1',
          crimson: '#f43f5e',
          amber: '#f59e0b',
          emerald: '#10b981',
        },
      },
      boxShadow: {
        'glow-cyan': '0 0 25px -5px rgba(0, 240, 255, 0.25)',
        'glow-violet': '0 0 25px -5px rgba(139, 92, 246, 0.25)',
        'glow-crimson': '0 0 25px -5px rgba(244, 63, 94, 0.3)',
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'spin-slow': 'spin 12s linear infinite',
      },
    },
  },
  plugins: [],
}
