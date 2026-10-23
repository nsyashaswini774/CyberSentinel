import React from 'react';

interface VyuhaLogoProps {
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl';
  showWordmark?: boolean;
  showTagline?: boolean;
  animated?: boolean;
  className?: string;
}

export const VyuhaLogo: React.FC<VyuhaLogoProps> = ({
  size = 'md',
  showWordmark = true,
  showTagline = false,
  animated = false,
  className = '',
}) => {
  const sizeMap = {
    xs: { icon: 20, text: 'text-sm', badge: 'text-[9px]', gap: 'gap-2' },
    sm: { icon: 26, text: 'text-base', badge: 'text-[9px]', gap: 'gap-2.5' },
    md: { icon: 34, text: 'text-xl', badge: 'text-[10px]', gap: 'gap-3' },
    lg: { icon: 46, text: 'text-2xl', badge: 'text-xs', gap: 'gap-3.5' },
    xl: { icon: 64, text: 'text-3xl', badge: 'text-xs', gap: 'gap-4' },
  };

  const currentSize = sizeMap[size];
  const iconSize = currentSize.icon;

  return (
    <div className={`inline-flex items-center ${currentSize.gap} select-none ${className}`}>
      {/* Geometric V Shield Symbol */}
      <div className="relative flex items-center justify-center shrink-0">
        {/* Ambient Glow */}
        <div
          className={`absolute inset-0 rounded-xl bg-cyan-500/20 blur-md pointer-events-none transition-opacity ${
            animated ? 'animate-pulse' : ''
          }`}
          style={{ width: iconSize, height: iconSize }}
        />

        <svg
          width={iconSize}
          height={iconSize}
          viewBox="0 0 48 48"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          className="relative z-10 transition-transform duration-300 hover:scale-105"
        >
          <defs>
            {/* Outer Shield/V Gradient */}
            <linearGradient id="vyuha-shield-grad" x1="6" y1="4" x2="42" y2="44" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#00f0ff" />
              <stop offset="45%" stopColor="#0284c7" />
              <stop offset="100%" stopColor="#6366f1" />
            </linearGradient>

            {/* Inner Core Gradient */}
            <linearGradient id="vyuha-core-grad" x1="16" y1="12" x2="32" y2="38" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#38bdf8" />
              <stop offset="100%" stopColor="#8b5cf6" />
            </linearGradient>

            {/* Accent Wing Gradient */}
            <linearGradient id="vyuha-wing-left" x1="4" y1="8" x2="20" y2="36" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#00f0ff" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#0369a1" stopOpacity="0.4" />
            </linearGradient>

            <linearGradient id="vyuha-wing-right" x1="44" y1="8" x2="28" y2="36" gradientUnits="userSpaceOnUse">
              <stop offset="0%" stopColor="#818cf8" stopOpacity="0.9" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.4" />
            </linearGradient>

            {/* Glow Filter */}
            <filter id="vyuha-glow" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="1.5" result="glow" />
              <feComposite in="SourceGraphic" in2="glow" operator="over" />
            </filter>
          </defs>

          {/* Outer Shield Perimeter Facets */}
          <path
            d="M24 4L40 10V22C40 32.5 33.2 41.2 24 44C14.8 41.2 8 32.5 8 22V10L24 4Z"
            stroke="url(#vyuha-shield-grad)"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            fill="#030712"
            fillOpacity="0.85"
          />

          {/* Futuristic Geometric 'V' Structure */}
          {/* Left Wing Facet */}
          <path
            d="M12 14L24 38L21 38L10 16L12 14Z"
            fill="url(#vyuha-wing-left)"
          />

          {/* Right Wing Facet */}
          <path
            d="M36 14L24 38L27 38L38 16L36 14Z"
            fill="url(#vyuha-wing-right)"
          />

          {/* Central Angular V Core */}
          <path
            d="M16 12L24 30L32 12H27.5L24 21L20.5 12H16Z"
            fill="url(#vyuha-core-grad)"
            filter="url(#vyuha-glow)"
          />

          {/* Defense Strategic Formations (Node Interconnects) */}
          <circle cx="24" cy="30" r="2" fill="#00f0ff" />
          <circle cx="24" cy="4" r="1.5" fill="#38bdf8" />
          <circle cx="12" cy="14" r="1.5" fill="#00f0ff" />
          <circle cx="36" cy="14" r="1.5" fill="#a855f7" />

          {/* Precision Crosshair Lines */}
          <line x1="24" y1="12" x2="24" y2="18" stroke="#38bdf8" strokeWidth="1" strokeDasharray="1 2" />
          <line x1="18" y1="21" x2="30" y2="21" stroke="#38bdf8" strokeWidth="0.8" strokeOpacity="0.7" />
        </svg>
      </div>

      {/* Typography Wordmark */}
      {showWordmark && (
        <div className="flex flex-col justify-center">
          <div className="flex items-center gap-2 leading-none">
            <span
              className={`font-black tracking-wider text-white font-mono uppercase ${currentSize.text} bg-gradient-to-r from-white via-slate-100 to-slate-300 bg-clip-text text-transparent`}
            >
              VYUHA <span className="text-cyan-400 font-extrabold">AI</span>
            </span>
            <span
              className={`font-mono font-bold uppercase tracking-widest px-1.5 py-0.5 rounded bg-cyan-950/80 border border-cyan-500/30 text-cyan-300 ${currentSize.badge}`}
            >
              THREAT INTEL
            </span>
          </div>
          {showTagline && (
            <p className="text-[11px] font-medium text-slate-400 tracking-wide mt-1">
              AI-Powered Digital Threat Intelligence
            </p>
          )}
        </div>
      )}
    </div>
  );
};

export default VyuhaLogo;
