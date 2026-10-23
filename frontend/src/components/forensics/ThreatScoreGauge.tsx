import React from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Activity, 
  Layers,
  ArrowUpRight,
  Target
} from 'lucide-react';
import type { ThreatAssessment } from '../../types';

interface ThreatScoreGaugeProps {
  threat: ThreatAssessment;
}

export const ThreatScoreGauge: React.FC<ThreatScoreGaugeProps> = ({ threat }) => {
  const score = Math.round(threat.score);
  const level = threat.level;

  // Determine threat severity color accents
  const getTheme = (threatLevel: string) => {
    switch (threatLevel) {
      case 'CRITICAL':
        return {
          stroke: '#dc2626',
          glow: 'rgba(220, 38, 38, 0.4)',
          badgeBg: 'bg-rose-950/80 border-rose-600 text-rose-300',
          text: 'text-rose-400',
          icon: ShieldAlert,
        };
      case 'HIGH':
        return {
          stroke: '#ef4444',
          glow: 'rgba(239, 68, 68, 0.35)',
          badgeBg: 'bg-red-950/80 border-red-600 text-red-300',
          text: 'text-red-400',
          icon: ShieldAlert,
        };
      case 'MEDIUM':
        return {
          stroke: '#f59e0b',
          glow: 'rgba(245, 158, 11, 0.35)',
          badgeBg: 'bg-amber-950/80 border-amber-600 text-amber-300',
          text: 'text-amber-400',
          icon: AlertTriangle,
        };
      case 'LOW':
        return {
          stroke: '#eab308',
          glow: 'rgba(234, 179, 8, 0.3)',
          badgeBg: 'bg-yellow-950/80 border-yellow-600 text-yellow-300',
          text: 'text-yellow-400',
          icon: AlertTriangle,
        };
      default:
        return {
          stroke: '#10b981',
          glow: 'rgba(16, 185, 129, 0.3)',
          badgeBg: 'bg-emerald-950/80 border-emerald-600 text-emerald-300',
          text: 'text-emerald-400',
          icon: ShieldCheck,
        };
    }
  };

  const theme = getTheme(level);
  const Icon = theme.icon;

  // Gauge geometry calculations (240 degree arc)
  const radius = 64;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  // Use a 240 degree gauge (from 150deg to 390deg)
  const arcLength = (240 / 360) * circumference;
  const progressOffset = arcLength - (score / 100) * arcLength;

  return (
    <div className="glass-panel rounded-3xl p-6 sm:p-7 border border-cyan-500/20 shadow-2xl space-y-6">
      {/* Top Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              THREAT INDEX & RISK VERDICT
            </h3>
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold ${theme.badgeBg}`}>
              {level} RISK
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time heuristic evaluation synthesized across 5 forensic dimensions
          </p>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span>ALGORITHM VERSION 5.2</span>
        </div>
      </div>

      {/* Main Dial & High-Level Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-center">
        {/* Dial Instrument (Left) */}
        <div className="md:col-span-5 flex flex-col items-center justify-center p-4 bg-slate-950/60 rounded-2xl border border-slate-800/80 relative">
          <div className="relative w-44 h-44 flex items-center justify-center">
            {/* Ambient Backlight Glow */}
            <div
              className="absolute inset-0 rounded-full blur-xl pointer-events-none transition-all duration-700"
              style={{ backgroundColor: theme.glow }}
            />

            <svg className="w-full h-full transform -rotate-210" viewBox="0 0 160 160">
              {/* Background Arc */}
              <circle
                cx="80"
                cy="80"
                r={radius}
                stroke="#1e293b"
                strokeWidth={strokeWidth}
                fill="none"
                strokeDasharray={`${arcLength} ${circumference}`}
                strokeLinecap="round"
              />

              {/* Dynamic Value Arc */}
              <circle
                cx="80"
                cy="80"
                r={radius}
                stroke={theme.stroke}
                strokeWidth={strokeWidth}
                fill="none"
                strokeDasharray={`${arcLength} ${circumference}`}
                strokeDashoffset={progressOffset}
                strokeLinecap="round"
                className="transition-all duration-1000 ease-out"
                style={{ filter: `drop-shadow(0 0 8px ${theme.stroke})` }}
              />
            </svg>

            {/* Center Content */}
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <Icon className={`w-6 h-6 mb-1 ${theme.text}`} />
              <div className="flex items-baseline">
                <span className="text-3xl font-extrabold font-mono text-white tracking-tight">
                  {score}
                </span>
                <span className="text-xs font-mono text-slate-400 ml-1">/100</span>
              </div>
              <span className={`text-[11px] font-bold font-mono uppercase tracking-wider mt-0.5 ${theme.text}`}>
                {level}
              </span>
            </div>
          </div>

          <div className="mt-2 text-center">
            <span className="text-xs font-semibold text-slate-300 block font-mono">
              {threat.verdict}
            </span>
          </div>
        </div>

        {/* 5D Vector Breakdown Bars (Right) */}
        <div className="md:col-span-7 space-y-3.5">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400 uppercase tracking-wider font-bold flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5 text-cyan-400" />
              5-DIMENSIONAL THREAT VECTORS
            </span>
            <span className="text-slate-500">MAX WEIGHT: 100 PTS</span>
          </div>

          {threat.subscores && (
            <div className="space-y-2.5">
              {/* Vector 1: Authentication & Spoofing */}
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-slate-300 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    Authentication & Spoofing (SPF/DKIM/DMARC)
                  </span>
                  <span className="font-bold text-white font-mono">
                    {Math.round(threat.subscores.authentication)} / 25
                  </span>
                </div>
                <div className="w-full bg-slate-800/80 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      threat.subscores.authentication > 10 ? 'bg-rose-500' : 'bg-cyan-400'
                    }`}
                    style={{ width: `${Math.min(100, (threat.subscores.authentication / 25) * 100)}%` }}
                  />
                </div>
              </div>

              {/* Vector 2: URLs & Domains */}
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-slate-300 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-sky-400" />
                    URLs & Domain Reputation (DGA/Typosquatting)
                  </span>
                  <span className="font-bold text-white font-mono">
                    {Math.round(threat.subscores.urls_domains)} / 25
                  </span>
                </div>
                <div className="w-full bg-slate-800/80 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      threat.subscores.urls_domains > 10 ? 'bg-rose-500' : 'bg-sky-400'
                    }`}
                    style={{ width: `${Math.min(100, (threat.subscores.urls_domains / 25) * 100)}%` }}
                  />
                </div>
              </div>

              {/* Vector 3: AI Intent & NLP */}
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-slate-300 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                    AI Intent & Urgency NLP Lures
                  </span>
                  <span className="font-bold text-white font-mono">
                    {Math.round(threat.subscores.ai_content)} / 25
                  </span>
                </div>
                <div className="w-full bg-slate-800/80 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      threat.subscores.ai_content > 10 ? 'bg-rose-500' : 'bg-purple-400'
                    }`}
                    style={{ width: `${Math.min(100, (threat.subscores.ai_content / 25) * 100)}%` }}
                  />
                </div>
              </div>

              {/* Vector 4: Network Origin & MTA */}
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-slate-300 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                    Network Origin & MTA Routing
                  </span>
                  <span className="font-bold text-white font-mono">
                    {Math.round(threat.subscores.network_origin)} / 15
                  </span>
                </div>
                <div className="w-full bg-slate-800/80 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      threat.subscores.network_origin > 5 ? 'bg-rose-500' : 'bg-indigo-400'
                    }`}
                    style={{ width: `${Math.min(100, (threat.subscores.network_origin / 15) * 100)}%` }}
                  />
                </div>
              </div>

              {/* Vector 5: Attachments */}
              <div className="p-2.5 rounded-xl bg-slate-900/60 border border-slate-800/80">
                <div className="flex justify-between text-xs font-mono mb-1.5">
                  <span className="text-slate-300 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                    Attachment MIME & Executable Inspection
                  </span>
                  <span className="font-bold text-white font-mono">
                    {Math.round(threat.subscores.attachments)} / 10
                  </span>
                </div>
                <div className="w-full bg-slate-800/80 h-1.5 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-500 ${
                      threat.subscores.attachments > 2 ? 'bg-rose-500' : 'bg-emerald-400'
                    }`}
                    style={{ width: `${Math.min(100, (threat.subscores.attachments / 10) * 100)}%` }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ThreatScoreGauge;
