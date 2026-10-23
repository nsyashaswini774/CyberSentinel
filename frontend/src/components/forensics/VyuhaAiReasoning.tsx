import React from 'react';
import { 
  Cpu, 
  CheckCircle2, 
  AlertTriangle, 
  ShieldAlert, 
  Zap,
  Target,
  Sparkles,
  Info
} from 'lucide-react';
import type { ThreatAssessment } from '../../types';

interface VyuhaAiReasoningProps {
  threat: ThreatAssessment;
}

export const VyuhaAiReasoning: React.FC<VyuhaAiReasoningProps> = ({ threat }) => {
  const confidencePercent = Math.round((threat.ai_confidence || 0) * 100);

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-rose-950/80 border-rose-600 text-rose-300';
      case 'HIGH':
        return 'bg-red-950/80 border-red-600 text-red-300';
      case 'MEDIUM':
        return 'bg-amber-950/80 border-amber-600 text-amber-300';
      case 'LOW':
        return 'bg-yellow-950/80 border-yellow-600 text-yellow-300';
      default:
        return 'bg-emerald-950/80 border-emerald-600 text-emerald-300';
    }
  };

  return (
    <div className="glass-panel rounded-3xl p-6 sm:p-7 border border-cyan-500/20 shadow-2xl space-y-6">
      {/* Header Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-gradient-to-tr from-purple-950 to-indigo-900 rounded-xl border border-purple-500/40 text-purple-300 shadow-md">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold font-mono text-white uppercase tracking-wider flex items-center gap-2">
              VYUHA AI ANALYSIS & REASONING ENGINE
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Explainable neural intent classification and psychological coercion detection
            </p>
          </div>
        </div>

        {/* Model Confidence & Intent Badges */}
        <div className="flex flex-wrap items-center gap-2.5">
          {threat.intent_category && (
            <div className="flex items-center space-x-1.5 px-3 py-1 bg-cyan-950/80 border border-cyan-500/40 rounded-xl text-xs font-mono text-cyan-300">
              <Target className="w-3.5 h-3.5" />
              <span>
                Intent: <strong className="text-white">{threat.intent_category}</strong>
              </span>
            </div>
          )}

          <div className="flex items-center space-x-1.5 px-3 py-1 bg-purple-950/80 border border-purple-500/40 rounded-xl text-xs font-mono text-purple-300">
            <Sparkles className="w-3.5 h-3.5" />
            <span>
              Model Confidence: <strong className="text-white">{confidencePercent}%</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Narrative Synthesis */}
      <div className="p-4 rounded-2xl bg-slate-950/70 border border-slate-800/80 flex items-start space-x-3">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
          {threat.summary}
        </p>
      </div>

      {/* Two Column Grid: Explainable Points & NLP Lure Phrases */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Left: Why is this email suspicious? */}
        <div className="space-y-3">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            Explainable Forensic Findings ({threat.explanation_points?.length || 0})
          </h4>

          {threat.explanation_points && threat.explanation_points.length > 0 ? (
            <div className="space-y-2">
              {threat.explanation_points.map((point, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-900/60 hover:bg-slate-900/90 rounded-xl border border-slate-800/80 text-xs text-slate-300 flex items-start space-x-2.5 transition"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0 mt-1.5" />
                  <span className="leading-relaxed">{point}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-slate-500 italic p-3 bg-slate-950/40 rounded-xl border border-slate-800">
              No suspicious heuristic anomalies triggered in RFC payload.
            </p>
          )}
        </div>

        {/* Right: Flagged Coercion / Urgency Phrases */}
        <div className="space-y-3">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            Detected Psychological Coercion & Urgency Lures
          </h4>

          {threat.flagged_phrases && threat.flagged_phrases.length > 0 ? (
            <div className="space-y-2">
              <div className="flex flex-wrap gap-2">
                {threat.flagged_phrases.map((phrase, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1.5 bg-rose-950/60 border border-rose-800/80 rounded-xl text-rose-300 text-xs font-mono flex items-center gap-1.5"
                  >
                    <Zap className="w-3 h-3 text-rose-400" />
                    "{phrase}"
                  </span>
                ))}
              </div>
              <p className="text-[11px] text-slate-400 pt-1 leading-normal">
                Extracted NLP coercion signals indicate simulated emergency or impending account closure to bypass rational verification.
              </p>
            </div>
          ) : (
            <p className="text-xs text-slate-500 italic p-3 bg-slate-950/40 rounded-xl border border-slate-800">
              No coercive urgency phrases flagged by NLP detector.
            </p>
          )}
        </div>
      </div>

      {/* Triggered Forensic Risk Rules */}
      {threat.risk_factors && threat.risk_factors.length > 0 && (
        <div className="pt-2 space-y-3 border-t border-slate-800/80">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-400" />
              TRIGGERED HEURISTIC RULES ({threat.risk_factors.length})
            </span>
            <span className="text-slate-500">PENALTY POINTS ATTRIBUTED</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {threat.risk_factors.map((rf, i) => (
              <div
                key={i}
                className="p-3 bg-slate-950/70 border border-slate-800/80 rounded-xl flex items-start justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-white">{rf.rule}</span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border font-bold ${getRiskBadge(rf.severity)}`}>
                      {rf.severity}
                    </span>
                  </div>
                  <p className="text-slate-400 text-[11px] leading-relaxed">{rf.description}</p>
                </div>
                <span className="font-mono font-bold text-rose-400 shrink-0 bg-rose-950/80 border border-rose-800/60 px-2 py-0.5 rounded-lg">
                  +{rf.points}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default VyuhaAiReasoning;
