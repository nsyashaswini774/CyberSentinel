import React from 'react';
import { 
  UploadCloud, 
  FileCode, 
  Network, 
  Cpu, 
  Link2, 
  Gauge, 
  FileCheck2,
  CheckCircle2,
  Clock
} from 'lucide-react';

export type PipelineStepId = 'ingest' | 'extract' | 'trace' | 'analyze' | 'investigate' | 'score' | 'report';

interface PipelineStep {
  id: PipelineStepId;
  number: number;
  label: string;
  sublabel: string;
  icon: React.ElementType;
}

interface InvestigationPipelineProps {
  currentStep?: PipelineStepId;
  onStepClick?: (step: PipelineStepId) => void;
  isComplete?: boolean;
}

const steps: PipelineStep[] = [
  { id: 'ingest', number: 1, label: 'INGEST', sublabel: 'MIME / EML Payload', icon: UploadCloud },
  { id: 'extract', number: 2, label: 'EXTRACT', sublabel: 'RFC Headers & Auth', icon: FileCode },
  { id: 'trace', number: 3, label: 'TRACE', sublabel: 'MTA Hops & Geo-IP', icon: Network },
  { id: 'analyze', number: 4, label: 'ANALYZE', sublabel: 'AI Intent & NLP Lures', icon: Cpu },
  { id: 'investigate', number: 5, label: 'INVESTIGATE', sublabel: 'URLs & Domain Rep', icon: Link2 },
  { id: 'score', number: 6, label: 'SCORE', sublabel: '5D Threat Vector', icon: Gauge },
  { id: 'report', number: 7, label: 'REPORT', sublabel: 'PDF & Cryptographic Hash', icon: FileCheck2 },
];

export const InvestigationPipeline: React.FC<InvestigationPipelineProps> = ({
  currentStep = 'ingest',
  onStepClick,
  isComplete = false,
}) => {
  const getStepStatus = (index: number) => {
    const currentIndex = steps.findIndex((s) => s.id === currentStep);
    if (isComplete) return 'complete';
    if (index < currentIndex) return 'complete';
    if (index === currentIndex) return 'active';
    return 'pending';
  };

  return (
    <div className="w-full glass-panel rounded-2xl p-4 sm:p-5 border border-cyan-500/20 shadow-xl overflow-x-auto">
      <div className="flex items-center justify-between min-w-[760px] relative">
        {/* Background Connecting Rail */}
        <div className="absolute top-5 left-6 right-6 h-0.5 bg-slate-800 -z-0" />

        {steps.map((step, idx) => {
          const status = getStepStatus(idx);
          const Icon = step.icon;
          const isClickable = !!onStepClick;

          return (
            <div
              key={step.id}
              onClick={() => isClickable && onStepClick(step.id)}
              className={`relative z-10 flex flex-col items-center text-center transition-all duration-300 ${
                isClickable ? 'cursor-pointer group' : ''
              }`}
              style={{ width: '13%' }}
            >
              {/* Step Circle Node */}
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center font-mono text-xs font-bold border transition-all duration-300 ${
                  status === 'complete'
                    ? 'bg-cyan-950 border-cyan-500 text-cyan-300 shadow-lg shadow-cyan-500/20 scale-100'
                    : status === 'active'
                    ? 'bg-gradient-to-tr from-cyan-500 to-blue-600 border-white text-slate-950 shadow-lg shadow-cyan-500/30 scale-110'
                    : 'bg-slate-900/90 border-slate-800 text-slate-500'
                } ${isClickable ? 'group-hover:border-cyan-400' : ''}`}
              >
                {status === 'complete' ? (
                  <CheckCircle2 className="w-5 h-5 text-cyan-400" />
                ) : status === 'active' ? (
                  <Icon className="w-5 h-5 text-slate-950 animate-pulse" />
                ) : (
                  <span className="font-mono text-slate-500">{step.number}</span>
                )}
              </div>

              {/* Step Labels */}
              <div className="mt-2.5 space-y-0.5">
                <span
                  className={`block text-[11px] font-bold font-mono uppercase tracking-wider ${
                    status === 'active'
                      ? 'text-cyan-400'
                      : status === 'complete'
                      ? 'text-slate-200'
                      : 'text-slate-500'
                  }`}
                >
                  {step.label}
                </span>
                <span className="block text-[9px] text-slate-400 font-sans leading-tight">
                  {step.sublabel}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default InvestigationPipeline;
