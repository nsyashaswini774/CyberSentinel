import React, { useState, useRef } from 'react';
import { 
  UploadCloud, 
  FileText, 
  Sparkles, 
  AlertCircle, 
  Loader2, 
  FileCheck,
  ShieldAlert,
  ArrowRight,
  Code2
} from 'lucide-react';
import { apiService } from '../../services/api';
import type { EmailAnalysisResult } from '../../types';

export type IngestionPhase = 'READY' | 'INGESTING' | 'PARSING' | 'ANALYZING' | 'INVESTIGATING' | 'COMPLETE';

interface EmailIngestionProps {
  onAnalysisComplete: (result: EmailAnalysisResult) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export const EmailIngestion: React.FC<EmailIngestionProps> = ({
  onAnalysisComplete,
  isLoading,
  setIsLoading,
}) => {
  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [rawText, setRawText] = useState<string>('');
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [currentPhase, setCurrentPhase] = useState<IngestionPhase>('READY');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const runPhaseTracker = async <T,>(operation: () => Promise<T>): Promise<T> => {
    setCurrentPhase('INGESTING');
    const timer1 = setTimeout(() => setCurrentPhase('PARSING'), 250);
    const timer2 = setTimeout(() => setCurrentPhase('ANALYZING'), 600);
    const timer3 = setTimeout(() => setCurrentPhase('INVESTIGATING'), 1050);

    try {
      const result = await operation();
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      setCurrentPhase('COMPLETE');
      return result;
    } catch (err) {
      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      setCurrentPhase('READY');
      throw err;
    }
  };

  const handleFileUpload = async (file: File) => {
    setError(null);
    setSelectedFileName(file.name);
    setIsLoading(true);

    try {
      const result = await runPhaseTracker(() => apiService.analyzeEmlFile(file));
      onAnalysisComplete(result);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to analyze .eml file');
    } finally {
      setIsLoading(false);
      setCurrentPhase('READY');
    }
  };

  const handleRawSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawText.trim()) {
      setError('Please paste raw email headers or RFC 5322 email text.');
      return;
    }
    setError(null);
    setIsLoading(true);

    try {
      const result = await runPhaseTracker(() => apiService.analyzeRawText(rawText));
      onAnalysisComplete(result);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to analyze raw email text');
    } finally {
      setIsLoading(false);
      setCurrentPhase('READY');
    }
  };

  const handleSampleLoad = async () => {
    setError(null);
    setSelectedFileName('sample_phishing_attack.eml');
    setIsLoading(true);

    try {
      const result = await runPhaseTracker(() => apiService.loadSampleAnalysis());
      onAnalysisComplete(result);
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Failed to load live phishing sample');
    } finally {
      setIsLoading(false);
      setCurrentPhase('READY');
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  const phasesList: { key: IngestionPhase; label: string }[] = [
    { key: 'READY', label: 'READY' },
    { key: 'INGESTING', label: 'INGESTING' },
    { key: 'PARSING', label: 'PARSING' },
    { key: 'ANALYZING', label: 'ANALYZING' },
    { key: 'INVESTIGATING', label: 'INVESTIGATING' },
    { key: 'COMPLETE', label: 'COMPLETE' },
  ];

  return (
    <div className="glass-panel rounded-3xl p-6 sm:p-8 border border-cyan-500/20 shadow-2xl relative overflow-hidden">
      {/* Background Cyber Ambient Glow */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

      {/* Top Controls: Tab Switcher & 1-Click Phishing Sample */}
      <div className="flex flex-wrap items-center justify-between gap-4 mb-6 border-b border-slate-800/80 pb-5">
        <div className="flex items-center space-x-2 bg-slate-950/80 p-1.5 rounded-2xl border border-slate-800">
          <button
            onClick={() => setActiveTab('upload')}
            className={`flex items-center space-x-2 px-5 py-2 rounded-xl text-xs font-semibold transition-all duration-200 ${
              activeTab === 'upload'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload EML File</span>
          </button>
          <button
            onClick={() => setActiveTab('paste')}
            className={`flex items-center space-x-2 px-5 py-2 rounded-xl text-xs font-semibold transition-all duration-200 ${
              activeTab === 'paste'
                ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Paste Raw Email</span>
          </button>
        </div>

        {/* 1-Click Phishing Sample Test Trigger */}
        <button
          onClick={handleSampleLoad}
          disabled={isLoading}
          className="flex items-center space-x-2 px-4 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-purple-900/50 via-indigo-900/40 to-slate-900/70 hover:from-purple-800/70 hover:to-indigo-800/60 text-purple-200 border border-purple-500/40 shadow-lg shadow-purple-950/50 transition-all duration-300 hover:scale-[1.02] disabled:opacity-50"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin text-purple-300" />
          ) : (
            <Sparkles className="w-4 h-4 text-purple-400 animate-pulse" />
          )}
          <span>Load Live Phishing Sample</span>
        </button>
      </div>

      {/* Progress State Visualizer (Active during investigation) */}
      {isLoading && (
        <div className="mb-6 p-4 rounded-2xl bg-slate-950/90 border border-cyan-500/30 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-cyan-400 font-bold flex items-center gap-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              EXECUTING DIGITAL FORENSIC PIPELINE
            </span>
            <span className="text-slate-400">
              TARGET: <span className="text-white">{selectedFileName || 'RFC PAYLOAD'}</span>
            </span>
          </div>

          {/* Phase Sequence Dots */}
          <div className="grid grid-cols-2 sm:grid-cols-6 gap-2">
            {phasesList.map((p) => {
              const activeIndex = phasesList.findIndex((x) => x.key === currentPhase);
              const thisIndex = phasesList.findIndex((x) => x.key === p.key);
              const isPast = thisIndex < activeIndex;
              const isCurrent = thisIndex === activeIndex;

              return (
                <div
                  key={p.key}
                  className={`px-2.5 py-1.5 rounded-lg text-[10px] font-mono font-bold text-center border transition-all ${
                    isCurrent
                      ? 'bg-cyan-500 text-slate-950 border-white shadow-md shadow-cyan-500/30 animate-pulse'
                      : isPast
                      ? 'bg-cyan-950/60 text-cyan-400 border-cyan-800'
                      : 'bg-slate-900/60 text-slate-600 border-slate-800'
                  }`}
                >
                  {p.label}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Error Message Banner */}
      {error && (
        <div className="mb-6 p-4 bg-rose-950/50 border border-rose-800/80 rounded-2xl flex items-center space-x-3 text-rose-300 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Tab 1: File Dropzone */}
      {activeTab === 'upload' && (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all duration-300 flex flex-col items-center justify-center space-y-4 ${
            dragActive
              ? 'border-cyan-400 bg-cyan-950/30 scale-[1.01]'
              : 'border-slate-800 hover:border-cyan-500/50 bg-slate-950/40 hover:bg-slate-900/40'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,.msg,.txt"
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileUpload(e.target.files[0]);
              }
            }}
            className="hidden"
          />

          <div className="p-5 bg-gradient-to-tr from-cyan-950 to-slate-900 border border-cyan-500/30 rounded-2xl text-cyan-400 shadow-xl shadow-cyan-950/50">
            {isLoading ? (
              <Loader2 className="w-10 h-10 animate-spin text-cyan-400" />
            ) : (
              <UploadCloud className="w-10 h-10 text-cyan-400 transition-transform duration-300 group-hover:scale-110" />
            )}
          </div>

          <div className="space-y-1">
            <p className="text-base font-bold text-white font-sans">
              {isLoading ? 'Extracting Forensic Metadata...' : 'Drop suspicious .eml file here'}
            </p>
            <p className="text-xs text-slate-400 font-sans">
              or click to browse from your workstation (supports RFC 5322 .eml, .msg, .txt)
            </p>
          </div>

          <div className="flex items-center gap-2 pt-2">
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-md bg-slate-900 text-slate-400 border border-slate-800">
              MIME PARSING
            </span>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-md bg-slate-900 text-slate-400 border border-slate-800">
              SHA-256 INTEGRITY
            </span>
            <span className="text-[10px] font-mono px-2.5 py-1 rounded-md bg-slate-900 text-slate-400 border border-slate-800">
              MTA GEOLOCATION
            </span>
          </div>
        </div>
      )}

      {/* Tab 2: Raw Text Editor */}
      {activeTab === 'paste' && (
        <form onSubmit={handleRawSubmit} className="space-y-4">
          <div className="relative">
            <textarea
              value={rawText}
              onChange={(e) => setRawText(e.target.value)}
              placeholder="Paste raw email message here (including headers like 'Received:', 'From:', 'Subject:', 'Authentication-Results:' or complete raw RFC 822 MIME payload)..."
              rows={9}
              className="w-full bg-slate-950/80 border border-slate-800 rounded-2xl p-4 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 shadow-inner"
            />
            <div className="absolute top-3 right-3 px-2 py-0.5 rounded bg-slate-900/90 border border-slate-800 text-[10px] font-mono text-slate-400">
              RFC 5322 RAW INPUT
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-3 text-xs font-mono text-slate-500">
              <span>{rawText.length} characters</span>
              <span>•</span>
              <span>{rawText.split('\n').filter(Boolean).length} lines</span>
            </div>

            <button
              type="submit"
              disabled={isLoading || !rawText.trim()}
              className="flex items-center space-x-2 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl text-xs shadow-lg shadow-cyan-500/20 transition-all duration-300 hover:scale-[1.02] disabled:opacity-50"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Analyzing RFC Payload...</span>
                </>
              ) : (
                <>
                  <Code2 className="w-4 h-4" />
                  <span>Parse & Analyze Content</span>
                  <ArrowRight className="w-4 h-4 ml-1" />
                </>
              )}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};

export default EmailIngestion;
