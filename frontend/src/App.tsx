import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  Activity, 
  Database, 
  Server,
  FileSearch,
  Archive,
  Inbox,
  FileDown
} from 'lucide-react';
import { apiService } from './services/api';
import type { HealthStatus, EmailAnalysisResult } from './types';
import { EmailIngestion } from './components/upload/EmailIngestion';
import { ForensicOverview } from './components/forensics/ForensicOverview';
import { CaseArchives } from './components/history/CaseArchives';

export const App: React.FC = () => {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [analysisResult, setAnalysisResult] = useState<EmailAnalysisResult | null>(null);
  const [analyzing, setAnalyzing] = useState<boolean>(false);
  const [activeView, setActiveView] = useState<'scanner' | 'archives'>('scanner');

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getHealth();
      setHealth(data);
    } catch (err: any) {
      setError(err.message || 'Unable to connect to CyberSentinel AI backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const handleSelectHistoricalCase = (caseDetail: EmailAnalysisResult) => {
    setAnalysisResult(caseDetail);
    setActiveView('scanner');
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-900">
      {/* Top SOC Navbar */}
      <header className="border-b border-slate-800 bg-[#0d1527]/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-gradient-to-tr from-cyan-600 to-blue-500 rounded-lg shadow-lg shadow-cyan-500/20">
              <ShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div>
              <span className="text-xl font-bold tracking-wider text-white font-mono flex items-center gap-2">
                CYBERSENTINEL <span className="text-cyan-400">AI</span>
                <span className="text-[10px] uppercase font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded">
                  SIH SOC Platform
                </span>
              </span>
              <p className="text-xs text-slate-400">Email Threat Detection, Geolocation & Forensic Intelligence</p>
            </div>
          </div>

          {/* Center Navigation Switcher */}
          <div className="hidden md:flex items-center bg-slate-900/90 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => {
                setActiveView('scanner');
              }}
              className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeView === 'scanner'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Inbox className="w-3.5 h-3.5" />
              <span>Live Investigation</span>
            </button>

            <button
              onClick={() => {
                setActiveView('archives');
                setAnalysisResult(null);
              }}
              className={`flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeView === 'archives'
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-md'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Archive className="w-3.5 h-3.5" />
              <span>Case Archives</span>
            </button>
          </div>

          {/* Backend Connection Status Badge */}
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2 bg-slate-900/90 border border-slate-800 px-3 py-1.5 rounded-full text-xs">
              <span className="relative flex h-2.5 w-2.5">
                {health ? (
                  <>
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
                  </>
                ) : (
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-amber-500"></span>
                )}
              </span>
              <span className="font-mono text-slate-300">
                {loading ? 'Checking Engine...' : health ? 'API Online' : 'Connecting to API...'}
              </span>
            </div>
            <button
              onClick={fetchHealth}
              title="Refresh API Connection"
              className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded transition"
            >
              <Activity className="w-4 h-4" />
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Connection Status Banner */}
        {error ? (
          <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-xl flex items-center justify-between text-rose-300">
            <div className="flex items-center space-x-3">
              <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0" />
              <div>
                <p className="font-semibold text-sm">Backend Engine Offline</p>
                <p className="text-xs text-rose-400/80">Make sure the FastAPI server is running at <code className="bg-rose-900/40 px-1 py-0.5 rounded">http://localhost:8000</code> ({error})</p>
              </div>
            </div>
            <button
              onClick={fetchHealth}
              className="text-xs font-semibold bg-rose-900/60 hover:bg-rose-900 border border-rose-700 px-3 py-1.5 rounded-lg transition"
            >
              Retry Connection
            </button>
          </div>
        ) : null}

        {/* View Mode Switching */}
        {activeView === 'archives' ? (
          <CaseArchives
            onSelectCase={handleSelectHistoricalCase}
            onNewScan={() => {
              setAnalysisResult(null);
              setActiveView('scanner');
            }}
          />
        ) : analysisResult ? (
          <ForensicOverview
            result={analysisResult}
            onReset={() => setAnalysisResult(null)}
          />
        ) : (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-xl font-bold text-white flex items-center gap-2">
                  <FileSearch className="w-5 h-5 text-cyan-400" />
                  Email Threat Ingestion & Investigation Workstation
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Upload an RFC 5322 .eml file or paste raw email text to trigger forensic extraction, AI intent analysis, and PDF report export.
                </p>
              </div>
              <button
                onClick={() => setActiveView('archives')}
                className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-slate-700 rounded-xl text-xs font-semibold transition"
              >
                <Archive className="w-3.5 h-3.5" />
                <span>View Stored Cases</span>
              </button>
            </div>

            {/* Email Ingestion Form (Dropzone & Raw Paste) */}
            <EmailIngestion
              onAnalysisComplete={(res) => setAnalysisResult(res)}
              isLoading={analyzing}
              setIsLoading={setAnalyzing}
            />

            {/* Platform Feature Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4">
              <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 bg-cyan-950 text-cyan-400 rounded-lg border border-cyan-800/40">
                    <Server className="w-5 h-5" />
                  </div>
                  <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800 px-2 py-0.5 rounded">
                    RFC 5322
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-white">Full Header Forensics</h4>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                  Extracts sender, recipient, subject, reply-to, message ID, and authentication results (SPF, DKIM, DMARC).
                </p>
              </div>

              <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 bg-blue-950 text-blue-400 rounded-lg border border-blue-800/40">
                    <Database className="w-5 h-5" />
                  </div>
                  <span className="text-[11px] font-mono text-blue-400 bg-blue-950/60 border border-blue-800 px-2 py-0.5 rounded">
                    SHA-256 / MD5
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-white">Chain of Custody & Archives</h4>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                  Computes cryptographic hashes of every email and archives persistent forensic cases for legal and SOC review.
                </p>
              </div>

              <div className="bg-[#0f172a] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="p-2.5 bg-purple-950 text-purple-400 rounded-lg border border-purple-800/40">
                    <FileDown className="w-5 h-5" />
                  </div>
                  <span className="text-[11px] font-mono text-purple-400 bg-purple-950/60 border border-purple-800 px-2 py-0.5 rounded">
                    PDF Export
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-white">Court-Ready PDF Reports</h4>
                <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                  Generates executive-grade PDF investigation reports with full threat metrics, explainable AI reasoning, and MTA routes.
                </p>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-[#090e1a] py-4 text-center text-xs text-slate-500">
        CyberSentinel AI • SIH Email Threat Intelligence & Forensic Platform
      </footer>
    </div>
  );
};

export default App;
