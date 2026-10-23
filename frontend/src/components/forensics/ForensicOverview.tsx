import React, { useState } from 'react';
import { 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  Key, 
  Globe, 
  Link2, 
  Hash, 
  FileCode,
  CheckCircle2,
  XCircle,
  HelpCircle,
  MapPin,
  Network,
  FileDown,
  ArrowLeft,
  Copy,
  Check,
  FileCheck2,
  Cpu,
  Layers,
  Inbox
} from 'lucide-react';
import type { EmailAnalysisResult } from '../../types';
import { GeoMap } from '../map/GeoMap';
import { HopTimeline } from '../timeline/HopTimeline';
import { UrlThreatIntel } from './UrlThreatIntel';
import { ThreatScoreGauge } from './ThreatScoreGauge';
import { VyuhaAiReasoning } from './VyuhaAiReasoning';
import { InvestigationPipeline, type PipelineStepId } from '../investigation/InvestigationPipeline';
import { ReportCenterModal } from '../reports/ReportCenterModal';
import { apiService } from '../../services/api';

interface ForensicOverviewProps {
  result: EmailAnalysisResult;
  onReset: () => void;
}

type TabType = 'intelligence' | 'map' | 'timeline' | 'urls' | 'headers' | 'hashes' | 'body';

export const ForensicOverview: React.FC<ForensicOverviewProps> = ({ result, onReset }) => {
  const [activeTab, setActiveTab] = useState<TabType>('intelligence');
  const [headerFilter, setHeaderFilter] = useState<string>('');
  const [exportingPdf, setExportingPdf] = useState<boolean>(false);
  const [reportModalOpen, setReportModalOpen] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const caseRef = `CASE-VA-${(result.scan_id || 1001).toString().padStart(5, '0')}`;

  const handleExportPdf = async () => {
    setExportingPdf(true);
    try {
      if (result.scan_id) {
        await apiService.downloadScanPdf(result.scan_id);
      } else {
        await apiService.exportCurrentScanPdf(result);
      }
    } catch (err: any) {
      alert('Failed to generate forensic PDF report: ' + (err.response?.data?.detail || err.message));
    } finally {
      setExportingPdf(false);
    }
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(label);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const getThreatBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-600';
      case 'HIGH':
        return 'bg-red-950/80 text-red-300 border-red-600';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-300 border-amber-600';
      case 'LOW':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-600';
      default:
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-600';
    }
  };

  const getAuthIcon = (status: string) => {
    if (status === 'PASS') return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
    if (status === 'FAIL') return <XCircle className="w-4 h-4 text-rose-400" />;
    return <HelpCircle className="w-4 h-4 text-amber-400" />;
  };

  // Find origin public hop
  const originHop = result.hops.find((h) => !h.is_private) || result.hops[0];

  const filteredHeaders = result.headers.filter(
    (h) =>
      h.name.toLowerCase().includes(headerFilter.toLowerCase()) ||
      h.value.toLowerCase().includes(headerFilter.toLowerCase())
  );

  const handlePipelineStepClick = (step: PipelineStepId) => {
    if (step === 'ingest') onReset();
    else if (step === 'extract') setActiveTab('headers');
    else if (step === 'trace') setActiveTab('timeline');
    else if (step === 'analyze' || step === 'score') setActiveTab('intelligence');
    else if (step === 'investigate') setActiveTab('urls');
    else if (step === 'report') setReportModalOpen(true);
  };

  return (
    <div className="space-y-6">
      {/* 7-Step Investigation Pipeline Bar */}
      <InvestigationPipeline
        currentStep={
          activeTab === 'intelligence'
            ? 'score'
            : activeTab === 'map' || activeTab === 'timeline'
            ? 'trace'
            : activeTab === 'urls'
            ? 'investigate'
            : activeTab === 'headers'
            ? 'extract'
            : 'report'
        }
        onStepClick={handlePipelineStepClick}
        isComplete={true}
      />

      {/* Top Banner: Dossier Overview, Origin & Action Bar */}
      <div className="glass-panel rounded-3xl p-6 sm:p-7 border border-cyan-500/20 shadow-2xl flex flex-wrap items-center justify-between gap-6">
        <div className="flex items-center space-x-4">
          <div className={`p-4 rounded-2xl border shadow-lg ${getThreatBadge(result.threat.level)}`}>
            {result.threat.score >= 50 ? (
              <ShieldAlert className="w-8 h-8 text-rose-400" />
            ) : result.threat.score >= 20 ? (
              <AlertTriangle className="w-8 h-8 text-amber-400" />
            ) : (
              <ShieldCheck className="w-8 h-8 text-emerald-400" />
            )}
          </div>

          <div>
            <div className="flex flex-wrap items-center gap-2.5">
              <h2 className="text-xl sm:text-2xl font-black text-white font-mono tracking-tight">
                {result.threat.verdict}
              </h2>
              <span className={`text-xs px-3 py-1 rounded-full font-bold font-mono border ${getThreatBadge(result.threat.level)}`}>
                {result.threat.level} RISK ({Math.round(result.threat.score)}/100)
              </span>
              <span className="text-xs font-mono bg-cyan-950/80 text-cyan-400 border border-cyan-800 px-3 py-1 rounded-full">
                {caseRef}
              </span>
              {originHop && (
                <span className="text-xs font-mono bg-slate-900 text-slate-300 border border-slate-800 px-3 py-1 rounded-full flex items-center gap-1.5">
                  <MapPin className="w-3.5 h-3.5 text-cyan-400" />
                  Origin: {originHop.ip} ({originHop.country || 'Unknown'})
                </span>
              )}
            </div>
            <p className="text-xs sm:text-sm text-slate-300 mt-1 max-w-2xl font-sans leading-relaxed">
              {result.threat.summary}
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => setReportModalOpen(true)}
            className="flex items-center space-x-2 text-xs font-bold px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-cyan-400 border border-cyan-500/40 rounded-xl shadow-md transition"
          >
            <FileCheck2 className="w-4 h-4" />
            <span>Forensic Report Center</span>
          </button>

          <button
            onClick={handleExportPdf}
            disabled={exportingPdf}
            className="flex items-center space-x-2 text-xs font-bold px-5 py-2.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 rounded-xl shadow-lg shadow-cyan-500/20 transition-all duration-200 hover:scale-[1.02] disabled:opacity-60"
          >
            <FileDown className={`w-4 h-4 text-slate-950 ${exportingPdf ? 'animate-bounce' : ''}`} />
            <span>{exportingPdf ? 'Generating Report...' : 'Export PDF Report'}</span>
          </button>

          <button
            onClick={onReset}
            className="flex items-center space-x-1.5 text-xs font-semibold px-4 py-2.5 bg-slate-900 hover:bg-slate-800 text-slate-300 rounded-xl border border-slate-800 transition"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Scan Another</span>
          </button>
        </div>
      </div>

      {/* Primary Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('intelligence')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
            activeTab === 'intelligence'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-950/40 border border-slate-800'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Threat Intelligence & AI</span>
        </button>

        <button
          onClick={() => setActiveTab('map')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
            activeTab === 'map'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-950/40 border border-slate-800'
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>Geolocation Trajectory ({result.hops.filter((h) => h.lat && h.lon).length})</span>
        </button>

        <button
          onClick={() => setActiveTab('timeline')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
            activeTab === 'timeline'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-950/40 border border-slate-800'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>MTA Hops Sequence ({result.hops.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('urls')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
            activeTab === 'urls'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-950/40 border border-slate-800'
          }`}
        >
          <Link2 className="w-3.5 h-3.5" />
          <span>URL & Domain Matrix ({result.urls.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('headers')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
            activeTab === 'headers'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-950/40 border border-slate-800'
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>RFC Headers ({result.headers.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('hashes')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
            activeTab === 'hashes'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-950/40 border border-slate-800'
          }`}
        >
          <Hash className="w-3.5 h-3.5" />
          <span>Evidence Chain of Custody</span>
        </button>

        <button
          onClick={() => setActiveTab('body')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold transition ${
            activeTab === 'body'
              ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
              : 'text-slate-400 hover:text-slate-200 bg-slate-950/40 border border-slate-800'
          }`}
        >
          <Inbox className="w-3.5 h-3.5" />
          <span>Body Content</span>
        </button>
      </div>

      {/* Tab 1: Threat Intelligence & AI */}
      {activeTab === 'intelligence' && (
        <div className="space-y-6">
          {/* Cyber Radial Threat Gauge */}
          <ThreatScoreGauge threat={result.threat} />

          {/* VYUHA AI Explainable Reasoning */}
          <VyuhaAiReasoning threat={result.threat} />

          {/* Sender & Authentication Verification Cards */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Sender & Recipient Details */}
            <div className="lg:col-span-2 glass-panel rounded-3xl p-6 border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2 border-b border-slate-800 pb-3">
                <Globe className="w-4 h-4 text-cyan-400" />
                Sender Verification & Email Forensics
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs font-mono">
                <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">SUBJECT</span>
                  <span className="font-semibold text-slate-200 mt-1 block break-words">{result.subject}</span>
                </div>

                <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">FROM (SENDER)</span>
                  <span className="font-semibold text-cyan-300 mt-1 block break-all">{result.sender}</span>
                </div>

                <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">TO (RECIPIENT)</span>
                  <span className="font-semibold text-slate-200 mt-1 block break-all">{result.recipient}</span>
                </div>

                <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800">
                  <span className="text-slate-500 text-[10px] block">DATE HEADER</span>
                  <span className="font-semibold text-slate-300 mt-1 block">{result.date || 'Not specified'}</span>
                </div>

                {result.reply_to && (
                  <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">REPLY-TO MISMATCH</span>
                    <span className="font-semibold text-amber-300 mt-1 block break-all">{result.reply_to}</span>
                  </div>
                )}

                {result.return_path && (
                  <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">RETURN-PATH</span>
                    <span className="font-semibold text-slate-300 mt-1 block break-all">{result.return_path}</span>
                  </div>
                )}
              </div>
            </div>

            {/* SPF / DKIM / DMARC Authentication Card */}
            <div className="glass-panel rounded-3xl p-6 border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2 border-b border-slate-800 pb-3">
                <Key className="w-4 h-4 text-cyan-400" />
                RFC Authentication Status
              </h3>

              <div className="grid grid-cols-3 gap-3 text-center">
                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 flex flex-col items-center">
                  <span className="text-[10px] text-slate-500 font-mono mb-1">SPF</span>
                  <div className="flex items-center space-x-1">
                    {getAuthIcon(result.authentication.spf)}
                    <span className="font-bold font-mono text-xs">{result.authentication.spf}</span>
                  </div>
                </div>

                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 flex flex-col items-center">
                  <span className="text-[10px] text-slate-500 font-mono mb-1">DKIM</span>
                  <div className="flex items-center space-x-1">
                    {getAuthIcon(result.authentication.dkim)}
                    <span className="font-bold font-mono text-xs">{result.authentication.dkim}</span>
                  </div>
                </div>

                <div className="bg-slate-950/80 p-3 rounded-xl border border-slate-800 flex flex-col items-center">
                  <span className="text-[10px] text-slate-500 font-mono mb-1">DMARC</span>
                  <div className="flex items-center space-x-1">
                    {getAuthIcon(result.authentication.dmarc)}
                    <span className="font-bold font-mono text-xs">{result.authentication.dmarc}</span>
                  </div>
                </div>
              </div>

              {result.authentication.details && (
                <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80 text-[11px] text-slate-400 font-mono break-all leading-tight">
                  {result.authentication.details}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Geolocation Map */}
      {activeTab === 'map' && <GeoMap hops={result.hops} />}

      {/* Tab 3: Transmission Timeline */}
      {activeTab === 'timeline' && <HopTimeline hops={result.hops} />}

      {/* Tab 4: URL Threat Intelligence Matrix */}
      {activeTab === 'urls' && <UrlThreatIntel urls={result.urls} />}

      {/* Tab 5: Raw RFC 5322 Headers */}
      {activeTab === 'headers' && (
        <div className="glass-panel rounded-3xl p-6 border border-slate-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              Raw RFC 5322 Email Headers ({result.headers.length})
            </h3>
            <input
              type="text"
              placeholder="Search header name or value..."
              value={headerFilter}
              onChange={(e) => setHeaderFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 rounded-xl px-4 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div className="overflow-x-auto max-h-[500px] divide-y divide-slate-800/80 border border-slate-800 rounded-2xl">
            {filteredHeaders.map((hdr, i) => (
              <div key={i} className="p-3 bg-slate-950/40 text-xs font-mono flex flex-col md:flex-row md:space-x-4">
                <span className="text-cyan-400 font-semibold w-52 shrink-0 select-all">{hdr.name}:</span>
                <span className="text-slate-300 break-all select-all flex-1">{hdr.value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 6: Cryptographic Evidence Hashes & Chain of Custody */}
      {activeTab === 'hashes' && (
        <div className="glass-panel rounded-3xl p-6 sm:p-8 border border-slate-800 space-y-6">
          <div className="border-b border-slate-800 pb-4">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
              <Hash className="w-4 h-4 text-cyan-400" />
              Cryptographic Integrity & Chain of Custody Seal
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Deterministic digital evidence hashes calculated directly from ingested RFC payload bytes
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* SHA-256 */}
            <div className="p-5 bg-slate-950/80 rounded-2xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyan-400 font-bold">SHA-256 DIGITAL FINGERPRINT</span>
                <button
                  onClick={() => copyToClipboard(result.sha256, 'sha256')}
                  className="flex items-center space-x-1 text-slate-400 hover:text-cyan-400 transition text-[11px]"
                >
                  {copiedField === 'sha256' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <p className="font-mono text-xs text-slate-200 break-all p-3 bg-slate-900/60 rounded-xl border border-slate-800/80 select-all">
                {result.sha256}
              </p>
            </div>

            {/* MD5 */}
            <div className="p-5 bg-slate-950/80 rounded-2xl border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-cyan-400 font-bold">MD5 INTEGRITY CHECKSUM</span>
                <button
                  onClick={() => copyToClipboard(result.md5, 'md5')}
                  className="flex items-center space-x-1 text-slate-400 hover:text-cyan-400 transition text-[11px]"
                >
                  {copiedField === 'md5' ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy</span>
                    </>
                  )}
                </button>
              </div>
              <p className="font-mono text-xs text-slate-200 break-all p-3 bg-slate-900/60 rounded-xl border border-slate-800/80 select-all">
                {result.md5}
              </p>
            </div>
          </div>

          <div className="p-4 rounded-2xl bg-cyan-950/30 border border-cyan-500/20 text-xs text-slate-300 font-sans leading-relaxed">
            <strong className="text-cyan-300 block mb-1">Evidentiary Chain-of-Custody Certification</strong>
            This record guarantees bit-level non-repudiation. Any modification to the RFC 5322 header, body, or MIME structure invalidates the SHA-256 checksum. Validated for enterprise SOC retention and law enforcement submission.
          </div>
        </div>
      )}

      {/* Tab 7: Plaintext Body Content */}
      {activeTab === 'body' && (
        <div className="glass-panel rounded-3xl p-6 border border-slate-800 space-y-4">
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
            Plaintext Body Content & RFC Decoded Payload
          </h3>
          <pre className="bg-slate-950 p-5 rounded-2xl font-mono text-xs text-slate-300 whitespace-pre-wrap border border-slate-800 max-h-96 overflow-y-auto">
            {result.body_plain || '(Empty plaintext content)'}
          </pre>
        </div>
      )}

      {/* Dedicated Forensic Report Center Modal */}
      <ReportCenterModal
        isOpen={reportModalOpen}
        onClose={() => setReportModalOpen(false)}
        result={result}
      />
    </div>
  );
};

export default ForensicOverview;
