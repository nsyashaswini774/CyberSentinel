import React, { useState } from 'react';
import { 
  FileCheck2, 
  FileDown, 
  Copy, 
  Check, 
  X, 
  ShieldCheck, 
  Hash, 
  Download,
  ExternalLink,
  Layers
} from 'lucide-react';
import type { EmailAnalysisResult } from '../../types';
import { apiService } from '../../services/api';

interface ReportCenterModalProps {
  isOpen: boolean;
  onClose: () => void;
  result: EmailAnalysisResult;
}

export const ReportCenterModal: React.FC<ReportCenterModalProps> = ({
  isOpen,
  onClose,
  result,
}) => {
  const [downloadingPdf, setDownloadingPdf] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  if (!isOpen) return null;

  const caseRef = `CASE-VA-${(result.scan_id || 1001).toString().padStart(5, '0')}`;

  const handleDownloadPdf = async () => {
    setDownloadingPdf(true);
    try {
      if (result.scan_id) {
        await apiService.downloadScanPdf(result.scan_id);
      } else {
        await apiService.exportCurrentScanPdf(result);
      }
    } catch (err: any) {
      alert('Failed to generate PDF report: ' + (err.response?.data?.detail || err.message));
    } finally {
      setDownloadingPdf(false);
    }
  };

  const handleExportJson = () => {
    const jsonStr = JSON.stringify(result, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `VYUHA_Evidence_${caseRef}_${(result.sha256 || 'hash').slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(label);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl glass-panel-elevated rounded-3xl p-6 sm:p-8 border border-cyan-500/30 shadow-2xl space-y-6">
        {/* Close Button */}
        <button
          onClick={onClose}
          className="absolute top-6 right-6 p-2 rounded-xl text-slate-400 hover:text-white hover:bg-slate-800 transition"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center space-x-3.5 border-b border-slate-800 pb-5">
          <div className="p-3 rounded-2xl bg-gradient-to-tr from-cyan-950 to-blue-900 border border-cyan-500/40 text-cyan-400 shadow-lg shadow-cyan-950/50">
            <FileCheck2 className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold font-mono text-white">FORENSIC REPORT CENTER</h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                COURT-READY
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-sans">
              Cryptographically verified email threat dossier and evidentiary chain-of-custody export
            </p>
          </div>
        </div>

        {/* Case Metadata Summary Box */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 block">CASE REFERENCE</span>
            <span className="font-bold text-cyan-400 block mt-0.5">{caseRef}</span>
          </div>

          <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 block">THREAT INDEX</span>
            <span className="font-bold text-white block mt-0.5">{Math.round(result.threat.score)} / 100</span>
          </div>

          <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 block">RISK LEVEL</span>
            <span className={`font-bold block mt-0.5 ${
              result.threat.score >= 50 ? 'text-rose-400' : 'text-emerald-400'
            }`}>
              {result.threat.level}
            </span>
          </div>

          <div className="p-3 bg-slate-900/80 rounded-xl border border-slate-800">
            <span className="text-[10px] text-slate-500 block">VERIFIED HOPS</span>
            <span className="font-bold text-slate-200 block mt-0.5">{result.hops.length} MTAs</span>
          </div>
        </div>

        {/* Cryptographic Chain of Custody Integrity Seal */}
        <div className="p-4 rounded-2xl bg-slate-950/90 border border-slate-800/90 space-y-2.5">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span className="flex items-center gap-1.5 font-bold text-slate-300">
              <Hash className="w-3.5 h-3.5 text-cyan-400" />
              Cryptographic Integrity Hashes (RFC 5322 Payload)
            </span>
            <span className="text-[10px] text-emerald-400 flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5" />
              Chain of Custody Sealed
            </span>
          </div>

          {/* SHA-256 */}
          <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/70 border border-slate-800 text-xs font-mono">
            <div className="flex items-center space-x-2 truncate">
              <span className="text-slate-500 text-[10px]">SHA-256:</span>
              <span className="text-cyan-300 text-[11px] truncate select-all">{result.sha256}</span>
            </div>
            <button
              onClick={() => copyToClipboard(result.sha256, 'sha256')}
              className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 shrink-0 ml-2 transition"
              title="Copy SHA-256 hash"
            >
              {copiedHash === 'sha256' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>

          {/* MD5 */}
          <div className="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/70 border border-slate-800 text-xs font-mono">
            <div className="flex items-center space-x-2 truncate">
              <span className="text-slate-500 text-[10px]">MD5:</span>
              <span className="text-slate-300 text-[11px] truncate select-all">{result.md5}</span>
            </div>
            <button
              onClick={() => copyToClipboard(result.md5, 'md5')}
              className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 shrink-0 ml-2 transition"
              title="Copy MD5 hash"
            >
              {copiedHash === 'md5' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Actions Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
          <button
            onClick={handleDownloadPdf}
            disabled={downloadingPdf}
            className="flex items-center justify-center space-x-2 px-5 py-3.5 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold rounded-xl text-xs shadow-lg shadow-cyan-500/20 transition-all duration-300 hover:scale-[1.02] disabled:opacity-50"
          >
            <FileDown className={`w-4 h-4 text-slate-950 ${downloadingPdf ? 'animate-bounce' : ''}`} />
            <span>{downloadingPdf ? 'Generating Official PDF...' : 'Download Official PDF Report'}</span>
          </button>

          <button
            onClick={handleExportJson}
            className="flex items-center justify-center space-x-2 px-5 py-3.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 hover:border-cyan-500/40 font-semibold rounded-xl text-xs shadow-md transition"
          >
            <Download className="w-4 h-4 text-cyan-400" />
            <span>Export Raw Forensic JSON Dossier</span>
          </button>
        </div>

        <p className="text-[10px] text-slate-500 text-center leading-normal">
          Official reports are generated by the VYUHA AI Forensic Engine. All evidentiary timestamps and RFC headers are preserved for SOC auditing and law enforcement admissibility.
        </p>
      </div>
    </div>
  );
};

export default ReportCenterModal;
