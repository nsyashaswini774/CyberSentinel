import React, { useState, useEffect } from 'react';
import {
  Archive,
  Search,
  Filter,
  FileDown,
  ExternalLink,
  Trash2,
  RefreshCw,
  MapPin,
  Clock,
  ShieldAlert,
  AlertTriangle,
  ShieldCheck,
  User,
  Inbox
} from 'lucide-react';
import type { ScanHistorySummary, EmailAnalysisResult } from '../../types';
import apiService from '../../services/api';

interface CaseArchivesProps {
  onSelectCase: (caseDetail: EmailAnalysisResult) => void;
  onNewScan: () => void;
}

export const CaseArchives: React.FC<CaseArchivesProps> = ({ onSelectCase, onNewScan }) => {
  const [cases, setCases] = useState<ScanHistorySummary[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedLevel, setSelectedLevel] = useState<string>('ALL');
  const [downloadingId, setDownloadingId] = useState<number | null>(null);
  const [openingId, setOpeningId] = useState<number | null>(null);

  const fetchCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getScanHistory(searchQuery, selectedLevel);
      setCases(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load case archives from database.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchCases();
  }, [selectedLevel]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchCases();
  };

  const handleOpenCase = async (id: number) => {
    setOpeningId(id);
    try {
      const detail = await apiService.getScanDetail(id);
      onSelectCase(detail);
    } catch (err: any) {
      alert(`Error loading case #${id}: ` + (err.response?.data?.detail || err.message));
    } finally {
      setOpeningId(null);
    }
  };

  const handleDownloadPdf = async (id: number) => {
    setDownloadingId(id);
    try {
      await apiService.downloadScanPdf(id);
    } catch (err: any) {
      alert(`Failed to download PDF for case #${id}: ` + (err.response?.data?.detail || err.message));
    } finally {
      setDownloadingId(null);
    }
  };

  const handleDeleteCase = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm(`Are you sure you want to permanently delete Case #${id}?`)) {
      return;
    }
    try {
      await apiService.deleteScan(id);
      setCases((prev) => prev.filter((c) => c.id !== id));
    } catch (err: any) {
      alert(`Failed to delete case #${id}: ` + (err.response?.data?.detail || err.message));
    }
  };

  const getThreatBadge = (level: string) => {
    switch (level) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-700/80';
      case 'HIGH':
        return 'bg-red-950/80 text-red-300 border-red-700/80';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-300 border-amber-700/80';
      case 'LOW':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-700/80';
      default:
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-700/80';
    }
  };

  const getThreatIcon = (score: number) => {
    if (score >= 50) return <ShieldAlert className="w-4 h-4 text-rose-400" />;
    if (score >= 20) return <AlertTriangle className="w-4 h-4 text-amber-400" />;
    return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'Unknown date';
    try {
      const d = new Date(dateStr);
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return dateStr;
    }
  };

  const filterTabs = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE'];

  return (
    <div className="space-y-6">
      {/* Top Banner & Action Bar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center space-x-3.5">
          <div className="p-3 bg-cyan-950/80 border border-cyan-800/80 rounded-2xl text-cyan-400 shadow-md">
            <Archive className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold text-white font-mono flex items-center gap-2">
              Historical Case Archives
              <span className="text-xs font-normal px-2.5 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                {cases.length} {cases.length === 1 ? 'Record' : 'Records'}
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Search, review, and export court-ready forensic incident reports from persistent case archives.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchCases}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 transition"
            title="Refresh case archives"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          <button
            onClick={onNewScan}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-xl text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition shadow-lg shadow-cyan-500/20"
          >
            <Inbox className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </button>
        </div>
      </div>

      {/* Search Bar and Threat Level Filter Bar */}
      <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Search Form */}
          <form onSubmit={handleSearchSubmit} className="relative flex-1 min-w-[280px]">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
            <input
              type="text"
              placeholder="Search by subject, sender, recipient, IP, SHA-256 hash, verdict..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-10 pr-24 py-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
            />
            <button
              type="submit"
              className="absolute right-2 top-2 px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold transition"
            >
              Search
            </button>
          </form>

          {/* Quick Filter Pill Buttons */}
          <div className="flex flex-wrap items-center gap-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
            <span className="text-[11px] font-mono text-slate-500 px-2 flex items-center gap-1">
              <Filter className="w-3 h-3" />
              Risk:
            </span>
            {filterTabs.map((tab) => (
              <button
                key={tab}
                onClick={() => setSelectedLevel(tab)}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition ${
                  selectedLevel === tab
                    ? 'bg-cyan-500 text-slate-950 shadow-md font-bold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
                }`}
              >
                {tab}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 bg-rose-950/60 border border-rose-800/80 rounded-2xl text-rose-300 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button
            onClick={fetchCases}
            className="underline hover:text-white font-semibold"
          >
            Retry
          </button>
        </div>
      )}

      {/* Case List View */}
      {loading ? (
        <div className="p-16 text-center text-slate-400 bg-[#0f172a] border border-slate-800 rounded-2xl space-y-3">
          <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
          <p className="text-xs font-mono">Querying historical database records...</p>
        </div>
      ) : cases.length === 0 ? (
        <div className="p-16 text-center text-slate-500 bg-[#0f172a] border border-slate-800 rounded-2xl space-y-3">
          <Archive className="w-12 h-12 text-slate-600 mx-auto" />
          <h3 className="text-sm font-bold text-slate-300 font-mono">No Investigation Cases Found</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            {searchQuery || selectedLevel !== 'ALL'
              ? 'No historical cases matched your search query or threat level filter.'
              : 'You have not scanned any emails yet. Ingest an email or run a sample test to start.'}
          </p>
          {(searchQuery || selectedLevel !== 'ALL') && (
            <button
              onClick={() => {
                setSearchQuery('');
                setSelectedLevel('ALL');
              }}
              className="mt-2 px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-xl text-xs font-semibold border border-slate-700"
            >
              Clear Filters
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          {cases.map((c) => (
            <div
              key={c.id}
              onClick={() => handleOpenCase(c.id)}
              className="group bg-[#0f172a] border border-slate-800/90 hover:border-cyan-500/50 rounded-2xl p-4 sm:p-5 shadow-lg transition duration-200 cursor-pointer flex flex-col md:flex-row md:items-center md:justify-between gap-4 hover:bg-slate-900/40"
            >
              {/* Left Column: Verdict Badge & Subject/Metadata */}
              <div className="space-y-2 flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/80 px-2.5 py-0.5 rounded-lg border border-cyan-800/80">
                    #CASE-{c.id.toString().padStart(5, '0')}
                  </span>
                  <span
                    className={`text-xs px-2.5 py-0.5 rounded-lg font-bold border flex items-center gap-1.5 ${getThreatBadge(
                      c.threat_level
                    )}`}
                  >
                    {getThreatIcon(c.threat_score)}
                    <span>
                      {c.threat_level} ({Math.round(c.threat_score)}/100)
                    </span>
                  </span>
                  <span className="text-xs font-mono text-slate-300 font-semibold">
                    {c.verdict}
                  </span>
                </div>

                <div className="min-w-0">
                  <h4 className="text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition truncate">
                    {c.subject || '(No Subject)'}
                  </h4>
                </div>

                {/* Email details row */}
                <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 font-mono">
                  <div className="flex items-center gap-1.5 truncate max-w-xs">
                    <User className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    <span className="truncate">From: <strong className="text-slate-300">{c.sender || 'Unknown'}</strong></span>
                  </div>
                  {c.origin_ip && (
                    <div className="flex items-center gap-1.5">
                      <MapPin className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span className="text-cyan-300">{c.origin_ip}</span>
                      {c.origin_country && (
                        <span className="text-slate-400">({c.origin_country})</span>
                      )}
                    </div>
                  )}
                  <div className="flex items-center gap-1.5 text-slate-500">
                    <Clock className="w-3.5 h-3.5 shrink-0" />
                    <span>{formatDate(c.created_at)}</span>
                  </div>
                </div>
              </div>

              {/* Right Column: Actions */}
              <div
                className="flex items-center space-x-2 shrink-0 border-t md:border-t-0 pt-3 md:pt-0 border-slate-800/80"
                onClick={(e) => e.stopPropagation()}
              >
                <button
                  onClick={() => handleOpenCase(c.id)}
                  disabled={openingId === c.id}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-cyan-400 rounded-xl text-xs font-semibold border border-cyan-900/60 hover:border-cyan-500/80 transition"
                  title="Open full forensic case"
                >
                  <ExternalLink className={`w-3.5 h-3.5 ${openingId === c.id ? 'animate-spin' : ''}`} />
                  <span>{openingId === c.id ? 'Loading...' : 'Open Case'}</span>
                </button>

                <button
                  onClick={() => handleDownloadPdf(c.id)}
                  disabled={downloadingId === c.id}
                  className="flex items-center space-x-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 rounded-xl text-xs font-semibold border border-slate-700 hover:border-slate-500 transition"
                  title="Export official forensic investigation PDF report"
                >
                  <FileDown className={`w-3.5 h-3.5 text-rose-400 ${downloadingId === c.id ? 'animate-bounce' : ''}`} />
                  <span>{downloadingId === c.id ? 'Generating...' : 'PDF'}</span>
                </button>

                <button
                  onClick={(e) => handleDeleteCase(c.id, e)}
                  className="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-950/50 rounded-xl border border-transparent hover:border-rose-900/60 transition"
                  title="Delete case record"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default CaseArchives;
