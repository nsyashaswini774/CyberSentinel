import React, { useState } from 'react';
import { 
  Link2, 
  AlertTriangle, 
  Scissors, 
  EyeOff, 
  Search,
  Filter,
  ShieldAlert,
  Activity,
  Server,
  Lock,
  Unlock,
  Target
} from 'lucide-react';
import type { ExtractedUrl } from '../../types';

interface UrlThreatIntelProps {
  urls: ExtractedUrl[];
}

export const UrlThreatIntel: React.FC<UrlThreatIntelProps> = ({ urls }) => {
  const [filter, setFilter] = useState<string>('');
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState<boolean>(false);

  // Metrics calculation
  const totalCount = urls.length;
  const suspiciousCount = urls.filter((u) => u.is_suspicious).length;
  const shortenerCount = urls.filter((u) => u.is_shortener).length;
  const homographCount = urls.filter((u) => u.has_homograph).length;
  const typoCount = urls.filter((u) => u.reputation?.typosquatting_detected).length;
  const dgaCount = urls.filter((u) => u.reputation?.is_high_entropy).length;
  const highAbuseTldCount = urls.filter((u) => u.reputation?.tld_reputation_tier === 'High-Abuse').length;
  const mismatchedCount = urls.filter((u) =>
    u.reasons.some((r) => r.toLowerCase().includes('anchor text displays'))
  ).length;

  const filteredUrls = urls.filter((u) => {
    const matchesText =
      u.url.toLowerCase().includes(filter.toLowerCase()) ||
      u.domain.toLowerCase().includes(filter.toLowerCase()) ||
      (u.anchor_text && u.anchor_text.toLowerCase().includes(filter.toLowerCase())) ||
      (u.threat_category && u.threat_category.toLowerCase().includes(filter.toLowerCase())) ||
      (u.reputation?.impersonated_brand && u.reputation.impersonated_brand.toLowerCase().includes(filter.toLowerCase())) ||
      u.reasons.some((r) => r.toLowerCase().includes(filter.toLowerCase()));

    if (showSuspiciousOnly) {
      return matchesText && u.is_suspicious;
    }
    return matchesText;
  });

  const getRiskScoreColor = (score?: number) => {
    if (!score || score < 25) return 'text-emerald-400 border-emerald-800 bg-emerald-950/60';
    if (score < 50) return 'text-amber-400 border-amber-800 bg-amber-950/60';
    if (score < 75) return 'text-red-400 border-red-800 bg-red-950/60';
    return 'text-rose-400 border-rose-800 bg-rose-950/80';
  };

  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
      {/* Header & Metrics Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <Link2 className="w-4 h-4 text-cyan-400" />
            URL & Domain Threat Intelligence Matrix
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Deep forensic inspection of embedded hyperlinks, Shannon entropy (DGA), typosquatting, brand spoofing, and abusive TLDs.
          </p>
        </div>

        {/* Quick Threat Metric Pills */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <span className="px-2.5 py-1 bg-slate-900 border border-slate-800 rounded-lg text-slate-300">
            Total URLs: <strong className="text-white">{totalCount}</strong>
          </span>
          <span className="px-2.5 py-1 bg-rose-950/50 border border-rose-800/80 rounded-lg text-rose-300">
            Suspicious: <strong className="text-rose-400">{suspiciousCount}</strong>
          </span>
          {typoCount > 0 && (
            <span className="px-2.5 py-1 bg-red-950/60 border border-red-700/80 rounded-lg text-red-300 flex items-center gap-1">
              <Target className="w-3 h-3 text-red-400" />
              Typosquatting: <strong>{typoCount}</strong>
            </span>
          )}
          {dgaCount > 0 && (
            <span className="px-2.5 py-1 bg-amber-950/60 border border-amber-700/80 rounded-lg text-amber-300 flex items-center gap-1">
              <Activity className="w-3 h-3 text-amber-400" />
              High Entropy/DGA: <strong>{dgaCount}</strong>
            </span>
          )}
          {highAbuseTldCount > 0 && (
            <span className="px-2.5 py-1 bg-orange-950/60 border border-orange-700/80 rounded-lg text-orange-300 flex items-center gap-1">
              <Server className="w-3 h-3 text-orange-400" />
              Abusive TLD: <strong>{highAbuseTldCount}</strong>
            </span>
          )}
          {shortenerCount > 0 && (
            <span className="px-2.5 py-1 bg-purple-950/50 border border-purple-800/80 rounded-lg text-purple-300 flex items-center gap-1">
              <Scissors className="w-3 h-3" />
              Shorteners: {shortenerCount}
            </span>
          )}
          {homographCount > 0 && (
            <span className="px-2.5 py-1 bg-red-950/50 border border-red-800/80 rounded-lg text-red-300 flex items-center gap-1">
              <EyeOff className="w-3 h-3" />
              Homographs: {homographCount}
            </span>
          )}
          {mismatchedCount > 0 && (
            <span className="px-2.5 py-1 bg-amber-950/50 border border-amber-800/80 rounded-lg text-amber-300 flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" />
              Mismatched: {mismatchedCount}
            </span>
          )}
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search URLs, domains, brands, reasons, or anchor text..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="w-full bg-slate-900 border border-slate-700/80 rounded-xl pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <button
          onClick={() => setShowSuspiciousOnly(!showSuspiciousOnly)}
          className={`flex items-center space-x-1.5 px-3.5 py-2 rounded-xl text-xs font-semibold border transition ${
            showSuspiciousOnly
              ? 'bg-rose-950/80 border-rose-700 text-rose-300'
              : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-slate-200'
          }`}
        >
          <Filter className="w-3.5 h-3.5" />
          <span>{showSuspiciousOnly ? 'Showing Suspicious Only' : 'Filter Suspicious'}</span>
        </button>
      </div>

      {/* URL Intelligence List */}
      {filteredUrls.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs bg-slate-950/40 rounded-xl border border-slate-800">
          No URLs found matching current search filter.
        </div>
      ) : (
        <div className="divide-y divide-slate-800/80">
          {filteredUrls.map((item, idx) => (
            <div
              key={idx}
              className="py-4 space-y-3 hover:bg-slate-900/30 p-3 rounded-xl transition"
            >
              {/* Badges & Domain Row */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`font-mono text-xs px-2.5 py-0.5 rounded border font-bold ${getRiskScoreColor(
                      item.risk_score
                    )}`}
                  >
                    Risk Score: {item.risk_score ?? 0}
                  </span>
                  {item.threat_category && item.threat_category !== 'Benign' && (
                    <span className="text-[11px] font-mono px-2.5 py-0.5 bg-rose-950/80 text-rose-300 rounded border border-rose-800 flex items-center gap-1">
                      <ShieldAlert className="w-3 h-3" />
                      {item.threat_category}
                    </span>
                  )}
                  {item.reputation?.typosquatting_detected && item.reputation.impersonated_brand && (
                    <span className="text-[11px] font-mono px-2 py-0.5 bg-red-950 text-red-300 rounded border border-red-700 flex items-center gap-1">
                      <Target className="w-3 h-3 text-red-400" />
                      Spoofs: {item.reputation.impersonated_brand}
                    </span>
                  )}
                  {item.reputation?.is_high_entropy && (
                    <span className="text-[11px] font-mono px-2 py-0.5 bg-amber-950 text-amber-300 rounded border border-amber-700 flex items-center gap-1">
                      <Activity className="w-3 h-3 text-amber-400" />
                      DGA (Entropy: {item.reputation.entropy})
                    </span>
                  )}
                  {item.is_shortener && (
                    <span className="text-[11px] font-mono px-2 py-0.5 bg-purple-950 text-purple-300 rounded border border-purple-800 flex items-center gap-1">
                      <Scissors className="w-3 h-3" />
                      Shortener
                    </span>
                  )}
                  {item.has_homograph && (
                    <span className="text-[11px] font-mono px-2 py-0.5 bg-red-950 text-red-300 rounded border border-red-800 flex items-center gap-1">
                      <EyeOff className="w-3 h-3" />
                      Homograph
                    </span>
                  )}
                </div>

                <div className="flex items-center space-x-2">
                  {item.reputation && (
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        item.reputation.tld_reputation_tier === 'High-Abuse'
                          ? 'bg-rose-950/70 text-rose-300 border-rose-800'
                          : item.reputation.tld_reputation_tier === 'Trusted'
                          ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800'
                          : 'bg-slate-900 text-slate-400 border-slate-800'
                      }`}
                    >
                      TLD Tier: {item.reputation.tld_reputation_tier}
                    </span>
                  )}
                  <span className="text-xs font-mono text-slate-400 bg-slate-950 px-2 py-1 rounded border border-slate-800">
                    Domain: <strong className="text-cyan-400">{item.domain}</strong>
                  </span>
                </div>
              </div>

              {/* URL & Anchor text comparison */}
              <div className="space-y-1.5 bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <div className="flex items-start space-x-2 text-xs font-mono break-all text-slate-200">
                  <span className="text-slate-500 shrink-0 select-none">URL:</span>
                  <span className="select-all text-cyan-300">{item.url}</span>
                </div>

                {item.anchor_text && (
                  <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
                    <span className="text-slate-500 select-none">Anchor Text:</span>
                    <span className="bg-slate-900 px-2 py-0.5 rounded border border-slate-700 text-slate-300">
                      "{item.anchor_text}"
                    </span>
                    {item.reasons.some((r) => r.includes('Anchor text displays')) && (
                      <span className="text-rose-400 text-[11px] font-bold flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        DECEPTIVE ANCHOR MISMATCH
                      </span>
                    )}
                  </div>
                )}

                {/* Protocol and Entropy details */}
                {item.reputation && (
                  <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono text-slate-400 border-t border-slate-800/60 mt-2">
                    <span className="flex items-center gap-1">
                      {item.reputation.protocol_risk.includes('Insecure') ? (
                        <Unlock className="w-3 h-3 text-amber-400" />
                      ) : (
                        <Lock className="w-3 h-3 text-emerald-400" />
                      )}
                      <span>Protocol: {item.reputation.protocol_risk}</span>
                    </span>
                    <span>•</span>
                    <span>Shannon Entropy: <strong className="text-slate-200">{item.reputation.entropy}</strong></span>
                    <span>•</span>
                    <span>Verdict: <strong className={item.reputation.reputation_verdict === 'High Risk' ? 'text-rose-400' : 'text-slate-300'}>{item.reputation.reputation_verdict}</strong></span>
                  </div>
                )}
              </div>

              {/* Reasons Breakdown */}
              {item.reasons.length > 0 && (
                <div className="pt-1 space-y-1">
                  {item.reasons.map((r, rIdx) => (
                    <div
                      key={rIdx}
                      className="text-[11px] text-rose-300 flex items-start space-x-1.5"
                    >
                      <span className="text-rose-500">•</span>
                      <span>{r}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default UrlThreatIntel;

