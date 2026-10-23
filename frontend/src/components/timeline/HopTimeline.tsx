import { 
  Clock, 
  MapPin, 
  Network,
  Layers
} from 'lucide-react';
import type { HopGeolocation } from '../../types';

interface HopTimelineProps {
  hops: HopGeolocation[];
}

export const HopTimeline: React.FC<HopTimelineProps> = ({ hops }) => {
  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            Email Transmission Timeline & Routing Sequence
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Chronological inspection of intermediate Mail Transfer Agents (MTAs) and calculated transit delays.
          </p>
        </div>
        <div className="flex items-center space-x-2 text-xs font-mono bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-xl">
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-300">Total Relay Hops: {hops.length}</span>
        </div>
      </div>

      {hops.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs">
          No Received: headers available in this message payload to construct transmission timeline.
        </div>
      ) : (
        <div className="relative pl-6 space-y-6 before:absolute before:left-3 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-rose-500 before:via-cyan-500 before:to-emerald-500">
          {hops.map((hop, idx) => {
            const isFirst = idx === 0;
            const isLast = idx === hops.length - 1;

            return (
              <div key={hop.hop_index} className="relative group">
                {/* Node Bullet Marker */}
                <div
                  className={`absolute -left-6 top-1.5 w-6 h-6 rounded-full flex items-center justify-center font-mono text-[10px] font-bold border-2 shadow-lg transition ${
                    isFirst
                      ? 'bg-rose-950 border-rose-500 text-rose-300 shadow-rose-900/50'
                      : isLast
                      ? 'bg-emerald-950 border-emerald-500 text-emerald-300 shadow-emerald-900/50'
                      : 'bg-[#0a0e17] border-cyan-500 text-cyan-300 shadow-cyan-900/50'
                  }`}
                >
                  {hop.hop_index}
                </div>

                {/* Content Card */}
                <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-5 hover:border-slate-700 transition space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold text-white font-mono">
                        {isFirst ? 'Origin Sender Gateway' : isLast ? 'Destination Mailbox MX' : `Relay Hop #${hop.hop_index}`}
                      </span>
                      {hop.is_private ? (
                        <span className="text-[10px] bg-slate-800 text-slate-400 border border-slate-700 px-2 py-0.5 rounded font-mono">
                          RFC 1918 Private LAN
                        </span>
                      ) : (
                        <span className="text-[10px] bg-cyan-950 text-cyan-400 border border-cyan-800 px-2 py-0.5 rounded font-mono">
                          Public Internet
                        </span>
                      )}
                    </div>

                    {/* Transit Delay Badge */}
                    {hop.delay_seconds !== undefined && hop.delay_seconds !== null && (
                      <div className="flex items-center space-x-1.5 text-[11px] font-mono bg-slate-950 px-2.5 py-1 rounded-lg border border-slate-800 text-slate-300">
                        <Clock className="w-3 h-3 text-cyan-400" />
                        <span>+{hop.delay_seconds}s transit delay</span>
                      </div>
                    )}
                  </div>

                  {/* Hop Details Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                    <div className="bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 font-mono block">IP ADDRESS</span>
                      <span className="font-mono text-cyan-300 font-semibold mt-0.5 block">{hop.ip}</span>
                    </div>

                    <div className="bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 font-mono block">GEOLOCATION</span>
                      <span className="font-semibold text-slate-200 mt-0.5 flex items-center gap-1">
                        <MapPin className="w-3 h-3 text-cyan-400 shrink-0" />
                        {hop.city ? `${hop.city}, ` : ''}{hop.country || 'Unknown'}
                      </span>
                    </div>

                    <div className="bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 font-mono block">HOST / MTA</span>
                      <span className="font-mono text-slate-300 mt-0.5 block truncate" title={hop.hostname || 'Unspecified'}>
                        {hop.hostname || 'Unspecified'}
                      </span>
                    </div>

                    <div className="bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                      <span className="text-[10px] text-slate-500 font-mono block">RECEIVING AGENT (BY)</span>
                      <span className="font-mono text-slate-300 mt-0.5 block truncate" title={hop.by || 'Destination'}>
                        {hop.by || 'Destination'}
                      </span>
                    </div>
                  </div>

                  {/* ISP & Protocol Footer */}
                  <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/60 text-[11px] font-mono text-slate-400">
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-500">ISP / Network:</span>
                      <span className="text-slate-300">{hop.isp || 'Local Routing Infrastructure'}</span>
                    </div>
                    {hop.timestamp && (
                      <div className="text-slate-500">
                        {hop.timestamp}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default HopTimeline;
