import React, { useMemo } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { Globe, MapPin, Server } from 'lucide-react';
import type { HopGeolocation } from '../../types';

interface GeoMapProps {
  hops: HopGeolocation[];
}

// Helper to create glowing cyber pin icons with hop numbers
const createCyberMarkerIcon = (hopIndex: number, isOrigin: boolean) => {
  const bgColor = isOrigin ? '#ef4444' : '#06b6d4';
  const shadowColor = isOrigin ? 'rgba(239, 68, 68, 0.6)' : 'rgba(6, 182, 212, 0.6)';

  return L.divIcon({
    className: 'custom-cyber-marker',
    html: `
      <div style="
        position: relative;
        width: 32px;
        height: 32px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        background-color: #0d1527;
        border: 2px solid ${bgColor};
        box-shadow: 0 0 12px ${shadowColor};
        color: white;
        font-family: monospace;
        font-size: 11px;
        font-weight: bold;
      ">
        <span>#${hopIndex}</span>
        <div style="
          position: absolute;
          bottom: -4px;
          width: 8px;
          height: 8px;
          transform: rotate(45deg);
          background-color: ${bgColor};
        "></div>
      </div>
    `,
    iconSize: [32, 32],
    iconAnchor: [16, 32],
    popupAnchor: [0, -32],
  });
};

export const GeoMap: React.FC<GeoMapProps> = ({ hops }) => {
  // Filter hops that have valid latitude and longitude coordinates
  const geoHops = useMemo(() => {
    return hops.filter(
      (h) => h.lat !== null && h.lat !== undefined && h.lon !== null && h.lon !== undefined
    );
  }, [hops]);

  // Center on first public hop, or fallback to center of the world
  const centerPosition: [number, number] = useMemo(() => {
    if (geoHops.length > 0 && geoHops[0].lat && geoHops[0].lon) {
      return [geoHops[0].lat, geoHops[0].lon];
    }
    return [30.0, 10.0];
  }, [geoHops]);

  // Polyline trajectory coordinates
  const polylinePositions: [number, number][] = useMemo(() => {
    return geoHops.map((h) => [h.lat as number, h.lon as number]);
  }, [geoHops]);

  return (
    <div className="bg-[#0f172a] border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
        <div>
          <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono flex items-center gap-2">
            <Globe className="w-4 h-4 text-cyan-400" />
            Global Relay Trajectory & IP Geolocation Map
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            Visualizing the geographical route traversed by the email across worldwide Mail Transfer Agents (MTAs).
          </p>
        </div>
        <div className="flex items-center space-x-3 text-xs font-mono">
          <span className="flex items-center gap-1.5 text-rose-400">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block animate-pulse"></span>
            Sending Origin
          </span>
          <span className="flex items-center gap-1.5 text-cyan-400">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block"></span>
            Relay Server
          </span>
          <span className="px-2 py-0.5 bg-slate-900 border border-slate-800 rounded text-slate-400">
            {geoHops.length} Geolocated Nodes
          </span>
        </div>
      </div>

      {geoHops.length === 0 ? (
        <div className="h-[420px] rounded-xl border border-slate-800 bg-[#070b14] flex flex-col items-center justify-center space-y-3 text-slate-500 p-6 text-center">
          <MapPin className="w-10 h-10 text-slate-600" />
          <p className="text-sm font-semibold text-slate-400">No Geographic Coordinates Found</p>
          <p className="text-xs max-w-md">
            All detected hops in this email were within private/internal networks (RFC 1918) or contained unresolvable IP ranges.
          </p>
        </div>
      ) : (
        <div className="h-[460px] rounded-xl overflow-hidden border border-slate-800 relative z-0">
          <MapContainer
            center={centerPosition}
            zoom={geoHops.length > 1 ? 3 : 5}
            scrollWheelZoom={false}
            style={{ height: '100%', width: '100%', backgroundColor: '#070b14' }}
          >
            {/* Dark Matter / CartoDB tiles for Cybersecurity aesthetic */}
            <TileLayer
              attribution='&copy; <a href="https://carto.com/attributions">CARTO</a>'
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              maxZoom={19}
            />

            {/* Trajectory Polyline connecting hops */}
            {polylinePositions.length > 1 && (
              <Polyline
                positions={polylinePositions}
                pathOptions={{
                  color: '#06b6d4',
                  weight: 3,
                  opacity: 0.8,
                  dashArray: '8, 8',
                }}
              />
            )}

            {/* Hop Markers */}
            {geoHops.map((hop, idx) => {
              const isOrigin = idx === 0;
              return (
                <Marker
                  key={hop.hop_index}
                  position={[hop.lat as number, hop.lon as number]}
                  icon={createCyberMarkerIcon(hop.hop_index, isOrigin)}
                >
                  <Popup className="cyber-popup">
                    <div className="bg-[#0f172a] text-slate-200 p-3 rounded-lg border border-slate-700 shadow-xl font-sans text-xs space-y-2 min-w-[200px]">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 font-mono">
                        <span className={`font-bold ${isOrigin ? 'text-rose-400' : 'text-cyan-400'}`}>
                          HOP #{hop.hop_index} {isOrigin && '(ORIGIN MTA)'}
                        </span>
                        <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded">
                          {hop.country_code || 'GEO'}
                        </span>
                      </div>
                      <div className="space-y-1 font-mono text-[11px]">
                        <div>
                          <span className="text-slate-500">IP: </span>
                          <span className="text-white font-bold">{hop.ip}</span>
                        </div>
                        <div>
                          <span className="text-slate-500">Location: </span>
                          <span className="text-cyan-300">
                            {hop.city ? `${hop.city}, ` : ''}{hop.country || 'Unknown'}
                          </span>
                        </div>
                        {hop.isp && (
                          <div>
                            <span className="text-slate-500">ISP: </span>
                            <span className="text-slate-300">{hop.isp}</span>
                          </div>
                        )}
                        {hop.hostname && (
                          <div>
                            <span className="text-slate-500">Host: </span>
                            <span className="text-slate-400 truncate block">{hop.hostname}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  </Popup>
                </Marker>
              );
            })}
          </MapContainer>
        </div>
      )}

      {/* Geolocation Table Legend */}
      {geoHops.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 pt-2">
          {geoHops.map((hop, idx) => (
            <div
              key={hop.hop_index}
              className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl text-xs space-y-1"
            >
              <div className="flex items-center justify-between font-mono">
                <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5" />
                  Hop #{hop.hop_index} {idx === 0 && '(Origin)'}
                </span>
                <span className="text-[11px] text-slate-400 bg-slate-800/80 px-2 py-0.5 rounded">
                  {hop.country}
                </span>
              </div>
              <p className="font-mono text-slate-300">{hop.ip}</p>
              <p className="text-slate-500 text-[11px] truncate">
                {hop.city ? `${hop.city} • ` : ''}{hop.isp || 'Standard Internet Route'}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default GeoMap;
