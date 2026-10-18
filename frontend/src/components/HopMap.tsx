import React, { useEffect, useRef } from 'react';
import L from 'leaflet';

interface Hop {
  hop_number?: number;
  ip: string;
  lat?: number;
  lon?: number;
  latitude?: number;
  longitude?: number;
  city?: string;
  region?: string;
  country?: string;
  isp?: string;
  org?: string;
  label?: string;
}

interface HopMapProps {
  hops: Hop[];
}

export const HopMap: React.FC<HopMapProps> = ({ hops }) => {
  const mapContainerRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapContainerRef.current) return;

    // Filter hops that have valid coordinates
    const validHops = hops.filter((h) => {
      const lat = h.lat ?? h.latitude;
      const lon = h.lon ?? h.longitude;
      return typeof lat === 'number' && typeof lon === 'number' && !isNaN(lat) && !isNaN(lon);
    });

    if (mapInstanceRef.current) {
      mapInstanceRef.current.remove();
      mapInstanceRef.current = null;
    }

    const defaultLat = validHops.length > 0 ? (validHops[0].lat ?? validHops[0].latitude!) : 20;
    const defaultLon = validHops.length > 0 ? (validHops[0].lon ?? validHops[0].longitude!) : 0;
    const defaultZoom = validHops.length > 0 ? 3 : 2;

    const map = L.map(mapContainerRef.current, {
      center: [defaultLat, defaultLon],
      zoom: defaultZoom,
      zoomControl: true,
      attributionControl: false,
    });
    mapInstanceRef.current = map;

    // Use reliable OpenStreetMap tiles with built-in cyber dark mode styling (or CARTO if configured)
    const cartoApiKey = import.meta.env.VITE_CARTO_API_KEY;
    const isCarto = Boolean(cartoApiKey && cartoApiKey.length > 25);
    const tileUrl = isCarto
      ? `https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png?key=${cartoApiKey}`
      : 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png';

    L.tileLayer(tileUrl, {
      maxZoom: 19,
      subdomains: isCarto ? 'abcd' : 'abc',
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    }).addTo(map);

    if (validHops.length === 0) {
      return;
    }

    const latLngs: L.LatLngTuple[] = [];

    validHops.forEach((h, index) => {
      const lat = (h.lat ?? h.latitude)!;
      const lon = (h.lon ?? h.longitude)!;
      latLngs.push([lat, lon]);

      const isFirst = index === 0;
      const isLast = index === validHops.length - 1;
      const markerColor = isFirst ? '#ef4444' : isLast ? '#10b981' : '#06b6d4';

      const customIcon = L.divIcon({
        className: 'custom-hop-marker',
        html: `
          <div style="
            background: ${markerColor};
            width: 26px;
            height: 26px;
            border-radius: 50%;
            border: 3px solid rgba(255,255,255,0.9);
            box-shadow: 0 0 12px ${markerColor};
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-size: 11px;
            font-weight: bold;
            font-family: 'JetBrains Mono', monospace;
          ">
            ${h.hop_number ?? index + 1}
          </div>
        `,
        iconSize: [26, 26],
        iconAnchor: [13, 13],
      });

      const locStr = [h.city, h.region, h.country].filter(Boolean).join(', ') || 'Unknown Location';
      const popupContent = `
        <div style="font-family: sans-serif; font-size: 12px; color: #0f172a; padding: 4px;">
          <div style="font-weight: bold; font-size: 13px; margin-bottom: 3px;">
            Hop #${h.hop_number ?? index + 1} ${isFirst ? '(Origin)' : isLast ? '(Destination)' : '(Relay)'}
          </div>
          <div><b>IP:</b> <code>${h.ip}</code></div>
          <div><b>Location:</b> ${locStr}</div>
          <div><b>ISP / ASN:</b> ${h.isp || h.org || 'Unknown'}</div>
        </div>
      `;

      L.marker([lat, lon], { icon: customIcon })
        .addTo(map)
        .bindPopup(popupContent);
    });

    if (latLngs.length > 1) {
      // Connect hops with a glowing cyan animated dash line
      L.polyline(latLngs, {
        color: '#06b6d4',
        weight: 3,
        opacity: 0.85,
        dashArray: '8, 8',
      }).addTo(map);

      // Fit bounds to show all hops with padding
      const bounds = L.latLngBounds(latLngs);
      map.fitBounds(bounds, { padding: [40, 40], maxZoom: 8 });
    }

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, [hops]);

  return (
    <div style={{ position: 'relative', width: '100%', height: '360px', borderRadius: '12px', overflow: 'hidden' }}>
      <div ref={mapContainerRef} className="dark-map" style={{ width: '100%', height: '100%', backgroundColor: '#070b14' }} />
      {hops.length === 0 && (
        <div style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'rgba(7, 11, 20, 0.8)',
          color: '#94a3b8',
          fontSize: '14px',
        }}>
          No geographical hops extracted from email headers.
        </div>
      )}
    </div>
  );
};
