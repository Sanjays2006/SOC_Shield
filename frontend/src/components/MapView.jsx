import { useState, useMemo} from "react";
import {
  MapContainer,
  TileLayer,
  CircleMarker,
  Popup,
  Polyline,
  Tooltip
} from "react-leaflet";

// 🎨 Severity color
const getColor = (severity) => {
  if (severity === "Critical") return "#ff0000";
  if (severity === "High") return "#ff4d4d";
  if (severity === "Medium") return "#ffa500";
  return "#00ff00";
};

// 🔥 Size
const getRadius = (severity) => {
  if (severity === "Critical") return 12;
  if (severity === "High") return 10;
  if (severity === "Medium") return 8;
  return 6;
};

// 🎯 Target (India)
const target = [20, 78];

function MapView({ alerts, onInvestigate, onBlock }) {

  const [selectedIP, setSelectedIP] = useState(null);

  // ✅ PROCESS + FREEZE COORDINATES
  const processedAlerts = useMemo(() => {
  const unique = {};

  alerts.forEach((a) => {
    if (!a.geo?.lat || !a.geo?.lon) return;

    const key = a.src_ip;

    // keep only latest alert per IP
    if (!unique[key] || new Date(a.timestamp) > new Date(unique[key].timestamp)) {
      unique[key] = {
        ...a,
        lat: Number(parseFloat(a.geo.lat).toFixed(2)),
        lon: Number(parseFloat(a.geo.lon).toFixed(2)),
        severity: a.alert?.severity || "Low"
      };
    }
  });

  return Object.values(unique);
}, [alerts]);
  return (
    <MapContainer
      center={[20, 0]}
      zoom={2}
      style={{ height: "500px", width: "100%" }}
    >
      <TileLayer url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png" />

      {processedAlerts.map((a) => {
        const isSelected = selectedIP === a.src_ip;

        return (
          <>
            {/* 🔴 MARKER */}
            <CircleMarker
              key={a.src_ip}
              center={[a.lat, a.lon]}
              radius={isSelected ? 16 : getRadius(a.severity)}
              pathOptions={{
                color: isSelected ? "#00ffff" : getColor(a.severity),
                fillColor: getColor(a.severity),
                fillOpacity: 0.9,
              }}
              className={`pulse-marker ${isSelected ? "selected-marker" : ""}`}
              eventHandlers={{
                click: () => {
                  setSelectedIP(a.src_ip);
                  onInvestigate?.(a);
                }
              }}
            >
              <Tooltip>
                ⚠ {a.alert?.signature} <br />
                🌐 {a.geo?.country}
              </Tooltip>

              <Popup>
                <div>
                  <b>🌍 Country:</b> {a.geo?.country || "Unknown"} <br />
                  <b>🧑‍💻 IP:</b> {a.src_ip} <br />
                  <b>⚠ Attack:</b> {a.alert?.signature} <br />
                  <b>🚨 Severity:</b> {a.severity} <br />
                  <b>🔥 Score:</b> {a.score}

                  <br /><br />

                  <button onClick={() => onInvestigate?.(a)}>
                    🔍 Investigate
                  </button>

                  <button onClick={() => onBlock?.(a.src_ip)}>
                    🚫 Block
                  </button>
                </div>
              </Popup>
            </CircleMarker>

            {/* 🌐 ATTACK LINE */}
            <Polyline
              key={a.src_ip + "-line"}
              positions={[[a.lat, a.lon], target]}
              pathOptions={{
                color: getColor(a.severity),
                weight: a.severity === "Critical" ? 3 : 2,
                opacity: 0.8,
                className: "attack-line"
              }}
            />
          </>
        );
      })}
    </MapContainer>
  );
}

export default MapView;