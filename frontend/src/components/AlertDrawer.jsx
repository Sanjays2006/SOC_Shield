import "../App.css";
import { useEffect, useState } from "react";
import { API_URL } from "../api";
import IncidentSummary from "./IncidentSummary";

export default function AlertDrawer({ alert, onClose, onBlock, onResolve, onAssign }) {
  const [blockedIPs, setBlockedIPs] = useState([]);

  useEffect(() => {
    fetch(`${API_URL}/blocked-ips`)
      .then(res => res.json())
      .then(data => {
        const ips = Array.isArray(data) ? data.map(item => item.ip) : [];
        setBlockedIPs(ips);
      })
      .catch(() => setBlockedIPs([]));
  }, []);

  if (!alert) return null;

  const severity = alert.alert?.severity || "Low";
  const priority = alert.priority || severity;
  const ml = alert.ml || null;
  const anomaly = alert.anomaly || null;
  const isBlocked = blockedIPs.includes(alert.src_ip);

  return (
    <div className="drawer">

      {/* HEADER */}
      <div className="drawer-header">
        🔍 Investigation
        <button onClick={onClose}>✖</button>
      </div>

      {/* BASIC INFO */}
      <div className="drawer-section">
        <h3>🌐 Source Info</h3>
        <p><b>IP:</b> {alert.src_ip}</p>
        {alert.dest_ip && <p><b>Destination:</b> {alert.dest_ip}{alert.dest_port ? `:${alert.dest_port}` : ""}</p>}
        <p><b>Country:</b> {alert.geo?.country || "Unknown"}</p>
      </div>

      {/* ATTACK DETAILS */}
      <div className="drawer-section">
        <h3>⚠ Attack Details</h3>
        <p><b>Type:</b> {alert.alert?.signature}</p>
        <p>
          <b>IDS Severity:</b>{" "}
          <span className={`severity ${severity.toLowerCase()}`}>{severity}</span>
        </p>
        <p><b>Rule Score:</b> {alert.score}</p>
        {typeof alert.risk_score === "number" && (
          <p><b>Risk Score:</b> {alert.risk_score} <span className={`severity ${priority.toLowerCase()}`}>{priority}</span></p>
        )}
      </div>

      {/* ML + ANOMALY */}
      {(ml || anomaly) && (
        <div className="drawer-section">
          <h3>🧠 ML Analysis</h3>
          {ml?.family && (
            <p>
              <b>Classification:</b> {ml.family}
              {typeof ml.confidence === "number" && ` (${(ml.confidence * 100).toFixed(0)}% confidence)`}
            </p>
          )}
          {anomaly?.score != null && (
            <p><b>Anomaly score:</b> {anomaly.score.toFixed(3)} {anomaly.is_anomaly ? "⚠ anomalous" : "(normal)"}</p>
          )}
          {alert.signals_used?.length > 0 && (
            <p><b>Signals used:</b> {alert.signals_used.join(", ")}</p>
          )}
        </div>
      )}

      {/* TIMESTAMP */}
      <div className="drawer-section">
        <h3>🕒 Timeline</h3>
        <p>{alert.timestamp}</p>
      </div>

      {/* AI INCIDENT SUMMARY */}
      <div className="drawer-section">
        <h3>📝 Incident Summary</h3>
        <IncidentSummary alertId={alert._id} />
      </div>

      {/* ACTIONS */}
      <div className="drawer-actions">
        <button disabled={isBlocked} onClick={() => onBlock(alert.src_ip)}>
          {isBlocked ? "🚫 Blocked" : "🚫 Block"}
        </button>
        <button onClick={() => onResolve(alert._id)}>✔ Resolve</button>
        <button disabled={alert.assigned_to} onClick={() => onAssign(alert._id)}>
          {alert.assigned_to ? "👤 Assigned" : "👤 Assign"}
        </button>
      </div>

    </div>
  );
}
