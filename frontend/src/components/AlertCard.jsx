export default function AlertCard({ alert, onInvestigate, onResolve, onBlock, onAssign }) {

  const severity = alert.alert?.severity || alert.severity || "Low";
  const priority = alert.priority || severity;
  const ml = alert.ml || null;
  const anomaly = alert.anomaly || null;

  // Card border follows the combined PRIORITY when present, else IDS severity.
  const borderClass = (priority || severity).toLowerCase();

  return (
    <div className={`alert-card ${borderClass}`}>

      <div className="alert-header">
        ⚠ {alert.alert?.signature || alert.type}
        {priority && <span className={`priority-badge ${borderClass}`}>{priority}</span>}
      </div>

      <div>🌐 IP: {alert.src_ip}{alert.dest_ip ? ` → ${alert.dest_ip}` : ""}</div>

      {/* Original IDS severity + rule score preserved */}
      <div>🚨 IDS severity: {severity} &nbsp;|&nbsp; 🔥 Score: {alert.score}</div>

      {/* New ML + risk fields */}
      {typeof alert.risk_score === "number" && (
        <div>📈 Risk: <b>{alert.risk_score}</b> ({priority})</div>
      )}
      {ml?.family && (
        <div>
          🧠 ML: {ml.family}
          {typeof ml.confidence === "number" && ` (${(ml.confidence * 100).toFixed(0)}%)`}
        </div>
      )}
      {anomaly?.score != null && (
        <div>🌀 Anomaly: {anomaly.score.toFixed(2)} {anomaly.is_anomaly ? "⚠" : ""}</div>
      )}

      <div>Status: {alert.status || "Open"}</div>
      <p>👤 {alert.assigned_to ? alert.assigned_to : "Unassigned"}</p>

      <div className="actions">
        <button onClick={() => onInvestigate(alert)}>🔍 Investigate</button>
        <button onClick={() => onBlock(alert.src_ip)}>🚫 Block</button>
        <button onClick={() => onResolve(alert._id)}>✔ Resolve</button>
        <button onClick={() => onAssign(alert._id)}>👤 Assign</button>
      </div>
    </div>
  );
}
