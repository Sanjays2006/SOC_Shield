import { useEffect, useState } from "react";
import axios from "axios";
import { API_URL } from "../api";

// Overview cards driven by REAL backend /stats data.
export default function OverviewCards() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;
    const load = async () => {
      try {
        const res = await axios.get(`${API_URL}/stats`);
        if (active) {
          setStats(res.data);
          setError(false);
        }
      } catch (e) {
        if (active) setError(true);
      } finally {
        if (active) setLoading(false);
      }
    };
    load();
    const t = setInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, []);

  if (loading) return <div className="overview-cards">Loading metrics…</div>;
  if (error)
    return (
      <div className="overview-cards error-banner">
        ⚠ Could not load metrics. Is the backend running?
      </div>
    );
  if (!stats) return null;

  const cards = [
    { label: "Total Alerts", value: stats.total_alerts, cls: "" },
    { label: "Open Alerts", value: stats.open_alerts, cls: "warn" },
    { label: "Critical", value: stats.critical_alerts, cls: "crit" },
    { label: "Blocked IPs", value: stats.blocked_ips, cls: "" },
    { label: "Total Logs", value: stats.total_logs, cls: "" },
  ];

  return (
    <div className="overview-cards">
      {cards.map((c) => (
        <div className={`metric-card ${c.cls}`} key={c.label}>
          <div className="metric-value">{c.value ?? 0}</div>
          <div className="metric-label">{c.label}</div>
        </div>
      ))}
    </div>
  );
}
