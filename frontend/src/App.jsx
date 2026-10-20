import { useEffect, useState, useRef, useMemo } from "react";
import io from "socket.io-client";
import "./App.css";
import axios, { API_URL, isAuthed, getRole, getUser, clearAuth } from "./api";
import Login from "./components/Login";
import MapView from "./components/MapView";
import Sidebar from "./components/Sidebar";
import StatsPanel from "./components/StatsPanel";

import AlertCard from "./components/AlertCard";
import AlertDrawer from "./components/AlertDrawer";
import Filters from "./components/Filters";
import AIInsights from "./components/AIInsights";
import OverviewCards from "./components/OverviewCards";
import AttackChain from "./components/AttackChain";
import PcapAnalyzer from "./components/PcapAnalyzer";
import logo from "./assets/bot.jpeg";

import { Bar, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
  LineElement,
  PointElement,
} from "chart.js";

import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

ChartJS.register(
  BarElement, CategoryScale, LinearScale, Tooltip, Legend, LineElement, PointElement
);

const socket = io(API_URL);

// Build headers for raw fetch() calls, including the bearer token.
function authHeaders(extra = {}) {
  const token = localStorage.getItem("socshield_token");
  return { ...extra, ...(token ? { Authorization: `Bearer ${token}` } : {}) };
}

function App() {
  const [authed, setAuthed] = useState(isAuthed());
  const [role, setRole] = useState(getRole());
  const [logs, setLogs] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [page, setPage] = useState("dashboard");
  const [loadError, setLoadError] = useState(false);

  const [ip, setIp] = useState("");
  const [ipData, setIpData] = useState(null);

  const [selectedAlert, setSelectedAlert] = useState(null);

  // Filter + sort state
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterPriority, setFilterPriority] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState("newest");

  // Pagination (client-side over the fetched set)
  const [page_n, setPageN] = useState(1);
  const PAGE_SIZE = 10;

  const alertSound = useRef(null);

  useEffect(() => {
    alertSound.current = new Audio("/alert.mp3");
  }, []);

  useEffect(() => {
    const unlock = () => {
      alertSound.current?.play().then(() => {
        alertSound.current.pause();
        alertSound.current.currentTime = 0;
      }).catch(() => {});
      window.removeEventListener("click", unlock);
    };
    window.addEventListener("click", unlock);
  }, []);

  const fetchIP = async () => {
    try {
      const res = await axios.get(`${API_URL}/ip-intel/${ip}`);
      setIpData(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    const fetchData = async () => {
      try {
        const logsRes = await axios.get(`${API_URL}/logs`);
        const alertsRes = await axios.get(`${API_URL}/alerts`);
        setLoadError(false);

        setLogs(Array.isArray(logsRes.data) ? logsRes.data : logsRes.data.items || []);
        const alertData = Array.isArray(alertsRes.data) ? alertsRes.data : alertsRes.data.items || [];

        setAlerts(prev =>
          JSON.stringify(prev) === JSON.stringify(alertData) ? prev : alertData
        );

        const timelineData = alertData.slice(-20).map(a => ({
          time: new Date(a.timestamp || Date.now()).toLocaleTimeString(),
          score: a.risk_score ?? a.score ?? 0,
        }));
        setTimeline(timelineData);
      } catch (e) {
        setLoadError(true);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    socket.on("new_log", (log) => setLogs(prev => [log, ...prev]));

    socket.on("new_alert", (alert) => {
      setAlerts(prev => [alert, ...prev]);
      setTimeline(prev => [
        ...prev.slice(-19),
        { time: new Date().toLocaleTimeString(), score: alert.risk_score ?? alert.score },
      ]);
      toast.error(`🚨 ${alert.alert?.signature || alert.type} from ${alert.src_ip}`);
      const pr = alert.priority || alert.alert?.severity;
      if (["High", "Critical"].includes(pr)) {
        alertSound.current?.play().catch(() => {});
      }
    });

    return () => {
      socket.off("new_log");
      socket.off("new_alert");
    };
  }, []);

  const fetchAlerts = async () => {
    const res = await fetch(`${API_URL}/alerts`, { headers: authHeaders() });
    const data = await res.json();
    setAlerts(Array.isArray(data) ? data : data.items || []);
  };

  const resolveAlert = async (id) => {
    try {
      const res = await fetch(`${API_URL}/resolve-alert`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ id }),
      });
      const data = await res.json();
      toast.success(data.message || "Resolved");
      fetchAlerts();
    } catch (err) {
      toast.error("Resolve failed");
    }
  };

  const blockIP = async (ip) => {
    try {
      const res = await fetch(`${API_URL}/block-ip`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ ip }),
      });
      const data = await res.json();
      toast.success(data.message || "Blocked");
    } catch (err) {
      toast.error("Block failed");
    }
  };

  const assignAlert = async (id) => {
    const analyst = prompt("Enter analyst name:");
    if (!analyst) return;
    try {
      const res = await fetch(`${API_URL}/assign-alert`, {
        method: "POST",
        headers: authHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({ id, analyst }),
      });
      const data = await res.json();
      toast.success(data.message || "Assigned");
      fetchAlerts();
    } catch (err) {
      toast.error("Assign failed");
    }
  };

  // 🔍 FILTER + SEARCH + SORT
  const processedAlerts = useMemo(() => {
    let list = alerts.filter(a => {
      const sev = a.alert?.severity || a.severity;
      const pri = a.priority || sev;
      if (filterSeverity && sev !== filterSeverity) return false;
      if (filterPriority && pri !== filterPriority) return false;
      if (search) {
        const hay = `${a.src_ip || ""} ${a.alert?.signature || ""} ${a.ml?.family || ""}`.toLowerCase();
        if (!hay.includes(search.toLowerCase())) return false;
      }
      return true;
    });

    list = [...list].sort((a, b) => {
      if (sort === "risk") return (b.risk_score ?? 0) - (a.risk_score ?? 0);
      if (sort === "score") return (b.score ?? 0) - (a.score ?? 0);
      return new Date(b.timestamp || 0) - new Date(a.timestamp || 0);
    });
    return list;
  }, [alerts, filterSeverity, filterPriority, search, sort]);

  // Pagination slice
  const totalPages = Math.max(1, Math.ceil(processedAlerts.length / PAGE_SIZE));
  const pageAlerts = processedAlerts.slice((page_n - 1) * PAGE_SIZE, page_n * PAGE_SIZE);

  const chartData = {
    labels: ["Low", "Medium", "High", "Critical"],
    datasets: [{
      label: "Attack Count",
      data: ["Low", "Medium", "High", "Critical"].map(
        s => alerts.filter(a => (a.priority || a.alert?.severity || a.severity) === s).length
      ),
      backgroundColor: ["#00ff00", "#ffa500", "#ff4d4d", "#ff0000"],
    }],
  };

  const timelineData = {
    labels: timeline.map(t => t.time),
    datasets: [{
      label: "Risk Score", data: timeline.map(t => t.score),
      borderColor: "#ff0000", tension: 0.4,
    }],
  };

  const memoAlerts = useMemo(() => alerts, [alerts]);

  if (!authed) {
    return <Login onAuthed={(d) => { setAuthed(true); setRole(d.role); }} />;
  }

  const logout = () => { clearAuth(); setAuthed(false); setRole(null); };

  return (
    <div className="app-container">
      <Sidebar setPage={setPage} page={page} />

      <div style={{ display: "flex", width: "100%" }}>
        <div className="main-content">
          <div className="topbar">
            <h1>SOCShield Dashboard</h1>
            <div className="topbar-user">
              <span className={`role-chip ${role}`}>{role}</span>
              <span className="user-name">{getUser()}</span>
              <button className="logout-btn" onClick={logout}>Logout</button>
            </div>
          </div>
          <ToastContainer />

          {loadError && (
            <div className="error-banner">
              ⚠ Cannot reach backend at {API_URL}. Check that it is running.
            </div>
          )}

          {/* DASHBOARD */}
          {page === "dashboard" && (
            <>
              <OverviewCards />
              <AIInsights alerts={alerts} />

              <div className="chart-row">
                <div className="chart-box"><Bar data={chartData} /></div>
                <div className="chart-box"><Line data={timelineData} /></div>
              </div>

              <h3>🚨 Live Alerts</h3>
              {alerts.length === 0 && !loadError && (
                <p className="empty-state">No alerts yet. Start the agent to stream events.</p>
              )}
              {alerts.slice(0, 5).map((a, i) => (
                <AlertCard key={a._id || i} alert={a}
                  onInvestigate={setSelectedAlert} onResolve={resolveAlert}
                  onBlock={blockIP} onAssign={assignAlert} />
              ))}
            </>
          )}

          {/* ALERTS */}
          {page === "alerts" && (
            <>
              <h2>🚨 All Alerts</h2>
              <Filters
                setSeverity={setFilterSeverity}
                setPriority={setFilterPriority}
                setSearch={setSearch}
                setSort={setSort}
              />
              <AIInsights alerts={alerts} />

              {processedAlerts.length === 0 ? (
                <p className="empty-state">No alerts match your filters.</p>
              ) : (
                <>
                  {pageAlerts.map((a, i) => (
                    <AlertCard key={a._id || i} alert={a}
                      onInvestigate={setSelectedAlert} onResolve={resolveAlert}
                      onBlock={blockIP} onAssign={assignAlert} />
                  ))}

                  <div className="pagination">
                    <button disabled={page_n <= 1} onClick={() => setPageN(p => p - 1)}>← Prev</button>
                    <span>Page {page_n} / {totalPages} ({processedAlerts.length} alerts)</span>
                    <button disabled={page_n >= totalPages} onClick={() => setPageN(p => p + 1)}>Next →</button>
                  </div>
                </>
              )}
            </>
          )}

          {/* LOGS */}
          {page === "logs" && (
            <>
              <h2>📡 Logs</h2>
              {logs.length === 0 && <p className="empty-state">No logs yet.</p>}
              {logs.map((log, i) => (
                <div key={i} className="log-card">
                  <div>IP: {log.src_ip}</div>
                  <div>Type: {log.event_type}</div>
                  <div>Signature: {log.alert?.signature || log.normalized?.signature}</div>
                </div>
              ))}
            </>
          )}

          {page === "map" && <MapView alerts={memoAlerts} onInvestigate={setSelectedAlert} onBlock={blockIP} />}

          {/* IP INTEL */}
          {page === "ipintel" && (
            <div className="ipintel-container">
              <h2 className="ipintel-title">🌐 IP Intelligence</h2>
              <div className="ipintel-search">
                <input className="ip-input" value={ip}
                  onChange={(e) => setIp(e.target.value)}
                  placeholder="Enter IP address..." />
                <button className="scan-btn" onClick={fetchIP}>🔍 Scan</button>
              </div>
              {ipData && (
                <div className="ip-card">
                  <h3>📊 Result</h3>
                  <div className="ip-row"><span>🌍 Country:</span><b>{ipData.country}</b></div>
                  <div className="ip-row"><span>🏙 City:</span><b>{ipData.city}</b></div>
                  <div className="ip-row"><span>🏢 ISP:</span><b>{ipData.isp}</b></div>
                </div>
              )}
            </div>
          )}

          {page === "chain" && <AttackChain />}
          {page === "pcap" && <PcapAnalyzer />}
          {page === "scanner" && (
            <iframe src="https://cyberguard-analyzer21.onrender.com/"
              style={{ width: "100%", height: "100vh", border: "none" }}
              title="Virus Scanner" />
          )}
        </div>

        <StatsPanel alerts={alerts} />
      </div>

      <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)}
        onBlock={blockIP} onResolve={resolveAlert} onAssign={assignAlert} />
      <img src={logo} alt="SOCShield" className="floating-logo" />
    </div>
  );
}

export default App;
