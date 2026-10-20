import React from "react";

export default function Sidebar({ setPage, page }) {
  return (
    <div className="sidebar">
      <h2>SOCShield</h2>

      <button
        className={page === "dashboard" ? "active" : ""}
        onClick={() => setPage("dashboard")}
      >
        📊 Dashboard
      </button>

      <button
        className={page === "alerts" ? "active" : ""}
        onClick={() => setPage("alerts")}
      >
        🚨 Alerts
      </button>

      <button
        className={page === "logs" ? "active" : ""}
        onClick={() => setPage("logs")}
      >
        📡 Logs
      </button>

      <button
        className={page === "map" ? "active" : ""}
        onClick={() => setPage("map")}
      >
        🌍 Map
      </button>

      <button 
        className={page === "ipintel" ? "active" : ""}
        onClick={() => setPage("ipintel")}>
        🌐 IP Intel
      </button>

      <button 
        className={page === "chain" ? "active" : ""}
        onClick={() => setPage("chain")}>
        🔥 Attack Chain
      </button>

      {/* <button 
        className={page === "graph" ? "active" : ""}
        onClick={() => setPage("graph")}>
        🕸 Attack Graph
      </button> */}
      <button 
        className={page === "chain" ? "active" : ""}
        onClick={() => setPage("pcap")}>
        📁 PCAP Analyzer
      </button>

      {/* 🔥 NEW BUTTON */}
      <button
        className={page === "scanner" ? "active" : ""}
        onClick={() => setPage("scanner")}
        style={{
          marginTop: "20px",
          background: "#0ea5e9",
          fontWeight: "bold"
        }}
      >
        🔗 Virus Scanner
      </button>
    </div>
  );
}