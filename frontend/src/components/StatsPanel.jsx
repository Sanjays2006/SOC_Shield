import React from "react";

function StatsPanel({ alerts }) {

  // 🌍 Count attacks per country
  const countryCount = {};

  alerts.forEach(a => {
    const country = a.geo?.country || "Unknown";
    countryCount[country] = (countryCount[country] || 0) + 1;
  });

  // 🔥 Sort top attackers
  const topAttackers = Object.entries(countryCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div style={{
      width: "250px",
      background: "#111827",
      padding: "15px",
      borderLeft: "2px solid #1f2937"
    }}>
      <h3 style={{ color: "cyan" }}>📡 Top Attackers</h3>

      {topAttackers.map(([country, count], i) => (
        <div key={i} style={{
          margin: "10px 0",
          padding: "8px",
          background: "#1f2937",
          borderRadius: "5px"
        }}>
          🌍 {country}
          <div style={{ color: "red" }}>⚔ {count} attacks</div>
        </div>
      ))}
    </div>
  );
}

export default StatsPanel;