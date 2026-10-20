import { useState } from "react";
import { API_URL } from "../api";

export default function PcapAnalyzer() {
  const [file, setFile] = useState(null);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  // 🔥 UPLOAD FILE
  const uploadFile = async () => {
    if (!file) return alert("Select a file");

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);

      const res = await fetch(`${API_URL}/upload-pcap`, {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      console.log("PCAP REPORT:", data);

      setReport(data);
    } catch (err) {
      console.error(err);
      alert("Upload failed");
    } finally {
      setLoading(false);
    }
  };

  // 🔥 SEVERITY LOGIC
  const getSeverity = () => {
    if (!report) return "low";

    if (report.suspicious > 10) return "critical";
    if (report.suspicious > 5) return "high";
    if (report.suspicious > 1) return "medium";
    return "low";
  };

  // 🔥 DOWNLOAD REPORT
  const downloadReport = () => {
    if (!report) return;

    const content = `
SOCShield PCAP Report

Total Packets: ${report.total_packets || 0}
Protocols: ${report.protocols?.join(", ") || "N/A"}
Suspicious: ${report.suspicious || 0}
Severity: ${getSeverity()}

Top Source IPs:
${(report.top_ips || [])
  .map(([ip, count]) => `${ip} - ${count}`)
  .join("\n")}

Top Ports:
${(report.top_ports || [])
  .map(([port, count]) => `${port} - ${count}`)
  .join("\n")}

Possible Scanners:
${(report.possible_scanners || []).join(", ") || "None"}
`;

    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = "pcap_report.txt";
    a.click();
  };

  return (
    <div className="pcap-container">

      <h2 className="pcap-title">📁 PCAP Analyzer</h2>

      {/* 🔥 UPLOAD CARD */}
      <div className="pcap-card">

        <input
          type="file"
          onChange={(e) => setFile(e.target.files[0])}
        />

        <button onClick={uploadFile}>
          {loading ? "Analyzing..." : "Upload & Analyze"}
        </button>

        {/* FILE NAME */}
        {file && (
          <p className="file-name">📄 {file.name}</p>
        )}

      </div>

      {/* EMPTY STATE */}
      {!report && (
        <div className="empty-state">
          <p>📊 Upload a PCAP file to see analysis</p>
        </div>
      )}

      {/* REPORT */}
      {report && (
        <div className="report-box">

          <h3>📊 Report</h3>

          <p><b>Total Packets:</b> {report.total_packets}</p>
          <p><b>Protocols:</b> {report.protocols?.join(", ")}</p>
          <p><b>Suspicious:</b> {report.suspicious}</p>
          <p><b>Severity:</b> {getSeverity()}</p>

          {/* 🔥 TOP IPS */}
          <h4>🌐 Top Source IPs</h4>
          {(report.top_ips || []).map(([ip, count]) => (
            <div key={ip}>{ip} - {count}</div>
          ))}

          {/* 🔥 TOP PORTS */}
          <h4>🔌 Top Ports</h4>
          {(report.top_ports || []).map(([port, count]) => (
            <div key={port}>{port} - {count}</div>
          ))}

          {/* 🔥 SCANNERS */}
          <h4>🚨 Possible Scanners</h4>
          {(report.possible_scanners || []).length > 0 ? (
            report.possible_scanners.map((ip) => (
              <div key={ip}>{ip}</div>
            ))
          ) : (
            <p>None</p>
          )}

          <br />

          <button onClick={downloadReport}>
            ⬇ Download Report
          </button>

        </div>
      )}

    </div>
  );
}