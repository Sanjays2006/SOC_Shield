import { useEffect, useState } from "react";
import axios from "axios";
import { API_URL } from "../api";

// 🔥 SAFE RISK FUNCTION
const getRiskLevel = (attacks = []) => {
  let score = 0;

  attacks.forEach((a) => {
    const sev = a?.severity || "Low";

    if (sev === "Critical") score += 4;
    else if (sev === "High") score += 3;
    else if (sev === "Medium") score += 2;
    else score += 1;
  });

  if (score >= 10) return "CRITICAL";
  if (score >= 6) return "HIGH";
  if (score >= 3) return "MEDIUM";
  return "LOW";
};

export default function AttackChain() {
  const [chains, setChains] = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchChains = async () => {
      try {
        const res = await axios.get(`${API_URL}/attack-chain`);

        console.log("CHAIN DATA:", res.data);

        // ✅ SAFE CHECK
        if (res.data && typeof res.data === "object") {
          setChains(res.data);
        } else {
          setChains({});
        }

      } catch (err) {
        console.error("CHAIN FETCH ERROR:", err);
        setChains({});
      } finally {
        setLoading(false);
      }
    };

    fetchChains();
  }, []);

  // 🔄 LOADING STATE
  if (loading) {
    return <h2 style={{ color: "white" }}>Loading attack chains...</h2>;
  }

  return (
    <div style={{ padding: "20px", color: "white", width: "100%" }}>
      <h2>🔥 Attack Chains</h2>

      {Object.keys(chains).length === 0 ? (
        <p>No attack chains available</p>
      ) : (
        Object.entries(chains).map(([ip, attacks]) => {
          
          // ✅ SAFE DATA
          const safeAttacks = Array.isArray(attacks) ? attacks : [];
          const risk = getRiskLevel(safeAttacks);

          return (
            <div className="chain-card" key={ip}>

              {/* HEADER */}
              <div className="chain-header">
                🌐 {ip}
                <span className={`risk ${risk.toLowerCase()}`}>
                  {risk}
                </span>
              </div>

              {/* TIMELINE */}
              <div className="chain-timeline">
                {safeAttacks.map((a, i) => {
                  const severity = (a?.severity || "Low").toLowerCase();
                  const type = a?.type || "Unknown Attack";

                  return (
                    <div key={i} className="chain-node">
                      <div className={`dot ${severity}`} />
                      <div className="label">{type}</div>
                    </div>
                  );
                })}
              </div>

            </div>
          );
        })
      )}
    </div>
  );
}