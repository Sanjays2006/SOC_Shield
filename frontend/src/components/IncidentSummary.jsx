import { useState } from "react";
import axios from "axios";
import { API_URL } from "../api";

// Fetches an AI-assisted (or deterministic fallback) incident summary
// for a given alert id, on demand.
export default function IncidentSummary({ alertId }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const generate = async () => {
    if (!alertId) return;
    setLoading(true);
    setError(null);
    try {
      const res = await axios.get(`${API_URL}/incident-summary/${alertId}`);
      setData(res.data);
    } catch (e) {
      setError("Could not generate summary.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="incident-summary">
      <button className="ai-btn" onClick={generate} disabled={loading || !alertId}>
        {loading ? "Generating…" : "🤖 Generate AI Summary"}
      </button>

      {error && <div className="error-banner">{error}</div>}

      {data && (
        <div className="summary-body">
          <div className="summary-source">
            Source: {data.source === "llm" ? `LLM (${data.model})` : "Rule-based fallback"}
          </div>

          <h4>Summary</h4>
          <p>{data.summary}</p>

          {data.evidence?.length > 0 && (
            <>
              <h4>Evidence</h4>
              <ul>
                {data.evidence.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            </>
          )}

          <h4>Potential Impact</h4>
          <p>{data.potential_impact}</p>

          {data.recommended_steps?.length > 0 && (
            <>
              <h4>Recommended Steps</h4>
              <ol>
                {data.recommended_steps.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ol>
            </>
          )}

          <h4>Limitations</h4>
          <p className="limitations">{data.limitations}</p>
        </div>
      )}
    </div>
  );
}
