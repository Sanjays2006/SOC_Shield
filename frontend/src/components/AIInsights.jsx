// components/AIInsights.jsx
export default function AIInsights({ alerts }) {

  const highCount = alerts.filter(a => 
    (a.alert?.severity === "High" || a.alert?.severity === "Critical")
  ).length;

  return (
    <div className="ai-box">
      🤖 AI Insight:
      {highCount > 5 
        ? " ⚠ Spike in high severity attacks!"
        : " Normal traffic"}
    </div>
  );
}