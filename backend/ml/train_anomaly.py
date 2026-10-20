"""
Train the anomaly detector (Isolation Forest) on network-FLOW features.

Usage:
    python -m ml.train_anomaly --input flows.json \
        --out models/anomaly.joblib --report models/anomaly_report.json

IMPORTANT (data honesty):
Isolation Forest here operates on real flow volume features:
  flow_bytes_toserver, flow_bytes_toclient,
  flow_pkts_toserver, flow_pkts_toclient, dest_port
If the training data lacks these fields (e.g. the legacy 4-field eve.json),
training ABORTS with a clear message instead of inventing features. Use
simulation mode or a Suricata sensor with flow logging to produce suitable
data.

The output is an anomaly SCORE and a documented threshold. An anomaly is
"unusual", NOT automatically "malicious" — this is surfaced in the UI and
docs, and feeds the risk engine only as one weighted signal.
"""

import argparse
import json
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

MODEL_VERSION = "anomaly-iforest-1.0.0"

FLOW_FEATURES = [
    "flow_bytes_toserver", "flow_bytes_toclient",
    "flow_pkts_toserver", "flow_pkts_toclient", "dest_port",
]


def load_flow_rows(path):
    rows = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            flow = obj.get("flow", {}) or {}
            row = {
                "flow_bytes_toserver": flow.get("bytes_toserver"),
                "flow_bytes_toclient": flow.get("bytes_toclient"),
                "flow_pkts_toserver": flow.get("pkts_toserver"),
                "flow_pkts_toclient": flow.get("pkts_toclient"),
                "dest_port": obj.get("dest_port"),
            }
            if any(v is not None for v in row.values()):
                rows.append(row)
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", default="models/anomaly.joblib")
    ap.add_argument("--report", default="models/anomaly_report.json")
    ap.add_argument("--contamination", type=float, default=0.1)
    args = ap.parse_args()

    df = load_flow_rows(args.input)
    if df.empty or df[FLOW_FEATURES].dropna(how="all").empty:
        raise SystemExit(
            "No flow features found in the input. Isolation Forest needs "
            "flow volume data (bytes/pkts). The legacy 4-field eve.json does "
            "NOT contain these — use simulation mode or enable Suricata flow "
            "logging. Aborting rather than fabricating features."
        )

    # Impute missing numeric values with column medians (documented).
    df = df[FLOW_FEATURES].apply(pd.to_numeric, errors="coerce")
    medians = df.median(numeric_only=True)
    df = df.fillna(medians)

    pipe = Pipeline([
        ("scale", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators=200,
            contamination=args.contamination,
            random_state=42,
        )),
    ])
    pipe.fit(df.values)

    # decision_function: higher = more normal. We define anomaly_score as
    # the negated value so higher = more anomalous, and set the threshold
    # at the contamination quantile.
    raw = pipe.named_steps["iforest"].decision_function(
        pipe.named_steps["scale"].transform(df.values)
    )
    anomaly_scores = -raw
    threshold = float(np.quantile(anomaly_scores, 1 - args.contamination))

    metrics = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_rows": int(len(df)),
        "features": FLOW_FEATURES,
        "contamination": args.contamination,
        "anomaly_threshold": threshold,
        "score_stats": {
            "min": float(anomaly_scores.min()),
            "max": float(anomaly_scores.max()),
            "mean": float(anomaly_scores.mean()),
        },
        "medians": medians.to_dict(),
        "notes": [
            "Higher anomaly_score = more unusual.",
            "An anomaly is 'unusual', not automatically malicious.",
            "Threshold set at the (1 - contamination) score quantile.",
        ],
    }

    joblib.dump(
        {"pipeline": pipe, "version": MODEL_VERSION,
         "threshold": threshold, "features": FLOW_FEATURES,
         "medians": medians.to_dict()},
        args.out,
    )
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, default=str)

    print(f"✅ Saved anomaly model -> {args.out}")
    print(f"✅ Threshold: {threshold:.4f}  (n={len(df)})")


if __name__ == "__main__":
    main()
