# SOCShield — Known Limitations & Future Work

## Data
- **Bundled `eve.json` is a simplified 4-field sample** (`event_type`,
  `src_ip`, `alert.signature`, `http.url`). It is NOT real Suricata EVE
  output and contains no network-flow fields.
- Full EVE parsing is implemented and used automatically when richer events
  arrive (simulation mode or a real Suricata sensor with flow logging).

## ML classifier (RandomForest, attack family)
- Trains on the signatures present in the input dataset. With the ~45-event
  sample, metrics will **not** be statistically robust — the training script
  refuses to train on fewer than 10 events and reports class distribution.
- Labels are derived from signature text (auditable rules), **not** Suricata
  severity; the signature is excluded from features to prevent leakage.
- For a defensible model, supply a larger, verified labeled dataset.

## Anomaly detector (Isolation Forest)
- Requires real **flow features** (bytes/pkts to server/client, dest port).
- On flow-less legacy events it **abstains** (returns no score) rather than
  fabricating features. Training aborts with a clear message if the dataset
  lacks flow data.
- An anomaly means "unusual", **not** automatically "malicious" — surfaced
  in the UI and summaries.

## Risk engine
- Weights and thresholds are heuristic defaults (configurable via env).
  They should be tuned against labeled outcomes for a given environment.
- Asset criticality is supported but must be configured; it is empty by default.

## AI incident summaries
- Optional. Without a configured provider/key, a deterministic rule-based
  summary is used. LLM output is advisory only and may be imperfect; it
  cannot take actions.

## Platform
- No authentication/RBAC yet on state-changing endpoints (documented in
  SECURITY.md as recommended next work).
- Firewall blocking is Windows-specific (`netsh`) and disabled by default.
- Frontend pagination is client-side over the fetched set; server-side
  pagination endpoints exist (`?page=&limit=`) and can be wired in for very
  large datasets.
- Not security-tested; not certified production-ready.

## Suggested future improvements
1. Larger labeled dataset + model calibration (probability calibration,
   per-class thresholds).
2. Server-side pagination/streaming in the frontend for high volumes.
3. AuthN/AuthZ + audit log for analyst actions.
4. Model monitoring (drift detection, periodic retraining pipeline).
5. Containerized deployment (Docker Compose) with TLS and Mongo auth.
