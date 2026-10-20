"""
Feature assembly shared by training and inference.

Builds a feature DataFrame from a list of normalized events. Combines:
  - payload/text features (ml.labels.payload_features)
  - TF-IDF char n-grams over the URL (captures novel payload tokens)
  - categorical hints (app_proto, dest_port bucket)

Keeping this in ONE place guarantees train/inference parity (no skew).
"""

import pandas as pd

from ml.labels import payload_features, FEATURE_NAMES


# Well-known ports -> coarse bucket (reduces cardinality, avoids leakage
# from arbitrary ephemeral ports).
_PORT_BUCKETS = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    443: "https", 445: "smb", 3306: "mysql", 3389: "rdp", 8080: "http-alt",
}


def port_bucket(port):
    if port is None:
        return "unknown"
    return _PORT_BUCKETS.get(int(port), "other")


def build_payload_frame(events):
    """Return a DataFrame of interpretable payload features + raw url text.

    `events` is a list of dicts that each have at least 'http_url'
    (normalized) or a nested http.url (raw). We accept both.
    """
    rows = []
    urls = []
    for ev in events:
        url = ev.get("http_url")
        if url is None:
            url = (ev.get("http", {}) or {}).get("url")
        url = url or ""
        urls.append(url)

        feats = payload_features(url)
        feats["app_proto"] = ev.get("app_proto") or "unknown"
        feats["port_bucket"] = port_bucket(ev.get("dest_port"))
        rows.append(feats)

    df = pd.DataFrame(rows)
    df["__url__"] = urls
    return df


def numeric_feature_columns():
    """The interpretable numeric columns (excludes TF-IDF + categoricals)."""
    return list(FEATURE_NAMES)
