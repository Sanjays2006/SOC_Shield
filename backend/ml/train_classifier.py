"""
Train the attack-family classifier (RandomForest).

Usage:
    python -m ml.train_classifier --input ../suricata_logs/eve.json \
        --out models/classifier.joblib --report models/classifier_report.json

Design:
  - Labels = attack family from signature text (ml.labels), NOT severity.
  - Features = interpretable payload features + TF-IDF char n-grams of the
    URL + categorical (app_proto, port bucket) via a ColumnTransformer.
  - Pipeline is fit ONLY on the training split (no leakage); TF-IDF and
    encoders learn their vocabulary from train data only.
  - Class imbalance handled with class_weight="balanced".
  - Evaluation: precision/recall/F1 (per class + macro), confusion matrix,
    stratified train/test split, and optional cross-validation.
  - The signature string is deliberately EXCLUDED from features so the
    model cannot trivially echo the label-generating rule.
"""

import argparse
import json
from datetime import datetime, timezone

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    classification_report, confusion_matrix, f1_score,
)
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
import joblib

from ml.labels import family_from_signature
from ml.features import build_payload_frame, numeric_feature_columns

MODEL_VERSION = "classifier-rf-1.0.0"


def load_events(path):
    """Read EVE JSON (one object per line) into raw event dicts."""
    events = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("event_type") == "alert":
                events.append(obj)
    return events


def make_dataset(events):
    """Build (X_frame, y) from raw events."""
    labels = []
    norm_events = []
    for ev in events:
        sig = (ev.get("alert", {}) or {}).get("signature")
        url = (ev.get("http", {}) or {}).get("url")
        labels.append(family_from_signature(sig, url))
        norm_events.append({
            "http_url": url,
            "app_proto": ev.get("app_proto"),
            "dest_port": ev.get("dest_port"),
        })
    X = build_payload_frame(norm_events)
    y = pd.Series(labels, name="family")
    return X, y


def build_pipeline():
    numeric_cols = numeric_feature_columns()
    cat_cols = ["app_proto", "port_bucket"]

    pre = ColumnTransformer(
        transformers=[
            ("num", "passthrough", numeric_cols),
            ("cat", OneHotEncoder(handle_unknown="ignore"), cat_cols),
            ("url", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4),
                                    min_df=1), "__url__"),
        ],
        remainder="drop",
    )

    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    return Pipeline([("features", pre), ("model", clf)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Path to eve.json")
    ap.add_argument("--out", default="models/classifier.joblib")
    ap.add_argument("--report", default="models/classifier_report.json")
    ap.add_argument("--test-size", type=float, default=0.25)
    args = ap.parse_args()

    events = load_events(args.input)
    if len(events) < 10:
        raise SystemExit(
            f"Only {len(events)} alert events found — too few to train a "
            "defensible model. Provide a larger labeled dataset."
        )

    X, y = make_dataset(events)
    print(f"Loaded {len(X)} events across {y.nunique()} families:")
    print(y.value_counts().to_dict())

    # Stratify when every class has >=2 samples; otherwise fall back.
    stratify = y if y.value_counts().min() >= 2 else None
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=stratify
    )

    pipe = build_pipeline()
    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)

    # Cross-validation (guarded: needs enough samples per class).
    cv_scores = None
    try:
        if y.value_counts().min() >= 3:
            cv_scores = cross_val_score(
                build_pipeline(), X, y, cv=3,
                scoring="f1_macro"
            ).tolist()
    except Exception as e:
        print("CV skipped:", e)

    metrics = {
        "model_version": MODEL_VERSION,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_events": len(X),
        "classes": sorted(y.unique().tolist()),
        "class_distribution": y.value_counts().to_dict(),
        "test_size": args.test_size,
        "macro_f1": macro_f1,
        "classification_report": report,
        "confusion_matrix": cm,
        "confusion_labels": sorted(y_test.unique().tolist()),
        "cross_val_f1_macro": cv_scores,
        "notes": [
            "Labels derived from signature text, not Suricata severity.",
            "Signature string excluded from features to prevent leakage.",
            "class_weight=balanced used for imbalance.",
        ],
    }

    joblib.dump({"pipeline": pipe, "version": MODEL_VERSION}, args.out)
    with open(args.report, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, default=str)

    print(f"\n✅ Saved model -> {args.out}")
    print(f"✅ Saved report -> {args.report}")
    print(f"Macro F1 (holdout): {macro_f1:.3f}")


if __name__ == "__main__":
    main()
