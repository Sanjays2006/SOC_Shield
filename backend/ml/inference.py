"""
Runtime ML inference: classification + anomaly scoring.

Models are loaded lazily and cached. If a model file is missing or
scikit-learn/joblib is unavailable, inference degrades gracefully:
predictions return None and the pipeline continues (an alert is never
dropped just because ML is unavailable).
"""

import os
import threading

_LOCK = threading.Lock()
_CLASSIFIER = None
_ANOMALY = None
_CLASSIFIER_TRIED = False
_ANOMALY_TRIED = False

_MODELS_DIR = os.getenv("SOCSHIELD_MODELS_DIR", "models")
_CLASSIFIER_PATH = os.path.join(_MODELS_DIR, "classifier.joblib")
_ANOMALY_PATH = os.path.join(_MODELS_DIR, "anomaly.joblib")


def _load_classifier():
    global _CLASSIFIER, _CLASSIFIER_TRIED
    if _CLASSIFIER_TRIED:
        return _CLASSIFIER
    with _LOCK:
        if _CLASSIFIER_TRIED:
            return _CLASSIFIER
        _CLASSIFIER_TRIED = True
        try:
            import joblib
            if os.path.exists(_CLASSIFIER_PATH):
                _CLASSIFIER = joblib.load(_CLASSIFIER_PATH)
        except Exception as e:
            print("⚠️ Classifier load failed:", e)
            _CLASSIFIER = None
    return _CLASSIFIER


def _load_anomaly():
    global _ANOMALY, _ANOMALY_TRIED
    if _ANOMALY_TRIED:
        return _ANOMALY
    with _LOCK:
        if _ANOMALY_TRIED:
            return _ANOMALY
        _ANOMALY_TRIED = True
        try:
            import joblib
            if os.path.exists(_ANOMALY_PATH):
                _ANOMALY = joblib.load(_ANOMALY_PATH)
        except Exception as e:
            print("⚠️ Anomaly model load failed:", e)
            _ANOMALY = None
    return _ANOMALY


def classify(norm_event):
    """Predict attack family + calibrated confidence for a normalized event.

    Returns dict or None when unavailable:
      {"family": str, "confidence": float, "model_version": str}
    """
    bundle = _load_classifier()
    if bundle is None:
        return None
    try:
        from ml.features import build_payload_frame
        X = build_payload_frame([norm_event])
        pipe = bundle["pipeline"]
        pred = pipe.predict(X)[0]
        confidence = None
        if hasattr(pipe, "predict_proba"):
            proba = pipe.predict_proba(X)[0]
            confidence = float(max(proba))
        return {
            "family": str(pred),
            "confidence": confidence,
            "model_version": bundle.get("version"),
        }
    except Exception as e:
        print("⚠️ classify() failed:", e)
        return None


def anomaly_score(norm_event):
    """Compute an anomaly score for a normalized event with flow features.

    Returns dict or None:
      {"score": float, "is_anomaly": bool, "threshold": float,
       "model_version": str}
    Returns None when the model is missing OR the event lacks flow features
    (we do NOT fabricate flow data).
    """
    bundle = _load_anomaly()
    if bundle is None:
        return None

    from services.normalize import has_flow_features
    if not has_flow_features(norm_event):
        return None

    try:
        import numpy as np
        feats = bundle["features"]
        medians = bundle.get("medians", {})
        row = []
        for f in feats:
            v = norm_event.get(f)
            if v is None:
                v = medians.get(f, 0)
            row.append(float(v))
        pipe = bundle["pipeline"]
        scaled = pipe.named_steps["scale"].transform(np.array([row]))
        raw = pipe.named_steps["iforest"].decision_function(scaled)[0]
        score = float(-raw)
        threshold = float(bundle.get("threshold", 0.0))
        return {
            "score": score,
            "is_anomaly": score >= threshold,
            "threshold": threshold,
            "model_version": bundle.get("version"),
        }
    except Exception as e:
        print("⚠️ anomaly_score() failed:", e)
        return None
