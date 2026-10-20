"""
Attack-family labels + payload feature engineering.

DESIGN NOTE (ground-truth honesty):
The supervised classifier predicts an ATTACK FAMILY (XSS, SQLi, scan,
brute-force, DDoS, malware, privilege-escalation, benign, ...). The label
is derived from the Suricata *signature* text and corroborating payload
content — NOT from Suricata's numeric severity. Severity is an ordinal
risk hint, not a class, so using it as the label would be mislabeling.

The signature->family mapping is a deterministic, auditable rule set used
ONLY to construct training labels from signature strings. At inference
time the model classifies from payload/text features; it does not just
echo the signature. This lets the model generalize to unseen or malformed
signatures while keeping training labels defensible.
"""

import re

# Canonical attack families (the classifier's target classes).
FAMILIES = [
    "benign",
    "recon_scan",
    "xss",
    "sql_injection",
    "brute_force",
    "dos_ddos",
    "malware",
    "privilege_escalation",
    "exploit_rce",
    "other_suspicious",
]

# Ordered signature-substring rules -> family. First match wins.
_SIGNATURE_RULES = [
    (r"xss|cross.?site", "xss"),
    (r"sql|union\s+select|injection", "sql_injection"),
    (r"brute|login", "brute_force"),
    (r"ddos|dos|flood", "dos_ddos"),
    (r"malware|drop|trojan|virus|payload", "malware"),
    (r"privilege|escalation|sudo|root", "privilege_escalation"),
    (r"rce|exploit|zero.?day|remote code", "exploit_rce"),
    (r"scan|probe|crawl|recon|bot", "recon_scan"),
    (r"low level|normal|benign", "benign"),
]

# URL/payload substrings that corroborate a family (used as features and
# as a tie-breaker when the signature is generic/unknown).
_PAYLOAD_RULES = [
    (r"<script|onerror=|javascript:|document\.cookie", "xss"),
    (r"union\s+select|or\s+1=1|drop\s+table|--|'\s*or", "sql_injection"),
    (r"rm\s+-rf|wget\s|curl\s|/bin/sh|kernel", "exploit_rce"),
    (r"\.exe|\.bin|\.sh|download|malicious", "malware"),
    (r"sudo|root access|escalat", "privilege_escalation"),
    (r"flood|overload|traffic", "dos_ddos"),
    (r"scan|probe|discover", "recon_scan"),
]


def family_from_signature(signature, url=""):
    """Derive a training label from signature text, corroborated by URL.

    Returns one of FAMILIES. Deterministic and auditable.
    """
    sig = (signature or "").lower()
    for pattern, family in _SIGNATURE_RULES:
        if re.search(pattern, sig):
            return family

    # Signature was generic/unknown -> fall back to payload evidence.
    u = (url or "").lower()
    for pattern, family in _PAYLOAD_RULES:
        if re.search(pattern, u):
            return family

    return "other_suspicious"


# ---- Payload feature extraction (text -> numeric features) ----

_FEATURE_PATTERNS = {
    "has_script_tag": r"<script",
    "has_sql_union": r"union\s+select",
    "has_or_1eq1": r"or\s+1\s*=\s*1|'\s*or\s*'1'\s*=\s*'1",
    "has_sql_comment": r"--|#",
    "has_drop_table": r"drop\s+table",
    "has_shell_cmd": r"rm\s+-rf|/bin/sh|wget\s|curl\s",
    "has_exe_download": r"\.exe|\.bin|\.sh\b",
    "has_cookie_access": r"document\.cookie",
    "has_angle_brackets": r"[<>]",
    "has_quote": r"['\"]",
}


def payload_features(url):
    """Extract interpretable boolean/count features from a URL/payload."""
    u = (url or "").lower()
    feats = {name: 1 if re.search(pat, u) else 0 for name, pat in _FEATURE_PATTERNS.items()}
    feats["url_length"] = len(u)
    feats["special_char_count"] = sum(u.count(c) for c in "<>'\"();=/-")
    feats["digit_count"] = sum(ch.isdigit() for ch in u)
    return feats


FEATURE_NAMES = list(_FEATURE_PATTERNS.keys()) + [
    "url_length", "special_char_count", "digit_count",
]
