import joblib
import sys
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_DIR = BASE_DIR / "model"

web_model = joblib.load(MODEL_DIR / "web_ids_model.pkl")
system_model = joblib.load(MODEL_DIR / "system_ids_model.pkl")

sys.path.append(str(BASE_DIR))

from rules.rules import run_rules

web_features = [
    "method_risk",
    "status_risk",
    "url_risk",
    "bytes_log",
    "is_scanner_ua"
]

system_features = [
    "is_known_user",
    "port_range"
]


def detect_event(event):

    # -------------------------
    # 1. Rule-based detection
    # -------------------------
    rule_results = run_rules(event)

    # -------------------------
    # 2. ML-based detection
    # -------------------------
    ml_result = None

    if event.get("log_source") == "web_server":

        features = [[
            event.get("method_risk", 0),
            event.get("status_risk", 0),
            event.get("url_risk", 0),
            event.get("bytes_log", 0),
            event.get("is_scanner_ua", 0)
        ]]

        prediction = web_model.predict(features)[0]

        if prediction == 1:
            ml_result = {
                "detected": True,
                "source": "ML",
                "model": "web_ids_model"
            }

    elif event.get("log_source") == "system":

        features = [[
            event.get("is_known_user", 0),
            event.get("port_range", 0)
        ]]

        prediction = system_model.predict(features)[0]

        if prediction == 1:
            ml_result = {
                "detected": True,
                "source": "ML",
                "model": "system_ids_model"
            }

    # -------------------------
    # 3. Aggregate results
    # -------------------------

    rule_detected = len(rule_results) > 0
    ml_detected = ml_result is not None

    if rule_detected and ml_detected:

        severity = "high"
        source = "RULE + ML"

    elif rule_detected:

        severity = max(
            [r["severity"] for r in rule_results],
            key=lambda x: {"low": 1, "medium": 2, "high": 3}[x]
        )

        source = "RULE"

    elif ml_detected:

        severity = "medium"
        source = "ML"

    else:

        severity = "none"
        source = "NONE"

    # -------------------------
    # 4. Final alert
    # -------------------------

    return {
        "detected": rule_detected or ml_detected,
        "severity": severity,
        "source": source,
        "rules": rule_results,
        "ml": ml_result,
        "event": event
    }