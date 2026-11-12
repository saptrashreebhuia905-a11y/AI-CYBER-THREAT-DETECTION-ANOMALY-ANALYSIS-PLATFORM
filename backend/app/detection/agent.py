from __future__ import annotations

import pickle
from pathlib import Path
from typing import Any, Dict, List

import numpy as np

MODEL_PATH = Path(__file__).resolve().parents[2] / "ml_training" / "model.pkl"


def _build_default_training_data():
    return [
        {"request_rate": 10, "failed_attempts": 0},
        {"request_rate": 12, "failed_attempts": 0},
        {"request_rate": 15, "failed_attempts": 1},
        {"request_rate": 8, "failed_attempts": 0},
        {"request_rate": 20, "failed_attempts": 0},
        {"request_rate": 14, "failed_attempts": 0},
        {"request_rate": 11, "failed_attempts": 1},
        {"request_rate": 25, "failed_attempts": 0},
        {"request_rate": 9, "failed_attempts": 0},
        {"request_rate": 13, "failed_attempts": 0},
        {"request_rate": 250, "failed_attempts": 8},
        {"request_rate": 220, "failed_attempts": 9},
        {"request_rate": 180, "failed_attempts": 7},
        {"request_rate": 300, "failed_attempts": 12},
        {"request_rate": 150, "failed_attempts": 6},
    ]


def _ensure_model_exists():
    if MODEL_PATH.exists():
        return True

    try:
        from sklearn.ensemble import IsolationForest
        import pandas as pd

        df = pd.DataFrame(_build_default_training_data())
        model = IsolationForest(contamination=0.2, random_state=42)
        model.fit(df[["request_rate", "failed_attempts"]])
        MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(model, f)
        return True
    except Exception:
        return False


def load_model():
    if not _ensure_model_exists():
        return None

    try:
        with open(MODEL_PATH, "rb") as f:
            return pickle.load(f)
    except Exception:
        return None


def evaluate_rules(log: Dict[str, Any]) -> List[str]:
    reasons: List[str] = []
    login_status = str(log.get("login_status", "")).upper()
    failed_attempts = int(log.get("failed_attempts", 0) or 0)
    request_rate = int(log.get("request_rate", 0) or 0)

    if login_status == "FAILED" and failed_attempts >= 3:
        reasons.append("Brute-force password attack detected")
    if request_rate > 100:
        reasons.append("High request rate / possible DDoS attack")
    if login_status == "FAILED" and failed_attempts >= 8:
        reasons.append("Repeated login failures from one source")
    if request_rate > 200:
        reasons.append("Extreme traffic spike")
    if not reasons:
        reasons.append("Normal behavior")

    return reasons


def evaluate_ml_anomaly(log: Dict[str, Any]) -> Dict[str, Any]:
    model = load_model()
    if model is None:
        return {
            "is_anomaly": False,
            "confidence": 0.0,
            "model_status": "Fallback mode",
        }

    request_rate = float(log.get("request_rate", 0) or 0)
    failed_attempts = float(log.get("failed_attempts", 0) or 0)
    sample = np.array([[request_rate, failed_attempts]], dtype=float)

    try:
        prediction = model.predict(sample)[0]
        score = float(model.decision_function(sample)[0])
    except Exception:
        prediction = 1
        score = 0.0

    is_anomaly = bool(prediction == -1)
    confidence = abs(score)

    return {
        "is_anomaly": is_anomaly,
        "confidence": round(confidence, 3),
        "model_status": "Model active",
    }


def calculate_severity(risk_score: int) -> str:
    if risk_score >= 85:
        return "CRITICAL"
    if risk_score >= 60:
        return "HIGH"
    if risk_score >= 35:
        return "MEDIUM"
    return "LOW"


def analyze_log(log: Dict[str, Any]) -> Dict[str, Any]:
    rules = evaluate_rules(log)
    ml_result = evaluate_ml_anomaly(log)

    risk_score = 0
    if "Brute-force password attack detected" in rules:
        risk_score += 35
    if "High request rate / possible DDoS attack" in rules:
        risk_score += 25
    if "Repeated login failures from one source" in rules:
        risk_score += 20
    if "Extreme traffic spike" in rules:
        risk_score += 25
    if ml_result["is_anomaly"]:
        risk_score += 40

    risk_score = min(risk_score + int(ml_result["confidence"] * 25), 100)
    severity = calculate_severity(risk_score)

    return {
        "risk_score": risk_score,
        "severity": severity,
        "reasons": rules if rules else ["Normal behavior"],
        "ml_anomaly": ml_result["is_anomaly"],
        "ml_confidence": ml_result["confidence"],
        "model_status": ml_result["model_status"],
    }
