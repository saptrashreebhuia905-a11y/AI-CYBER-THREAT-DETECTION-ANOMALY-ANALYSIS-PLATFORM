from app.detection.ml_model import evaluate_anomaly
from app.detection.rules import evaluate_rules

ALERT_THRESHOLD = 40


def evaluate_event(log: dict) -> dict:
    rule_score, rule_reasons = evaluate_rules(log)
    anomaly_detected, anomaly_score = evaluate_anomaly(log)

    reasons = list(rule_reasons)
    risk_score = rule_score
    if anomaly_detected:
        risk_score += 25
        reasons.append("Machine-learning anomaly detected")

    risk_score = min(risk_score, 100)
    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 60:
        severity = "high"
    elif risk_score >= ALERT_THRESHOLD:
        severity = "medium"
    else:
        severity = "low"

    return {
        "risk_score": risk_score,
        "severity": severity,
        "reasons": reasons,
        "anomaly_detected": anomaly_detected,
        "anomaly_score": round(anomaly_score, 4),
        "is_alert": risk_score >= ALERT_THRESHOLD,
    }
