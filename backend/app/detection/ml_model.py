import csv
from pathlib import Path

FEATURES = ("request_rate", "failed_attempts")
ANOMALY_THRESHOLD = 3.5
DATASET_PATH = Path(__file__).resolve().parents[2] / "ml_training" / "dataset.csv"


def _load_baseline() -> dict[str, list[float]]:
    try:
        with DATASET_PATH.open(encoding="utf-8", newline="") as dataset_file:
            reader = csv.DictReader(dataset_file)
            if not reader.fieldnames or any(feature not in reader.fieldnames for feature in FEATURES):
                raise ValueError(f"Training data must include columns: {', '.join(FEATURES)}")
            values = {feature: [] for feature in FEATURES}
            for row in reader:
                for feature in FEATURES:
                    values[feature].append(float(row[feature]))
    except OSError as exc:
        raise RuntimeError(f"Could not read anomaly baseline dataset at {DATASET_PATH}") from exc

    if any(len(feature_values) < 4 for feature_values in values.values()):
        raise ValueError("Anomaly baseline dataset must contain at least four complete rows.")
    return values


def _quantile(sorted_values: list[float], fraction: float) -> float:
    position = (len(sorted_values) - 1) * fraction
    lower_index = int(position)
    upper_index = min(lower_index + 1, len(sorted_values) - 1)
    weight = position - lower_index
    return sorted_values[lower_index] * (1 - weight) + sorted_values[upper_index] * weight


def _fit_baseline(values: dict[str, list[float]]) -> dict[str, tuple[float, float]]:
    model = {}
    for feature, samples in values.items():
        ordered = sorted(samples)
        median = _quantile(ordered, 0.5)
        interquartile_range = _quantile(ordered, 0.75) - _quantile(ordered, 0.25)
        robust_scale = max(interquartile_range / 1.349, 1.0)
        model[feature] = (median, robust_scale)
    return model


_model = _fit_baseline(_load_baseline())


def evaluate_anomaly(log: dict) -> tuple[bool, float]:
    deviations = []
    for feature, (median, scale) in _model.items():
        value = float(log.get(feature, 0))
        deviations.append(abs(value - median) / scale)

    anomaly_score = max(deviations)
    return anomaly_score >= ANOMALY_THRESHOLD, round(anomaly_score, 4)


def get_model_profile() -> dict:
    return {
        "dataset": str(DATASET_PATH),
        "features": list(FEATURES),
        "baseline_rows": len(_load_baseline()[FEATURES[0]]),
        "threshold": ANOMALY_THRESHOLD,
        "method": "median and interquartile-range robust deviation",
    }
