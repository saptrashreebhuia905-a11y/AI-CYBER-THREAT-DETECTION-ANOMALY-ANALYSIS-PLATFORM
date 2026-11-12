import pickle
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest


def train_model():
    data = [
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

    df = pd.DataFrame(data)
    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(df[["request_rate", "failed_attempts"]])

    output_path = Path(__file__).resolve().parent / "model.pkl"
    with open(output_path, "wb") as f:
        pickle.dump(model, f)

    print(f"Model trained successfully and saved to: {output_path}")


if __name__ == "__main__":
    train_model()
