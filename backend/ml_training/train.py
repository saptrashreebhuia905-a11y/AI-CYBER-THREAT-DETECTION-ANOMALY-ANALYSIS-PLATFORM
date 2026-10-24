import pandas as pd
from sklearn.ensemble import IsolationForest
import pickle

data = {"request_rate": [10, 12, 15, 8, 20, 14, 11, 25, 9, 13], "failed_attempts": [0, 0, 0, 1, 0, 0, 0, 0, 1, 0]}
df = pd.DataFrame(data)
model = IsolationForest(contamination=0.1, random_state=42)
model.fit(df)

with open("../backend/ml_training/model.pkl", "wb") as f:
    pickle.dump(model, f)
print("Model trained successfully!")