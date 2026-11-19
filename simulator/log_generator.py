import os
import random
import time
from datetime import datetime, timezone

import requests

API_URL = "http://127.0.0.1:8000/api/v1/logs"
API_TOKEN = os.getenv("SENTINEL_API_TOKEN")

if not API_TOKEN:
    raise SystemExit("Set SENTINEL_API_TOKEN to a valid Sentinel bearer token before running the simulator.")

headers = {"Authorization": f"Bearer {API_TOKEN}"}

while True:
    payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": random.choice(["192.0.2.15", "198.51.100.42"]),
        "user_id": random.choice(["sim-user-101", "sim-user-102"]),
        "endpoint": "/simulated/activity",
        "request_rate": random.randint(5, 20),
        "login_status": random.choice(["SUCCESS", "FAILED"]),
        "failed_attempts": random.choice([0, 1]),
    }
    response = requests.post(API_URL, json=payload, headers=headers, timeout=5)
    response.raise_for_status()
    print(f"Stored synthetic event with risk score {response.json()['risk_score']}.")
    time.sleep(2)
