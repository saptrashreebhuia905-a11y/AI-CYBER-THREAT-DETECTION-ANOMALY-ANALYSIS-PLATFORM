import time, random, requests
from datetime import datetime

API_URL = "http://127.0.0.1:8000/api/v1/logs"
while True:
    payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": random.choice(["192.168.1.15", "10.0.0.42"]),
        "user_id": random.choice(["user_101", "user_102"]),
        "endpoint": "/api/v1/login",
        "request_rate": random.randint(5, 20),
        "login_status": random.choice(["SUCCESS", "FAILED"]),
        "failed_attempts": random.choice([0, 1])
    }
    requests.post(API_URL, json=payload)
    time.sleep(2)