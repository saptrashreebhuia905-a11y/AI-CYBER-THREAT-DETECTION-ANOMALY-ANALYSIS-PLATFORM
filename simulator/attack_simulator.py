import requests, time

API_URL = "http://127.0.0.1:8000/api/v1/logs"
for i in range(15):
    payload = {
        "timestamp": "2026-10-20T15:00:00Z",
        "source_ip": "198.51.100.44",
        "user_id": "admin_root",
        "endpoint": "/api/v1/admin",
        "request_rate": 250,
        "login_status": "FAILED",
        "failed_attempts": 8
    }
    requests.post(API_URL, json=payload)
    time.sleep(0.2)
print("Attack simulated!")