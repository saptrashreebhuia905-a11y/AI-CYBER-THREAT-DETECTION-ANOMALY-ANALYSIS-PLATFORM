import os

import requests

API_URL = "http://127.0.0.1:8000/api/v1/simulator/run"
API_TOKEN = os.getenv("SENTINEL_API_TOKEN")

if not API_TOKEN:
    raise SystemExit("Set SENTINEL_API_TOKEN to a valid Sentinel bearer token before running the simulator.")

response = requests.post(
    API_URL,
    json={"scenario": "brute_force", "event_count": 15},
    headers={"Authorization": f"Bearer {API_TOKEN}"},
    timeout=15,
)
response.raise_for_status()
print(f"Created {response.json()['events_created']} synthetic brute-force test events in the local database.")
