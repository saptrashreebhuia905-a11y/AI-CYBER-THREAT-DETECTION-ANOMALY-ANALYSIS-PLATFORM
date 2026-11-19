# Sentinel AI — Cyber Threat Detection Platform

Sentinel AI is a local security-event monitoring demo with a React dashboard, FastAPI service, MongoDB persistence, password-based sign-in, rule-based checks, a data-driven robust-baseline anomaly model, alert triage, and a synthetic-event simulator.

## Features

- Authenticated log submission, search, filters, and event history.
- Automatic rule and baseline-anomaly scoring on every event, with high-risk events surfaced as alerts.
- Dashboard metrics and alert triage states: open, investigating, and resolved.
- User registration and sign-in. Set bootstrap admin credentials to create an administrator; other registrations use the analyst role.
- A data-only simulator that creates synthetic records in the local database without sending network traffic.

## Requirements

- Python 3.12
- Node.js 20.19+ or 22.12+
- MongoDB 7 or Docker Desktop with Docker Compose

## Start MongoDB

From the repository root, start the local MongoDB container:

```powershell
docker compose up -d mongodb
```

The Compose file binds MongoDB to `127.0.0.1` only and persists data in a Docker volume. If MongoDB is already installed locally, make sure its service is running on port `27017` instead.

To use MongoDB Atlas instead, create a cluster and database user in Atlas, allow only your current client IP in Network Access, and copy the driver's connection string. Put that URI in `backend\.env` as `MONGO_URI`; set a database name with `MONGO_DATABASE`. URL-encode any reserved characters in the database username or password. Do not share or commit the connection string.

## Configure and start the backend

In PowerShell:

```powershell
cd backend
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Edit `backend\.env`. For Atlas, set `MONGO_URI` to your Atlas connection string; otherwise use the local URI in `.env.example`. Set a long random `JWT_SECRET`. To bootstrap an admin on first start, also set `ADMIN_USERNAME` and a unique `ADMIN_PASSWORD` of at least 12 characters. Keep `.env` private; it is ignored by Git. If the bootstrap values are blank, register an analyst account from the frontend.

Generate a signing secret in PowerShell with:

```powershell
py -3.12 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copy the output into `JWT_SECRET` in `backend\.env`; do not share it.

Create the environment and run the API:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

The backend API and interactive docs are at `http://127.0.0.1:8000` and `http://127.0.0.1:8000/docs`. MongoDB must be available before the backend starts; startup creates indexes and the configured bootstrap admin.

## Start the frontend

Open a second PowerShell terminal:

```powershell
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal, usually `http://127.0.0.1:5173`. Vite proxies `/api` requests to FastAPI on port `8000`.

## Production deployment notes

Build the frontend with `npm run build` from `frontend`; serve the generated `frontend/dist` directory as static files. Route `/api/` from the same HTTPS origin to the FastAPI service, and keep MongoDB on a private network. Configure `MONGO_URI`, `MONGO_DATABASE`, and a stable `JWT_SECRET` of at least 32 characters in the backend environment. Set a unique bootstrap admin password, enable TLS, and do not expose the MongoDB port publicly. The local Compose configuration is for development, not a production database deployment.

## Run the synthetic event generator

Use the simulator page in the frontend for the easiest way to create normal, repeated-login-failure, or high-request-rate records. The standalone log generator requires a bearer token. After signing in, obtain a token from the `/api/v1/auth/login` response in the API docs, then set it in PowerShell:

```powershell
$env:SENTINEL_API_TOKEN = "<your-access-token>"
python ..\simulator\log_generator.py
```

Stop the continuous generator with `Ctrl+C`.

## API overview

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/v1/health` | API and MongoDB health |
| `POST` | `/api/v1/auth/register` | Register an analyst |
| `POST` | `/api/v1/auth/login` | Sign in and receive a bearer token |
| `GET` | `/api/v1/auth/me` | Current account |
| `GET` | `/api/v1/dashboard` | Event and alert summary |
| `POST` | `/api/v1/logs` | Validate, score, and store an event |
| `GET` | `/api/v1/logs` | Search and filter event history |
| `GET` | `/api/v1/alerts` | List and filter detected alerts |
| `PATCH` | `/api/v1/alerts/{alert_id}` | Update alert status and triage notes |
| `POST` | `/api/v1/simulator/run` | Add bounded synthetic test events |

Protected endpoints require `Authorization: Bearer <access-token>`. The API returns `503` if MongoDB becomes unavailable during an operation.

## Tests and checks

Run backend unit tests:

```powershell
cd backend
.\.venv\Scripts\python.exe -m unittest discover -s tests
```

Inspect the configured anomaly baseline:

```powershell
python -m ml_training.train
```

Run frontend checks:

```powershell
cd frontend
npm run lint
npm run build
```
