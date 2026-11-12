from __future__ import annotations

from fastapi import FastAPI, status
from fastapi.middleware.cors import CORSMiddleware

from app.database import close_mongo_connection, connect_to_mongo, get_logs_collection
from app.detection.agent import analyze_log
from app.schemas import SecurityLogSchema

app = FastAPI(title="Sentinel AI Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()


@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()


@app.get("/")
def read_root():
    return {"status": "online", "message": "Sentinel AI Backend is running!"}


@app.get("/api/v1/health")
def health_check():
    return {"status": "healthy"}


@app.post("/api/v1/logs", status_code=status.HTTP_201_CREATED)
async def ingest_log(log: SecurityLogSchema):
    collection = get_logs_collection()
    assessment = analyze_log(log.model_dump())

    payload = log.model_dump()
    payload["risk_score"] = assessment["risk_score"]
    payload["severity"] = assessment["severity"]
    payload["reasons"] = assessment["reasons"]
    payload["ml_anomaly"] = assessment["ml_anomaly"]
    payload["ml_confidence"] = assessment["ml_confidence"]
    payload["model_status"] = assessment["model_status"]

    result = await collection.insert_one(payload)
    return {
        "status": "success",
        "inserted_id": str(result.inserted_id),
        "risk_score": assessment["risk_score"],
        "severity": assessment["severity"],
        "reasons": assessment["reasons"],
    }


@app.get("/api/v1/alerts")
async def recent_alerts():
    collection = get_logs_collection()
    documents = await collection.find({}).sort("timestamp", -1).limit(20).to_list(length=20)
    return {"alerts": documents}
