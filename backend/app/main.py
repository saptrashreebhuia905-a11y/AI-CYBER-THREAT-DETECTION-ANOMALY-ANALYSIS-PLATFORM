import logging
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from app.auth import create_initial_admin, get_current_user, require_analyst, router as auth_router
from app.database import (
    check_database_connection,
    close_mongo_connection,
    connect_to_mongo,
    get_logs_collection,
)
from app.detection.aggregator import evaluate_event
from app.schemas import AlertUpdateSchema, SecurityLogSchema, SimulatorRequestSchema

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    try:
        await connect_to_mongo()
        await create_initial_admin()
        yield
    finally:
        await close_mongo_connection()


app = FastAPI(title="Sentinel AI Backend", version="1.0.0", lifespan=lifespan)
app.include_router(auth_router)


@app.exception_handler(PyMongoError)
async def handle_database_error(_, exc: PyMongoError):
    logger.error("MongoDB operation failed: %s", exc)
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "MongoDB is unavailable or the database operation failed."},
    )


def _serialize_document(document: dict) -> dict:
    document["_id"] = str(document["_id"])
    return document


async def _store_log(log: SecurityLogSchema) -> dict:
    log_data = log.model_dump()
    log_data["source_ip"] = str(log.source_ip)
    detection = evaluate_event(log_data)
    log_data.update(
        {
            "created_at": datetime.now(timezone.utc),
            **detection,
            "alert_status": "open" if detection["is_alert"] else None,
            "alert_notes": "",
            "assigned_to": None,
        }
    )
    result = await get_logs_collection().insert_one(log_data)
    return {
        "status": "success",
        "inserted_id": str(result.inserted_id),
        "risk_score": detection["risk_score"],
        "severity": detection["severity"],
        "reasons": detection["reasons"],
        "is_alert": detection["is_alert"],
    }


@app.get("/")
def read_root():
    return {"status": "online", "message": "Sentinel AI Backend is running!"}


@app.get("/api/v1/health")
async def read_health():
    try:
        connected = await check_database_connection()
    except ServerSelectionTimeoutError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="FastAPI is running, but MongoDB is unavailable.",
        ) from None
    if not connected:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="MongoDB is not initialized.")
    return {"status": "online", "database": "connected"}


@app.post("/api/v1/logs", status_code=status.HTTP_201_CREATED)
async def ingest_log(log: SecurityLogSchema, _: dict = Depends(get_current_user)):
    return await _store_log(log)


@app.post("/api/v1/simulator/run")
async def run_simulator(
    request: SimulatorRequestSchema,
    _: dict = Depends(require_analyst),
):
    now = datetime.now(timezone.utc)
    scenarios = {
        "normal": ("203.0.113.42", "/simulated/activity", 8, "SUCCESS", 0),
        "brute_force": ("198.51.100.44", "/simulated/login", 20, "FAILED", 8),
        "high_request_rate": ("198.51.100.52", "/simulated/api", 180, "SUCCESS", 0),
    }
    source_ip, endpoint, request_rate, login_status, failed_attempts = scenarios[request.scenario]
    results = []

    for index in range(request.event_count):
        event = SecurityLogSchema(
            timestamp=now + timedelta(milliseconds=index),
            source_ip=source_ip,
            user_id=f"simulated-{request.scenario}",
            endpoint=endpoint,
            request_rate=request_rate,
            login_status=login_status,
            failed_attempts=failed_attempts,
        )
        results.append(await _store_log(event))

    return {"scenario": request.scenario, "events_created": len(results), "results": results}


@app.get("/api/v1/logs")
async def list_logs(
    source_ip: str | None = None,
    login_status: str | None = Query(default=None, pattern="^(SUCCESS|FAILED)$"),
    min_risk: int | None = Query(default=None, ge=0, le=100),
    search: str | None = Query(default=None, min_length=1, max_length=128),
    limit: int = Query(default=50, ge=1, le=500),
    skip: int = Query(default=0, ge=0),
    _: dict = Depends(get_current_user),
):
    filters: dict = {}
    if source_ip:
        filters["source_ip"] = source_ip
    if login_status:
        filters["login_status"] = login_status
    if min_risk is not None:
        filters["risk_score"] = {"$gte": min_risk}
    if search:
        pattern = re.escape(search)
        filters["$or"] = [
            {"source_ip": {"$regex": pattern, "$options": "i"}},
            {"user_id": {"$regex": pattern, "$options": "i"}},
            {"endpoint": {"$regex": pattern, "$options": "i"}},
        ]

    collection = get_logs_collection()
    total = await collection.count_documents(filters)
    cursor = collection.find(filters).sort("timestamp", -1).skip(skip).limit(limit)
    items = [_serialize_document(document) async for document in cursor]
    return {"items": items, "total": total, "limit": limit, "skip": skip}


@app.get("/api/v1/alerts")
async def list_alerts(
    alert_status: str | None = Query(default=None, alias="status", pattern="^(open|investigating|resolved)$"),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    limit: int = Query(default=50, ge=1, le=500),
    skip: int = Query(default=0, ge=0),
    _: dict = Depends(get_current_user),
):
    filters: dict = {"is_alert": True}
    if alert_status:
        filters["alert_status"] = alert_status
    if severity:
        filters["severity"] = severity

    collection = get_logs_collection()
    total = await collection.count_documents(filters)
    cursor = collection.find(filters).sort("created_at", -1).skip(skip).limit(limit)
    items = [_serialize_document(document) async for document in cursor]
    return {"items": items, "total": total, "limit": limit, "skip": skip}


@app.patch("/api/v1/alerts/{alert_id}")
async def update_alert(
    alert_id: str,
    update: AlertUpdateSchema,
    user: dict = Depends(require_analyst),
):
    try:
        object_id = ObjectId(alert_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid alert ID.") from None

    fields = update.model_dump()
    fields["updated_at"] = datetime.now(timezone.utc)
    if fields["assigned_to"] is None:
        fields["assigned_to"] = user["username"]
    result = await get_logs_collection().update_one(
        {"_id": object_id, "is_alert": True},
        {"$set": {"alert_status": fields["status"], "alert_notes": fields["notes"], "assigned_to": fields["assigned_to"], "updated_at": fields["updated_at"]}},
    )
    if result.matched_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    updated = await get_logs_collection().find_one({"_id": object_id})
    return _serialize_document(updated)


@app.get("/api/v1/dashboard")
async def read_dashboard(_: dict = Depends(get_current_user)):
    collection = get_logs_collection()
    now = datetime.now(timezone.utc)
    recent_threshold = now - timedelta(hours=24)
    total_logs = await collection.count_documents({})
    alert_count = await collection.count_documents({"is_alert": True})
    open_alerts = await collection.count_documents({"is_alert": True, "alert_status": "open"})
    investigating_alerts = await collection.count_documents({"is_alert": True, "alert_status": "investigating"})
    resolved_alerts = await collection.count_documents({"is_alert": True, "alert_status": "resolved"})
    recent_high_risk = await collection.count_documents(
        {"timestamp": {"$gte": recent_threshold}, "risk_score": {"$gte": 40}}
    )
    recent_cursor = collection.find({"is_alert": True}).sort("created_at", -1).limit(5)
    recent_alerts = [_serialize_document(document) async for document in recent_cursor]

    return {
        "total_logs": total_logs,
        "total_alerts": alert_count,
        "open_alerts": open_alerts,
        "investigating_alerts": investigating_alerts,
        "resolved_alerts": resolved_alerts,
        "high_risk_last_24h": recent_high_risk,
        "recent_alerts": recent_alerts,
    }
