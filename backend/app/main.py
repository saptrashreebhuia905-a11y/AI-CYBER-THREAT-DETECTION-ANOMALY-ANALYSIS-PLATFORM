from fastapi import FastAPI, status
from app.schemas import SecurityLogSchema
from app.database import connect_to_mongo, close_mongo_connection, get_logs_collection

app = FastAPI(title="Sentinel AI Backend", version="1.0.0")

@app.on_event("startup")
async def startup_db_client():
    await connect_to_mongo()

@app.on_event("shutdown")
async def shutdown_db_client():
    await close_mongo_connection()

@app.get("/")
def read_root():
    return {"status": "online", "message": "Sentinel AI Backend is running!"}

@app.post("/api/v1/logs", status_code=status.HTTP_201_CREATED)
async def ingest_log(log: SecurityLogSchema):
    collection = get_logs_collection()
    log_data = log.dict()
    result = await collection.insert_one(log_data)
    return {"status": "success", "inserted_id": str(result.inserted_id)}