from motor.motor_asyncio import AsyncIOMotorClient
import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

class Database:
    client: AsyncIOMotorClient = None
    db = None

db = Database()

async def connect_to_mongo():
    db.client = AsyncIOMotorClient(MONGO_URI)
    db.db = db.client.sentinel_ai_db
    print("Successfully connected to MongoDB!")

async def close_mongo_connection():
    db.client.close()

def get_logs_collection():
    return db.db.security_logs