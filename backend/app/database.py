from typing import Any

from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ASCENDING, DESCENDING

from app.settings import MONGO_DATABASE, MONGO_URI


client: Any = None
database: Any = None

async def connect_to_mongo():
    global client, database
    client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    database = client[MONGO_DATABASE]
    await client.admin.command("ping")
    await database.security_logs.create_index([("timestamp", DESCENDING)])
    await database.security_logs.create_index([("source_ip", ASCENDING), ("timestamp", DESCENDING)])
    await database.security_logs.create_index([("alert_status", ASCENDING), ("created_at", DESCENDING)])
    await database.users.create_index("username", unique=True)

async def close_mongo_connection():
    if client is not None:
        client.close()

def get_logs_collection():
    if database is None:
        raise RuntimeError("MongoDB has not been initialized")
    return database.security_logs

def get_users_collection():
    if database is None:
        raise RuntimeError("MongoDB has not been initialized")
    return database.users

async def check_database_connection():
    if client is None:
        return False
    await client.admin.command("ping")
    return True