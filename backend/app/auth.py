import base64
import binascii
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError
from pymongo.errors import DuplicateKeyError

from app.database import get_users_collection
from app.schemas import UserLoginSchema, UserRegisterSchema
from app.settings import ADMIN_PASSWORD, ADMIN_USERNAME, JWT_SECRET

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

TOKEN_LIFETIME_MINUTES = 60
PASSWORD_HASH_ITERATIONS = 310_000
bearer_scheme = HTTPBearer(auto_error=False)


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS)
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${_encode_bytes(salt)}${_encode_bytes(digest)}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored_hash.split("$")
        iterations = int(iteration_text)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 1_000_000:
            return False
        salt = base64.urlsafe_b64decode(salt_text + "=" * (-len(salt_text) % 4))
        expected = base64.urlsafe_b64decode(digest_text + "=" * (-len(digest_text) % 4))
    except (ValueError, TypeError, binascii.Error):
        return False

    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def create_access_token(username: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
    return jwt.encode({"sub": username, "exp": expires_at}, JWT_SECRET, algorithm="HS256")


async def create_initial_admin() -> None:
    username = ADMIN_USERNAME
    password = ADMIN_PASSWORD
    if not username and not password:
        logger.info("No bootstrap admin configured; new registrations will use the analyst role.")
        return
    if not username or not password or len(password) < 12:
        raise RuntimeError("Set both ADMIN_USERNAME and an ADMIN_PASSWORD of at least 12 characters.")

    try:
        credentials = UserRegisterSchema(username=username.strip(), password=password)
    except ValidationError as exc:
        raise RuntimeError("Bootstrap admin credentials are invalid; check ADMIN_USERNAME and ADMIN_PASSWORD.") from exc

    normalized_username = credentials.username.lower()
    users = get_users_collection()
    existing_user = await users.find_one({"username": normalized_username})
    if existing_user is None:
        await users.insert_one(
            {
                "username": normalized_username,
                "password_hash": hash_password(credentials.password),
                "role": "admin",
                "created_at": datetime.now(timezone.utc),
            }
        )
        logger.info("Created configured bootstrap administrator.")
    elif existing_user.get("role") != "admin":
        await users.update_one(
            {"_id": existing_user["_id"]},
            {"$set": {"role": "admin"}},
        )
        logger.info("Promoted the configured bootstrap account to administrator.")


def public_user(user: dict) -> dict:
    return {"username": user["username"], "role": user["role"]}


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> dict:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Sign in to access this resource.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized

    try:
        claims = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=["HS256"])
        username = claims.get("sub")
    except InvalidTokenError:
        raise unauthorized from None

    if not isinstance(username, str):
        raise unauthorized

    user = await get_users_collection().find_one({"username": username})
    if user is None:
        raise unauthorized
    return user


def require_analyst(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] not in {"admin", "analyst"}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Analyst access is required.")
    return user


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegisterSchema):
    username = payload.username.lower()
    user = {
        "username": username,
        "password_hash": hash_password(payload.password),
        "role": "analyst",
        "created_at": datetime.now(timezone.utc),
    }

    try:
        await get_users_collection().insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="That username is already registered.") from None

    return {
        "access_token": create_access_token(username),
        "token_type": "bearer",
        "user": public_user(user),
    }


@router.post("/login")
async def login(payload: UserLoginSchema):
    user = await get_users_collection().find_one({"username": payload.username.lower()})
    if user is None or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "access_token": create_access_token(user["username"]),
        "token_type": "bearer",
        "user": public_user(user),
    }


@router.get("/me")
async def read_current_user(user: dict = Depends(get_current_user)):
    return public_user(user)
