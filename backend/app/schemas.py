from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class SecurityLogSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    timestamp: datetime = Field(..., description="Event timestamp in ISO 8601 format")
    source_ip: IPvAnyAddress = Field(..., description="Client IP address")
    user_id: str = Field(..., min_length=1, max_length=128, description="User account ID")
    endpoint: str = Field(..., min_length=1, max_length=512, description="API route accessed")
    request_rate: int = Field(..., ge=0, le=1_000_000, description="Requests per minute")
    login_status: Literal["SUCCESS", "FAILED"]
    failed_attempts: int = Field(default=0, ge=0, le=1_000_000)


class UserRegisterSchema(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password: str = Field(..., min_length=12, max_length=128)


class UserLoginSchema(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class UserPublicSchema(BaseModel):
    username: str
    role: Literal["admin", "analyst"]


class AlertUpdateSchema(BaseModel):
    status: Literal["open", "investigating", "resolved"]
    notes: str | None = Field(default=None, max_length=2000)
    assigned_to: str | None = Field(default=None, max_length=64)


class SimulatorRequestSchema(BaseModel):
    scenario: Literal["normal", "brute_force", "high_request_rate"]
    event_count: int = Field(default=1, ge=1, le=20)
