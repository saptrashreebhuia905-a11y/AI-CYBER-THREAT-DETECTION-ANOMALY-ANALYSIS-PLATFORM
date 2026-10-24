from pydantic import BaseModel, Field
from typing import Optional

class SecurityLogSchema(BaseModel):
    timestamp: str = Field(..., description="ISO timestamp")
    source_ip: str = Field(..., description="Client IP address")
    user_id: str = Field(..., description="User account ID")
    endpoint: str = Field(..., description="API route accessed")
    request_rate: int = Field(..., description="Requests per minute")
    login_status: str = Field(..., description="SUCCESS or FAILED")
    failed_attempts: Optional[int] = Field(0, description="Failed login count")