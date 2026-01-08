"""Pydantic schemas for credentials"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from app.models.enums import CredentialType


class CredentialCreate(BaseModel):
    """Schema for creating a new credential"""

    name: str = Field(..., min_length=1, description="Credential name")
    resource_id: int = Field(..., description="Resource ID")
    application_id: Optional[int] = Field(None, description="Application ID")
    credential_type: CredentialType = Field(..., description="Type of credential")
    permissions: list[str] = Field(
        default=["read"], description="Permissions for this credential"
    )
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")
    jwt_subject: Optional[str] = Field(None, description="JWT subject claim")
    jwt_claims: Optional[dict] = Field(
        default=None, description="Additional JWT claims"
    )

    class Config:
        use_enum_values = False


class CredentialResponse(BaseModel):
    """Schema for credential response with sensitive data on create"""

    id: int
    name: str
    resource_id: int
    application_id: Optional[int]
    credential_type: CredentialType
    username: Optional[str] = None
    password: Optional[str] = Field(
        None, description="Only included on credential creation"
    )
    connection_string: Optional[str] = None
    iam_role_arn: Optional[str] = None
    jwt_token: Optional[str] = Field(
        None, description="Only included on credential creation"
    )
    mtls_cert: Optional[str] = None
    mtls_key: Optional[str] = Field(
        None, description="Only included on credential creation"
    )
    permissions: list[str]
    expires_at: Optional[datetime] = None
    auto_rotate: bool
    rotation_interval_days: int
    last_rotated_at: Optional[datetime] = None
    next_rotation_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime = Field(..., alias="created_on")

    class Config:
        from_attributes = True
        use_enum_values = False
        populate_by_name = True


class CredentialListResponse(BaseModel):
    """Schema for list of credentials without sensitive data"""

    id: int
    name: str
    resource_id: int
    application_id: Optional[int]
    credential_type: CredentialType
    permissions: list[str]
    expires_at: Optional[datetime] = None
    auto_rotate: bool
    rotation_interval_days: int
    last_rotated_at: Optional[datetime] = None
    next_rotation_at: Optional[datetime] = None
    is_active: bool
    created_at: datetime = Field(..., alias="created_on")

    class Config:
        from_attributes = True
        use_enum_values = False
        populate_by_name = True


class CredentialRotateRequest(BaseModel):
    """Schema for credential rotation request"""

    force: bool = Field(default=False, description="Force rotation even if not due")

    class Config:
        use_enum_values = False


class AutoRotateConfigRequest(BaseModel):
    """Schema for auto-rotation configuration"""

    auto_rotate: bool = Field(..., description="Enable or disable auto-rotation")
    rotation_interval_days: int = Field(
        default=30, ge=1, description="Days between rotations"
    )

    class Config:
        use_enum_values = False
