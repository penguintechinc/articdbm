"""
Pydantic schemas for cloud providers and MarchProxy configuration.

Provides request/response schemas for:
- Provider management (CRUD operations)
- Provider health testing
- MarchProxy configuration and status
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.enums import ProviderType, ResourceStatus


# ========================
# Provider Schemas
# ========================


class ProviderCreate(BaseModel):
    """Schema for creating a new cloud provider."""

    name: str = Field(..., min_length=1, max_length=255, description="Provider name")
    provider_type: ProviderType = Field(..., description="Type of infrastructure provider")
    configuration: dict = Field(
        default_factory=dict,
        description="Provider-specific configuration (kubeconfig, credentials, regions, etc)",
    )
    credentials_secret_name: Optional[str] = Field(
        None,
        max_length=255,
        description="Reference to secret management system",
    )
    is_default: bool = Field(
        False,
        description="Set as default provider for new resources",
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "name": "Production AWS",
                "provider_type": "aws",
                "configuration": {
                    "region": "us-east-1",
                    "vpc_id": "vpc-12345678",
                },
                "credentials_secret_name": "aws-prod-credentials",
                "is_default": True,
            }
        }


class ProviderUpdate(BaseModel):
    """Schema for updating a cloud provider."""

    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Provider name")
    configuration: Optional[dict] = Field(
        None,
        description="Provider-specific configuration",
    )
    credentials_secret_name: Optional[str] = Field(
        None,
        max_length=255,
        description="Reference to secret management system",
    )
    is_default: Optional[bool] = Field(
        None,
        description="Set as default provider for new resources",
    )
    is_active: Optional[bool] = Field(
        None,
        description="Activate or deactivate the provider",
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "name": "Production AWS Updated",
                "configuration": {
                    "region": "us-west-2",
                },
                "is_active": True,
            }
        }


class ProviderResponse(BaseModel):
    """Schema for provider response with sanitized configuration."""

    id: int = Field(..., description="Provider ID")
    name: str = Field(..., description="Provider name")
    provider_type: ProviderType = Field(..., description="Type of infrastructure provider")
    configuration: Dict[str, Any] = Field(
        ...,
        description="Provider-specific configuration (secrets removed)",
    )
    is_default: bool = Field(..., description="Is default provider")
    is_active: bool = Field(..., description="Is provider active")
    status: str = Field(
        ...,
        description="Provider health status: healthy, degraded, unhealthy, unknown",
    )
    last_health_check: Optional[datetime] = Field(
        None,
        description="Timestamp of last health check",
    )
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        """Pydantic configuration."""

        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "name": "Production AWS",
                "provider_type": "aws",
                "configuration": {
                    "region": "us-east-1",
                    "vpc_id": "vpc-12345678",
                },
                "is_default": True,
                "is_active": True,
                "status": "healthy",
                "last_health_check": "2025-01-08T10:30:00Z",
                "created_at": "2025-01-01T00:00:00Z",
                "updated_at": "2025-01-08T10:30:00Z",
            }
        }


class ProviderListResponse(BaseModel):
    """Schema for list of providers."""

    providers: List[ProviderResponse] = Field(
        default_factory=list,
        description="List of provider responses",
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "providers": [
                    {
                        "id": 1,
                        "name": "Production AWS",
                        "provider_type": "aws",
                        "configuration": {},
                        "is_default": True,
                        "is_active": True,
                        "status": "healthy",
                        "last_health_check": "2025-01-08T10:30:00Z",
                        "created_at": "2025-01-01T00:00:00Z",
                        "updated_at": "2025-01-08T10:30:00Z",
                    }
                ]
            }
        }


class ProviderTestRequest(BaseModel):
    """Schema for testing provider connectivity."""

    id: int = Field(..., gt=0, description="Provider ID to test")

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "id": 1,
            }
        }


class ProviderTestResponse(BaseModel):
    """Schema for provider test result."""

    success: bool = Field(..., description="Test passed or failed")
    message: str = Field(..., description="Test result message")
    details: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional test details (latency, version, etc)",
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "success": True,
                "message": "Provider is healthy and accessible",
                "details": {
                    "latency_ms": 42,
                    "version": "v1.28.0",
                    "nodes": 5,
                    "timestamp": "2025-01-08T10:30:00Z",
                },
            }
        }


# ========================
# MarchProxy Schemas
# ========================


class MarchProxyConfigRequest(BaseModel):
    """Schema for MarchProxy configuration request."""

    enabled: bool = Field(
        ...,
        description="Enable MarchProxy routing for this resource",
    )
    listen_port: int = Field(
        ...,
        gt=0,
        le=65535,
        description="Port MarchProxy listens on",
    )
    connection_rate_limit: int = Field(
        ...,
        gt=0,
        description="Max concurrent connections",
    )
    query_rate_limit: int = Field(
        ...,
        gt=0,
        description="Max queries per second",
    )
    enable_sql_injection_detection: bool = Field(
        ...,
        description="Enable SQL injection detection and blocking",
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "enabled": True,
                "listen_port": 3306,
                "connection_rate_limit": 100,
                "query_rate_limit": 1000,
                "enable_sql_injection_detection": True,
            }
        }


class MarchProxyStatusResponse(BaseModel):
    """Schema for MarchProxy status response."""

    connected: bool = Field(
        ...,
        description="MarchProxy is connected and responding",
    )
    version: Optional[str] = Field(
        None,
        description="MarchProxy version",
    )
    configured_routes: int = Field(
        ...,
        ge=0,
        description="Number of configured routes",
    )
    routes: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of configured routes with status",
    )

    class Config:
        """Pydantic configuration."""

        json_schema_extra = {
            "example": {
                "connected": True,
                "version": "2.0.0",
                "configured_routes": 2,
                "routes": [
                    {
                        "name": "prod-mysql",
                        "resource_id": 1,
                        "listen_port": 3306,
                        "backend_host": "db.internal",
                        "backend_port": 3306,
                        "status": "healthy",
                        "active_connections": 42,
                    },
                    {
                        "name": "prod-postgres",
                        "resource_id": 2,
                        "listen_port": 5432,
                        "backend_host": "db.internal",
                        "backend_port": 5432,
                        "status": "healthy",
                        "active_connections": 28,
                    },
                ],
            }
        }
