"""Pydantic schemas for resource management (databases and caches)."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, ConfigDict

from app.models.enums import (
    EngineType,
    ResourceType,
    ResourceStatus,
    TLSMode,
)


class ResourceCreate(BaseModel):
    """Schema for creating a new resource."""

    name: str = Field(..., min_length=1, max_length=255, description="Resource name")
    resource_type: ResourceType = Field(..., description="Type of resource (database or cache)")
    engine: EngineType = Field(..., description="Database or cache engine type")
    engine_version: Optional[str] = Field(None, description="Engine version (optional)")
    provider_id: str = Field(..., min_length=1, description="Provider ID")
    application_id: Optional[str] = Field(None, description="Associated application ID (optional)")
    instance_class: str = Field(..., min_length=1, description="Instance class or tier")
    storage_size_gb: int = Field(..., gt=0, description="Storage size in GB")
    multi_az: bool = Field(False, description="Multi-availability zone deployment")
    replicas: int = Field(0, ge=0, description="Number of replicas")
    tls_mode: TLSMode = Field(TLSMode.REQUIRED, description="TLS enforcement mode")
    tags: Dict[str, str] = Field(default_factory=dict, description="Resource tags")

    model_config = ConfigDict(use_enum_values=True)


class ResourceUpdate(BaseModel):
    """Schema for updating resource configuration."""

    instance_class: Optional[str] = Field(None, min_length=1, description="New instance class")
    storage_size_gb: Optional[int] = Field(None, gt=0, description="New storage size in GB")
    replicas: Optional[int] = Field(None, ge=0, description="New number of replicas")
    tls_mode: Optional[TLSMode] = Field(None, description="New TLS enforcement mode")
    tags: Optional[Dict[str, str]] = Field(None, description="Updated resource tags")

    model_config = ConfigDict(use_enum_values=True)


class ResourceResponse(BaseModel):
    """Complete resource information response."""

    id: str = Field(..., description="Resource ID")
    name: str = Field(..., description="Resource name")
    resource_type: ResourceType = Field(..., description="Resource type")
    engine: EngineType = Field(..., description="Engine type")
    engine_version: Optional[str] = Field(None, description="Engine version")
    provider_id: str = Field(..., description="Provider ID")
    application_id: Optional[str] = Field(None, description="Application ID")
    instance_class: str = Field(..., description="Instance class")
    storage_size_gb: int = Field(..., description="Storage size in GB")
    multi_az: bool = Field(..., description="Multi-AZ enabled")
    replicas: int = Field(..., description="Number of replicas")
    tls_mode: TLSMode = Field(..., description="TLS mode")
    tags: Dict[str, str] = Field(..., description="Resource tags")
    endpoint: str = Field(..., description="Resource endpoint/hostname")
    port: int = Field(..., ge=1, le=65535, description="Connection port")
    database_name: Optional[str] = Field(None, description="Database name (for databases)")
    status: ResourceStatus = Field(..., description="Current resource status")
    status_message: str = Field(..., description="Status details or error message")
    provider_resource_id: Optional[str] = Field(None, description="Provider-specific resource ID")
    elder_entity_id: Optional[str] = Field(None, description="Elder entity reference ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True)


class ResourceListResponse(BaseModel):
    """Paginated list of resources."""

    resources: List[ResourceResponse] = Field(..., description="List of resources")
    total: int = Field(..., ge=0, description="Total resource count")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether next page exists")
    has_previous: bool = Field(..., description="Whether previous page exists")


class ResourceMetricsRequest(BaseModel):
    """Request for resource metrics."""

    resource_id: str = Field(..., description="Resource ID")
    metric_name: str = Field(..., min_length=1, description="Metric name to retrieve")
    start_time: datetime = Field(..., description="Metrics start time")
    end_time: datetime = Field(..., description="Metrics end time")


class ResourceScaleRequest(BaseModel):
    """Request to scale a resource."""

    instance_class: Optional[str] = Field(None, min_length=1, description="New instance class")
    storage_size_gb: Optional[int] = Field(None, gt=0, description="New storage size in GB")
    replicas: Optional[int] = Field(None, ge=0, description="New number of replicas")

    model_config = ConfigDict(use_enum_values=True)
