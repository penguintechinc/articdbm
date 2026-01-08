"""Pydantic schemas for application management"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.models.enums import DeploymentModel


class ApplicationCreate(BaseModel):
    """Schema for creating a new application"""
    name: str = Field(..., min_length=1, max_length=255, description="Application name")
    description: Optional[str] = Field(None, max_length=1000, description="Application description")
    deployment_model: DeploymentModel = Field(..., description="Deployment model (shared/separate)")
    tags: Optional[Dict[str, Any]] = Field(None, description="Optional tags for the application")

    model_config = {"use_enum_values": False}


class ApplicationUpdate(BaseModel):
    """Schema for updating an application"""
    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Application name")
    description: Optional[str] = Field(None, max_length=1000, description="Application description")
    tags: Optional[Dict[str, Any]] = Field(None, description="Tags for the application")

    model_config = {"use_enum_values": False}


class ApplicationResponse(BaseModel):
    """Schema for application response"""
    id: int = Field(..., description="Application ID")
    name: str = Field(..., description="Application name")
    description: Optional[str] = Field(None, description="Application description")
    deployment_model: DeploymentModel = Field(..., description="Deployment model")
    elder_entity_id: Optional[int] = Field(None, description="Elder entity ID")
    elder_service_id: Optional[int] = Field(None, description="Elder service ID")
    organization_id: int = Field(..., description="Organization ID")
    tags: Optional[Dict[str, Any]] = Field(None, description="Application tags")
    is_active: bool = Field(True, description="Whether the application is active")
    resource_count: int = Field(0, description="Number of resources associated with this application")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = {"use_enum_values": False, "from_attributes": True}


class Pagination(BaseModel):
    """Schema for pagination metadata"""
    total: int = Field(..., description="Total number of items")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Items per page")
    pages: int = Field(..., description="Total number of pages")


class ApplicationListResponse(BaseModel):
    """Schema for paginated list of applications"""
    applications: List[ApplicationResponse] = Field(..., description="List of applications")
    pagination: Pagination = Field(..., description="Pagination metadata")

    model_config = {"use_enum_values": False, "from_attributes": True}


class ElderSyncRequest(BaseModel):
    """Schema for requesting Elder synchronization"""
    sync_type: str = Field("full", description="Type of sync (full, incremental, selective)")
    resource_ids: Optional[List[int]] = Field(None, description="Optional list of resource IDs to sync")

    model_config = {"use_enum_values": False}


class ElderSyncResponse(BaseModel):
    """Schema for Elder synchronization response"""
    success: bool = Field(..., description="Whether the synchronization was successful")
    entities_synced: int = Field(0, description="Number of entities synchronized")
    services_synced: int = Field(0, description="Number of services synchronized")
    errors: List[str] = Field(default_factory=list, description="List of errors during synchronization")

    model_config = {"use_enum_values": False}
