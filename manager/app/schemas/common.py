"""Common Pydantic schemas for ArticDBM Manager API.

This module contains shared schema definitions used across the application,
including pagination, timestamps, and response wrappers.
"""

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class TagSchema(BaseModel):
    """Tag schema with key-value pairs.

    Attributes:
        key: Tag identifier/name
        value: Tag value/content
    """

    key: str = Field(..., min_length=1, max_length=255, description="Tag key")
    value: str = Field(..., min_length=1, max_length=1024, description="Tag value")

    model_config = ConfigDict(str_strip_whitespace=True, json_schema_extra={"examples": [{"key": "environment", "value": "production"}]})


class PaginationRequest(BaseModel):
    """Pagination request parameters.

    Attributes:
        page: Page number (1-indexed)
        per_page: Number of items per page
    """

    page: int = Field(default=1, ge=1, description="Page number (1-indexed)")
    per_page: int = Field(default=20, ge=1, le=100, description="Items per page (1-100)")

    model_config = ConfigDict(json_schema_extra={"examples": [{"page": 1, "per_page": 20}]})


class PaginationResponse(BaseModel):
    """Pagination response metadata.

    Attributes:
        page: Current page number
        per_page: Items per page
        total: Total number of items
        total_pages: Total number of pages
    """

    page: int = Field(..., ge=1, description="Current page number")
    per_page: int = Field(..., ge=1, description="Items per page")
    total: int = Field(..., ge=0, description="Total item count")
    total_pages: int = Field(..., ge=0, description="Total page count")

    model_config = ConfigDict(json_schema_extra={"examples": [{"page": 1, "per_page": 20, "total": 100, "total_pages": 5}]})


class TimestampMixin(BaseModel):
    """Mixin for timestamp fields.

    Attributes:
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(from_attributes=True)


class BaseResponse(BaseModel):
    """Base response schema for successful API responses.

    Attributes:
        success: Response success status
        message: Optional response message
    """

    success: bool = Field(default=True, description="Response success status")
    message: Optional[str] = Field(default=None, description="Optional response message")

    model_config = ConfigDict(json_schema_extra={"examples": [{"success": True, "message": "Operation completed successfully"}]})


class ErrorResponse(BaseModel):
    """Error response schema for failed API requests.

    Attributes:
        success: Always False for error responses
        error: Error message/code
        details: Optional detailed error information
    """

    success: bool = Field(default=False, description="Response success status")
    error: str = Field(..., min_length=1, description="Error message or code")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Optional detailed error information")

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"success": False, "error": "VALIDATION_ERROR", "details": {"field": "email", "reason": "Invalid email format"}}
            ]
        }
    )
