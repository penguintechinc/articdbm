"""ArticDBM Manager API Schemas.

This package contains all Pydantic schema definitions for request/response
validation and serialization across the manager application.
"""

from manager.app.schemas.common import (
    BaseResponse,
    ErrorResponse,
    PaginationRequest,
    PaginationResponse,
    TagSchema,
    TimestampMixin,
)

__all__ = [
    "BaseResponse",
    "ErrorResponse",
    "PaginationRequest",
    "PaginationResponse",
    "TagSchema",
    "TimestampMixin",
]
