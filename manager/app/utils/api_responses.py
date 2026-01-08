"""Standard API response helpers for consistent JSON responses."""

from datetime import datetime
from typing import Any, Dict, Optional, Tuple


def success_response(
    data: Optional[Any] = None,
    message: Optional[str] = None,
    status_code: int = 200,
) -> Tuple[Dict[str, Any], int]:
    """
    Generate a successful API response.

    Args:
        data: Optional response data payload.
        message: Optional success message.
        status_code: HTTP status code (default: 200).

    Returns:
        Tuple of (response_dict, status_code).
    """
    response = {
        "success": True,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": status_code,
    }

    if message:
        response["message"] = message

    if data is not None:
        response["data"] = data

    return response, status_code


def error_response(
    error: str,
    details: Optional[Any] = None,
    status_code: int = 400,
) -> Tuple[Dict[str, Any], int]:
    """
    Generate an error API response.

    Args:
        error: Error message describing what went wrong.
        details: Optional detailed error information.
        status_code: HTTP status code (default: 400).

    Returns:
        Tuple of (response_dict, status_code).
    """
    response = {
        "success": False,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": status_code,
        "error": error,
    }

    if details is not None:
        response["details"] = details

    return response, status_code


def created_response(
    data: Any,
    message: str = "Created",
) -> Tuple[Dict[str, Any], int]:
    """
    Generate a 201 Created API response.

    Args:
        data: Response data payload (required).
        message: Success message (default: "Created").

    Returns:
        Tuple of (response_dict, 201).
    """
    return success_response(data=data, message=message, status_code=201)


def not_found_response(resource: str) -> Tuple[Dict[str, Any], int]:
    """
    Generate a 404 Not Found API response.

    Args:
        resource: Name of the resource that was not found.

    Returns:
        Tuple of (response_dict, 404).
    """
    error_msg = f"{resource} not found"
    return error_response(error=error_msg, status_code=404)


def forbidden_response(
    message: str = "Access denied",
) -> Tuple[Dict[str, Any], int]:
    """
    Generate a 403 Forbidden API response.

    Args:
        message: Error message (default: "Access denied").

    Returns:
        Tuple of (response_dict, 403).
    """
    return error_response(error=message, status_code=403)


def license_limit_response(limit: int) -> Tuple[Dict[str, Any], int]:
    """
    Generate a 403 License Limit Exceeded response.

    Args:
        limit: The limit that was exceeded.

    Returns:
        Tuple of (response_dict, 403).
    """
    error_msg = f"License limit of {limit} exceeded"
    details = {
        "upgrade_url": "https://license.penguintech.io/upgrade",
        "contact": "sales@penguintech.io",
    }
    return error_response(
        error=error_msg,
        details=details,
        status_code=403,
    )


def validation_error_response(
    errors: Dict[str, Any],
) -> Tuple[Dict[str, Any], int]:
    """
    Generate a 422 Unprocessable Entity response for validation errors.

    Args:
        errors: Dictionary of validation errors (field -> error message(s)).

    Returns:
        Tuple of (response_dict, 422).
    """
    response = {
        "success": False,
        "timestamp": datetime.utcnow().isoformat(),
        "status_code": 422,
        "error": "Validation failed",
        "validation_errors": errors,
    }

    return response, 422
