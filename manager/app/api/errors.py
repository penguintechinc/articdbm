"""ArticDBM REST API error handlers and custom exceptions."""

from typing import Any, Dict, Optional
from flask import Flask, jsonify
from manager.app.utils.api_responses import error_response


class ValidationError(Exception):
    """Raised when input validation fails."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Initialize ValidationError.

        Args:
            message: Error message describing validation failure.
            details: Optional detailed information about validation errors.
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}


class NotFoundError(Exception):
    """Raised when a requested resource is not found."""

    def __init__(self, resource: str, identifier: Optional[str] = None):
        """
        Initialize NotFoundError.

        Args:
            resource: Name of the resource type (e.g., 'User', 'Database').
            identifier: Optional identifier that was not found.
        """
        self.resource = resource
        self.identifier = identifier
        message = f"{resource} not found"
        if identifier:
            message += f": {identifier}"
        super().__init__(message)


class ForbiddenError(Exception):
    """Raised when access to a resource is denied."""

    def __init__(self, message: str = "Access denied"):
        """
        Initialize ForbiddenError.

        Args:
            message: Error message describing why access was denied.
        """
        super().__init__(message)
        self.message = message


class LicenseLimitError(Exception):
    """Raised when a license limit is exceeded."""

    def __init__(self, limit_type: str, limit: int, current: Optional[int] = None):
        """
        Initialize LicenseLimitError.

        Args:
            limit_type: Type of limit exceeded (e.g., 'connections', 'databases').
            limit: The limit value that was exceeded.
            current: Optional current value that triggered the limit.
        """
        self.limit_type = limit_type
        self.limit = limit
        self.current = current
        message = f"License limit exceeded for {limit_type}: {limit}"
        if current:
            message += f" (current: {current})"
        super().__init__(message)


def handle_validation_error(error: ValidationError) -> tuple[Dict[str, Any], int]:
    """
    Handle ValidationError exceptions.

    Args:
        error: ValidationError instance.

    Returns:
        Tuple of (response_dict, 422).
    """
    response = {
        "success": False,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "status_code": 422,
        "error": error.message,
    }

    if error.details:
        response["validation_errors"] = error.details

    return response, 422


def handle_not_found_error(error: NotFoundError) -> tuple[Dict[str, Any], int]:
    """
    Handle NotFoundError exceptions.

    Args:
        error: NotFoundError instance.

    Returns:
        Tuple of (response_dict, 404).
    """
    return error_response(
        error=str(error),
        status_code=404,
    )


def handle_forbidden_error(error: ForbiddenError) -> tuple[Dict[str, Any], int]:
    """
    Handle ForbiddenError exceptions.

    Args:
        error: ForbiddenError instance.

    Returns:
        Tuple of (response_dict, 403).
    """
    return error_response(
        error=error.message,
        status_code=403,
    )


def handle_license_limit_error(error: LicenseLimitError) -> tuple[Dict[str, Any], int]:
    """
    Handle LicenseLimitError exceptions.

    Args:
        error: LicenseLimitError instance.

    Returns:
        Tuple of (response_dict, 403).
    """
    details = {
        "limit_type": error.limit_type,
        "limit": error.limit,
        "upgrade_url": "https://license.penguintech.io/upgrade",
        "contact": "sales@penguintech.io",
    }

    if error.current is not None:
        details["current"] = error.current

    return error_response(
        error=str(error),
        details=details,
        status_code=403,
    )


def handle_400_error(error: Exception) -> tuple[Dict[str, Any], int]:
    """
    Handle 400 Bad Request errors.

    Args:
        error: Exception instance.

    Returns:
        Tuple of (response_dict, 400).
    """
    return error_response(
        error="Bad request",
        details={"message": str(error)},
        status_code=400,
    )


def handle_401_error(error: Exception) -> tuple[Dict[str, Any], int]:
    """
    Handle 401 Unauthorized errors.

    Args:
        error: Exception instance.

    Returns:
        Tuple of (response_dict, 401).
    """
    return error_response(
        error="Unauthorized",
        details={"message": "Authentication required"},
        status_code=401,
    )


def handle_403_error(error: Exception) -> tuple[Dict[str, Any], int]:
    """
    Handle 403 Forbidden errors.

    Args:
        error: Exception instance.

    Returns:
        Tuple of (response_dict, 403).
    """
    return error_response(
        error="Forbidden",
        details={"message": "Access denied"},
        status_code=403,
    )


def handle_404_error(error: Exception) -> tuple[Dict[str, Any], int]:
    """
    Handle 404 Not Found errors.

    Args:
        error: Exception instance.

    Returns:
        Tuple of (response_dict, 404).
    """
    return error_response(
        error="Not found",
        details={"message": "The requested resource was not found"},
        status_code=404,
    )


def handle_422_error(error: Exception) -> tuple[Dict[str, Any], int]:
    """
    Handle 422 Unprocessable Entity errors.

    Args:
        error: Exception instance.

    Returns:
        Tuple of (response_dict, 422).
    """
    return error_response(
        error="Unprocessable entity",
        details={"message": str(error)},
        status_code=422,
    )


def handle_500_error(error: Exception) -> tuple[Dict[str, Any], int]:
    """
    Handle 500 Internal Server Error.

    Args:
        error: Exception instance.

    Returns:
        Tuple of (response_dict, 500).
    """
    return error_response(
        error="Internal server error",
        details={"message": "An unexpected error occurred"},
        status_code=500,
    )


def register_error_handlers(app: Flask) -> None:
    """
    Register all error handlers with the Flask application.

    Args:
        app: Flask application instance.
    """
    # Custom exception handlers
    app.register_error_handler(ValidationError, lambda e: handle_validation_error(e))
    app.register_error_handler(NotFoundError, lambda e: handle_not_found_error(e))
    app.register_error_handler(ForbiddenError, lambda e: handle_forbidden_error(e))
    app.register_error_handler(LicenseLimitError, lambda e: handle_license_limit_error(e))

    # HTTP status code handlers
    app.register_error_handler(400, lambda e: handle_400_error(e))
    app.register_error_handler(401, lambda e: handle_401_error(e))
    app.register_error_handler(403, lambda e: handle_403_error(e))
    app.register_error_handler(404, lambda e: handle_404_error(e))
    app.register_error_handler(422, lambda e: handle_422_error(e))
    app.register_error_handler(500, lambda e: handle_500_error(e))
