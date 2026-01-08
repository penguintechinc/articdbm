"""Flask Blueprint for license management endpoints.

Provides comprehensive REST API endpoints for managing ArticDBM licenses,
including activation, deactivation, status, and usage statistics.
"""

import logging
from typing import Any, Dict, Tuple

from flask import Blueprint, request, current_app
from flask_security import login_required

from manager.app.utils.api_responses import (
    success_response,
    error_response,
)
from manager.app.api.errors import ValidationError

logger = logging.getLogger(__name__)

# Create Blueprint
license_bp = Blueprint(
    'license',
    __name__,
    url_prefix='/license',
    description='License management endpoints'
)


@license_bp.route('', methods=['GET'])
@login_required
def get_license() -> Tuple[Dict[str, Any], int]:
    """
    Get current license information.

    Returns license tier, active features, resource usage, and limits.

    Returns:
        JSON response with license details:
            - license_key: Current license key (masked)
            - tier: License tier (free, professional, enterprise)
            - features: List of enabled features
            - resource_count: Current number of active resources
            - resource_limit: Maximum resources allowed (-1 for unlimited)
            - is_active: Whether license is currently active
            - last_validated: ISO timestamp of last validation
            - expires_at: License expiration date (if applicable)

    Status Codes:
        200: Successfully retrieved license information
        401: Unauthorized (authentication required)
        500: License service error
    """
    try:
        # Get license service from app config
        license_service = current_app.config.get('license_service')
        if not license_service:
            logger.error("License service not available")
            return error_response(
                error="License service unavailable",
                status_code=500
            )

        # Get current license information
        import asyncio
        license_info = asyncio.run(license_service.get_current_license())

        # Mask license key if present
        if license_info.get("license_key"):
            key = license_info["license_key"]
            if len(key) > 4:
                license_info["license_key"] = f"{'*' * (len(key) - 4)}{key[-4:]}"

        return success_response(
            data=license_info,
            message="License information retrieved successfully",
            status_code=200
        )

    except Exception as e:
        logger.error(f"Error retrieving license information: {str(e)}")
        return error_response(
            error="Failed to retrieve license information",
            details={"message": str(e)},
            status_code=500
        )


@license_bp.route('', methods=['POST'])
@login_required
def activate_license() -> Tuple[Dict[str, Any], int]:
    """
    Activate a new license key.

    Validates the license key with the license server, deactivates any
    existing license, and stores the new license in the database.

    Request Body (JSON):
        license_key: License key to activate (required, format: PENG-XXXX-XXXX-XXXX-XXXX-ABCD)

    Returns:
        JSON response with activated license details.

    Status Codes:
        200: License activated successfully
        400: Invalid or missing license key
        401: Unauthorized (authentication required)
        422: Validation error
        500: License service error
    """
    try:
        # Parse request body
        data = request.get_json() or {}

        # Validate license key is provided
        license_key = data.get('license_key', '').strip()
        if not license_key:
            raise ValidationError("license_key is required")

        # Validate license key format (basic check)
        if not license_key.startswith('PENG-') or len(license_key) < 24:
            raise ValidationError(
                "Invalid license key format. Expected format: PENG-XXXX-XXXX-XXXX-XXXX-ABCD"
            )

        # Get license service from app config
        license_service = current_app.config.get('license_service')
        if not license_service:
            logger.error("License service not available")
            return error_response(
                error="License service unavailable",
                status_code=500
            )

        # Activate license
        import asyncio
        license_info = asyncio.run(license_service.activate_license(license_key))

        # Mask license key in response
        if license_info.get("license_key"):
            key = license_info["license_key"]
            if len(key) > 4:
                license_info["license_key"] = f"{'*' * (len(key) - 4)}{key[-4:]}"

        logger.info(f"License activated for tier: {license_info.get('tier')}")

        return success_response(
            data=license_info,
            message=f"License activated successfully (tier: {license_info.get('tier')})",
            status_code=200
        )

    except ValidationError as e:
        return error_response(
            error=e.message,
            details=e.details,
            status_code=422
        )
    except ValueError as e:
        logger.warning(f"License activation failed: {str(e)}")
        return error_response(
            error="License activation failed",
            details={"message": str(e)},
            status_code=400
        )
    except Exception as e:
        logger.error(f"Error activating license: {str(e)}")
        return error_response(
            error="Failed to activate license",
            details={"message": str(e)},
            status_code=500
        )


@license_bp.route('', methods=['DELETE'])
@login_required
def deactivate_license() -> Tuple[Dict[str, Any], int]:
    """
    Deactivate current license and revert to free tier.

    Removes the active license and reverts to the free tier with
    default resource limits.

    Returns:
        JSON response indicating deactivation status.

    Status Codes:
        200: License deactivated successfully
        401: Unauthorized (authentication required)
        404: No active license to deactivate
        500: License service error
    """
    try:
        # Get license service from app config
        license_service = current_app.config.get('license_service')
        if not license_service:
            logger.error("License service not available")
            return error_response(
                error="License service unavailable",
                status_code=500
            )

        # Deactivate license
        import asyncio
        deactivated = asyncio.run(license_service.deactivate_license())

        if not deactivated:
            logger.info("No active license to deactivate")
            return error_response(
                error="No active license to deactivate",
                status_code=404
            )

        logger.info("License deactivated successfully")

        return success_response(
            data={
                "tier": "free",
                "is_active": False,
                "message": "Reverted to free tier with default resource limits"
            },
            message="License deactivated successfully",
            status_code=200
        )

    except Exception as e:
        logger.error(f"Error deactivating license: {str(e)}")
        return error_response(
            error="Failed to deactivate license",
            details={"message": str(e)},
            status_code=500
        )


@license_bp.route('/usage', methods=['GET'])
@login_required
def get_usage_stats() -> Tuple[Dict[str, Any], int]:
    """
    Get detailed license usage statistics.

    Returns current resource usage, limits, and feature entitlements
    for the active license.

    Returns:
        JSON response with usage statistics:
            - tier: Current license tier
            - resource_count: Current number of active resources
            - resource_limit: Maximum resources allowed
            - features: List of enabled features
            - is_active: Whether license is currently active
            - last_validated: ISO timestamp of last validation
            - next_validation: ISO timestamp of next scheduled validation
            - usage_percentage: Resource usage as percentage (if applicable)

    Status Codes:
        200: Successfully retrieved usage statistics
        401: Unauthorized (authentication required)
        500: License service error
    """
    try:
        # Get license service from app config
        license_service = current_app.config.get('license_service')
        if not license_service:
            logger.error("License service not available")
            return error_response(
                error="License service unavailable",
                status_code=500
            )

        # Get usage statistics
        import asyncio
        usage_stats = asyncio.run(license_service.get_usage_stats())

        # Calculate usage percentage if limit is not unlimited
        resource_count = usage_stats.get('resource_count', 0)
        resource_limit = usage_stats.get('resource_limit', 3)

        if resource_limit > 0:
            usage_percentage = round(
                (resource_count / resource_limit) * 100, 2
            )
            usage_stats['usage_percentage'] = usage_percentage
        else:
            # Unlimited tier
            usage_stats['usage_percentage'] = 0

        return success_response(
            data=usage_stats,
            message="Usage statistics retrieved successfully",
            status_code=200
        )

    except Exception as e:
        logger.error(f"Error retrieving usage statistics: {str(e)}")
        return error_response(
            error="Failed to retrieve usage statistics",
            details={"message": str(e)},
            status_code=500
        )
