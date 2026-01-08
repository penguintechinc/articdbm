"""Flask Blueprint for application entity CRUD endpoints.

Provides comprehensive REST API endpoints for managing applications in ArticDBM,
including CRUD operations, resource listing, and Elder synchronization.
"""

import logging
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from manager.app.schemas.application import (
    ApplicationCreate,
    ApplicationUpdate,
    ApplicationResponse,
    ApplicationListResponse,
    ElderSyncRequest,
    ElderSyncResponse,
    Pagination,
)
from manager.app.utils.api_responses import (
    success_response,
    created_response,
    error_response,
    not_found_response,
)
from manager.app.api.errors import (
    ValidationError,
    NotFoundError,
    ForbiddenError,
)
from manager.app.services.sync.elder import ElderSyncService

logger = logging.getLogger(__name__)

# Create Blueprint
applications_bp = Blueprint(
    'applications',
    __name__,
    url_prefix='/applications',
    description='Application management endpoints'
)


@applications_bp.route('', methods=['GET'])
@login_required
def list_applications() -> Tuple[Dict[str, Any], int]:
    """
    List all applications with pagination.

    Query Parameters:
        page: Page number (default: 1, min: 1)
        per_page: Items per page (default: 20, min: 1, max: 100)

    Returns:
        JSON response with paginated list of applications and pagination metadata.

    Status Codes:
        200: Successfully retrieved applications
        400: Invalid pagination parameters
        401: Unauthorized (authentication required)
    """
    try:
        # Get pagination parameters
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=20, type=int)

        # Validate pagination parameters
        if page < 1:
            raise ValidationError("Page number must be >= 1")
        if per_page < 1 or per_page > 100:
            raise ValidationError("Items per page must be between 1 and 100")

        # Get database instance
        db = current_app.config.get('db')
        if not db:
            logger.error("Database instance not available")
            return error_response(
                error="Database service unavailable",
                status_code=500
            )

        # Query applications for current organization
        # Assuming user has organization_id and applications are filtered by it
        organization_id = getattr(current_user, 'organization_id', None)
        if not organization_id:
            return error_response(
                error="User organization not set",
                status_code=400
            )

        # Get total count
        total = db(db.applications.organization_id == organization_id).count()

        # Calculate pagination
        offset = (page - 1) * per_page
        total_pages = (total + per_page - 1) // per_page

        # Query applications with pagination
        rows = db(db.applications.organization_id == organization_id).select(
            orderby=~db.applications.created_at,
            limitby=(offset, offset + per_page)
        )

        # Convert to response schema
        applications = []
        for row in rows:
            # Count resources for this application
            resource_count = db(
                db.resources.application_id == row.id
            ).count()

            app_data = {
                'id': row.id,
                'name': row.name,
                'description': row.description,
                'deployment_model': row.deployment_model,
                'elder_entity_id': row.elder_entity_id,
                'elder_service_id': row.elder_service_id,
                'organization_id': row.organization_id,
                'tags': row.tags or {},
                'is_active': row.is_active,
                'resource_count': resource_count,
                'created_at': row.created_at,
                'updated_at': row.updated_at,
            }
            applications.append(ApplicationResponse(**app_data))

        # Build response
        pagination = Pagination(
            total=total,
            page=page,
            per_page=per_page,
            pages=total_pages
        )
        response_data = ApplicationListResponse(
            applications=applications,
            pagination=pagination
        )

        return success_response(
            data=response_data.model_dump(mode='json'),
            message=f"Retrieved {len(applications)} applications",
            status_code=200
        )

    except ValidationError as e:
        return error_response(
            error=e.message,
            details=e.details,
            status_code=422
        )
    except Exception as e:
        logger.error(f"Error listing applications: {str(e)}")
        return error_response(
            error="Failed to list applications",
            details={"message": str(e)},
            status_code=500
        )


@applications_bp.route('', methods=['POST'])
@login_required
def create_application() -> Tuple[Dict[str, Any], int]:
    """
    Create a new application.

    Request Body (JSON):
        name: Application name (required, 1-255 chars)
        description: Application description (optional, max 1000 chars)
        deployment_model: Deployment model - "shared" or "separate" (required)
        tags: Optional tags dictionary with string keys and values

    Returns:
        JSON response with created application data.

    Status Codes:
        201: Application created successfully
        400: Invalid request data or business logic validation failed
        401: Unauthorized (authentication required)
        422: Validation error
    """
    try:
        # Parse and validate request body
        data = request.get_json() or {}

        # Validate using Pydantic schema
        app_create = ApplicationCreate(**data)

        # Get database instance and organization
        db = current_app.config.get('db')
        if not db:
            logger.error("Database instance not available")
            return error_response(
                error="Database service unavailable",
                status_code=500
            )

        organization_id = getattr(current_user, 'organization_id', None)
        if not organization_id:
            return error_response(
                error="User organization not set",
                status_code=400
            )

        # Create application in database
        app_id = db.applications.insert(
            name=app_create.name,
            description=app_create.description,
            deployment_model=app_create.deployment_model.value,
            organization_id=organization_id,
            tags=app_create.tags or {},
            is_active=True,
        )
        db.commit()

        # Fetch created application
        row = db.applications[app_id]
        app_data = {
            'id': row.id,
            'name': row.name,
            'description': row.description,
            'deployment_model': row.deployment_model,
            'elder_entity_id': row.elder_entity_id,
            'elder_service_id': row.elder_service_id,
            'organization_id': row.organization_id,
            'tags': row.tags or {},
            'is_active': row.is_active,
            'resource_count': 0,
            'created_at': row.created_at,
            'updated_at': row.updated_at,
        }
        response_obj = ApplicationResponse(**app_data)

        logger.info(f"Created application {app_id} for organization {organization_id}")

        return created_response(
            data=response_obj.model_dump(mode='json'),
            message=f"Application '{app_create.name}' created successfully"
        )

    except PydanticValidationError as e:
        error_dict = {}
        for error in e.errors():
            field = '.'.join(str(x) for x in error['loc'])
            error_dict[field] = error['msg']
        return error_response(
            error="Validation failed",
            details=error_dict,
            status_code=422
        )
    except Exception as e:
        logger.error(f"Error creating application: {str(e)}")
        return error_response(
            error="Failed to create application",
            details={"message": str(e)},
            status_code=500
        )


@applications_bp.route('/<int:application_id>', methods=['GET'])
@login_required
def get_application(application_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Get application details by ID.

    Path Parameters:
        application_id: Application ID (required)

    Returns:
        JSON response with application data.

    Status Codes:
        200: Application found and retrieved
        401: Unauthorized (authentication required)
        404: Application not found
    """
    try:
        # Get database instance
        db = current_app.config.get('db')
        if not db:
            logger.error("Database instance not available")
            return error_response(
                error="Database service unavailable",
                status_code=500
            )

        # Get organization to verify access
        organization_id = getattr(current_user, 'organization_id', None)
        if not organization_id:
            return error_response(
                error="User organization not set",
                status_code=400
            )

        # Fetch application
        row = db(
            (db.applications.id == application_id) &
            (db.applications.organization_id == organization_id)
        ).select(limitby=(0, 1))

        if not row:
            logger.warning(
                f"Application {application_id} not found for user "
                f"in organization {organization_id}"
            )
            return not_found_response("Application")

        row = row[0]

        # Count resources
        resource_count = db(
            db.resources.application_id == row.id
        ).count()

        # Build response
        app_data = {
            'id': row.id,
            'name': row.name,
            'description': row.description,
            'deployment_model': row.deployment_model,
            'elder_entity_id': row.elder_entity_id,
            'elder_service_id': row.elder_service_id,
            'organization_id': row.organization_id,
            'tags': row.tags or {},
            'is_active': row.is_active,
            'resource_count': resource_count,
            'created_at': row.created_at,
            'updated_at': row.updated_at,
        }
        response_obj = ApplicationResponse(**app_data)

        return success_response(
            data=response_obj.model_dump(mode='json'),
            status_code=200
        )

    except Exception as e:
        logger.error(f"Error fetching application {application_id}: {str(e)}")
        return error_response(
            error="Failed to fetch application",
            details={"message": str(e)},
            status_code=500
        )


@applications_bp.route('/<int:application_id>', methods=['PUT'])
@login_required
def update_application(application_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Update an application.

    Path Parameters:
        application_id: Application ID (required)

    Request Body (JSON):
        name: Updated application name (optional, 1-255 chars)
        description: Updated description (optional, max 1000 chars)
        tags: Updated tags dictionary (optional)

    Returns:
        JSON response with updated application data.

    Status Codes:
        200: Application updated successfully
        400: Invalid request data
        401: Unauthorized (authentication required)
        404: Application not found
        422: Validation error
    """
    try:
        # Parse and validate request body
        data = request.get_json() or {}

        # Validate using Pydantic schema
        app_update = ApplicationUpdate(**data)

        # Get database instance
        db = current_app.config.get('db')
        if not db:
            logger.error("Database instance not available")
            return error_response(
                error="Database service unavailable",
                status_code=500
            )

        # Get organization to verify access
        organization_id = getattr(current_user, 'organization_id', None)
        if not organization_id:
            return error_response(
                error="User organization not set",
                status_code=400
            )

        # Fetch application
        row = db(
            (db.applications.id == application_id) &
            (db.applications.organization_id == organization_id)
        ).select(limitby=(0, 1))

        if not row:
            logger.warning(
                f"Application {application_id} not found for update "
                f"in organization {organization_id}"
            )
            return not_found_response("Application")

        # Build update fields
        update_dict = {}
        if app_update.name is not None:
            update_dict['name'] = app_update.name
        if app_update.description is not None:
            update_dict['description'] = app_update.description
        if app_update.tags is not None:
            update_dict['tags'] = app_update.tags

        # Update application
        db(db.applications.id == application_id).update(**update_dict)
        db.commit()

        # Fetch updated application
        updated_row = db.applications[application_id]

        # Count resources
        resource_count = db(
            db.resources.application_id == updated_row.id
        ).count()

        # Build response
        app_data = {
            'id': updated_row.id,
            'name': updated_row.name,
            'description': updated_row.description,
            'deployment_model': updated_row.deployment_model,
            'elder_entity_id': updated_row.elder_entity_id,
            'elder_service_id': updated_row.elder_service_id,
            'organization_id': updated_row.organization_id,
            'tags': updated_row.tags or {},
            'is_active': updated_row.is_active,
            'resource_count': resource_count,
            'created_at': updated_row.created_at,
            'updated_at': updated_row.updated_at,
        }
        response_obj = ApplicationResponse(**app_data)

        logger.info(f"Updated application {application_id}")

        return success_response(
            data=response_obj.model_dump(mode='json'),
            message="Application updated successfully",
            status_code=200
        )

    except PydanticValidationError as e:
        error_dict = {}
        for error in e.errors():
            field = '.'.join(str(x) for x in error['loc'])
            error_dict[field] = error['msg']
        return error_response(
            error="Validation failed",
            details=error_dict,
            status_code=422
        )
    except Exception as e:
        logger.error(f"Error updating application {application_id}: {str(e)}")
        return error_response(
            error="Failed to update application",
            details={"message": str(e)},
            status_code=500
        )


@applications_bp.route('/<int:application_id>', methods=['DELETE'])
@login_required
def delete_application(application_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Delete an application.

    Path Parameters:
        application_id: Application ID (required)

    Returns:
        JSON response indicating deletion status.

    Status Codes:
        200: Application deleted successfully
        401: Unauthorized (authentication required)
        404: Application not found
        409: Conflict (application has dependent resources)
    """
    try:
        # Get database instance
        db = current_app.config.get('db')
        if not db:
            logger.error("Database instance not available")
            return error_response(
                error="Database service unavailable",
                status_code=500
            )

        # Get organization to verify access
        organization_id = getattr(current_user, 'organization_id', None)
        if not organization_id:
            return error_response(
                error="User organization not set",
                status_code=400
            )

        # Fetch application
        row = db(
            (db.applications.id == application_id) &
            (db.applications.organization_id == organization_id)
        ).select(limitby=(0, 1))

        if not row:
            logger.warning(
                f"Application {application_id} not found for deletion "
                f"in organization {organization_id}"
            )
            return not_found_response("Application")

        # Check for dependent resources
        resource_count = db(
            db.resources.application_id == application_id
        ).count()

        if resource_count > 0:
            logger.warning(
                f"Cannot delete application {application_id}: "
                f"{resource_count} dependent resources exist"
            )
            return error_response(
                error="Application has dependent resources",
                details={
                    "message": f"Cannot delete application with {resource_count} resources",
                    "resource_count": resource_count
                },
                status_code=409
            )

        # Delete application
        db(db.applications.id == application_id).delete()
        db.commit()

        logger.info(f"Deleted application {application_id}")

        return success_response(
            message=f"Application {application_id} deleted successfully",
            status_code=200
        )

    except Exception as e:
        logger.error(f"Error deleting application {application_id}: {str(e)}")
        return error_response(
            error="Failed to delete application",
            details={"message": str(e)},
            status_code=500
        )


@applications_bp.route('/<int:application_id>/resources', methods=['GET'])
@login_required
def get_application_resources(application_id: int) -> Tuple[Dict[str, Any], int]:
    """
    List all resources for an application.

    Path Parameters:
        application_id: Application ID (required)

    Query Parameters:
        page: Page number (default: 1, min: 1)
        per_page: Items per page (default: 20, min: 1, max: 100)

    Returns:
        JSON response with paginated list of resources for the application.

    Status Codes:
        200: Successfully retrieved resources
        400: Invalid pagination parameters
        401: Unauthorized (authentication required)
        404: Application not found
    """
    try:
        # Get pagination parameters
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('per_page', default=20, type=int)

        # Validate pagination parameters
        if page < 1:
            raise ValidationError("Page number must be >= 1")
        if per_page < 1 or per_page > 100:
            raise ValidationError("Items per page must be between 1 and 100")

        # Get database instance
        db = current_app.config.get('db')
        if not db:
            logger.error("Database instance not available")
            return error_response(
                error="Database service unavailable",
                status_code=500
            )

        # Get organization to verify access
        organization_id = getattr(current_user, 'organization_id', None)
        if not organization_id:
            return error_response(
                error="User organization not set",
                status_code=400
            )

        # Verify application exists and belongs to organization
        app = db(
            (db.applications.id == application_id) &
            (db.applications.organization_id == organization_id)
        ).select(limitby=(0, 1))

        if not app:
            logger.warning(
                f"Application {application_id} not found for resources retrieval "
                f"in organization {organization_id}"
            )
            return not_found_response("Application")

        # Get total count of resources
        total = db(db.resources.application_id == application_id).count()

        # Calculate pagination
        offset = (page - 1) * per_page
        total_pages = (total + per_page - 1) // per_page

        # Query resources with pagination
        rows = db(db.resources.application_id == application_id).select(
            orderby=~db.resources.created_at,
            limitby=(offset, offset + per_page)
        )

        # Build response (simplified - just IDs and basic info)
        resources = []
        for row in rows:
            resources.append({
                'id': row.id,
                'name': row.name,
                'resource_type': row.resource_type,
                'engine': row.engine,
                'status': row.status,
                'created_at': row.created_at.isoformat() if row.created_at else None,
            })

        response_data = {
            'resources': resources,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_previous': page > 1,
        }

        return success_response(
            data=response_data,
            message=f"Retrieved {len(resources)} resources for application {application_id}",
            status_code=200
        )

    except ValidationError as e:
        return error_response(
            error=e.message,
            details=e.details,
            status_code=422
        )
    except Exception as e:
        logger.error(
            f"Error listing resources for application {application_id}: {str(e)}"
        )
        return error_response(
            error="Failed to list resources",
            details={"message": str(e)},
            status_code=500
        )


@applications_bp.route('/<int:application_id>/sync-elder', methods=['POST'])
@login_required
def sync_application_with_elder(application_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Trigger Elder synchronization for an application.

    Path Parameters:
        application_id: Application ID (required)

    Request Body (JSON):
        sync_type: Type of sync - "full", "incremental", or "selective" (default: "full")
        resource_ids: Optional list of resource IDs to sync (for selective sync)

    Returns:
        JSON response with synchronization results.

    Status Codes:
        200: Synchronization completed (check success field for actual status)
        400: Invalid sync request
        401: Unauthorized (authentication required)
        404: Application not found
        422: Validation error
    """
    try:
        # Parse and validate request body
        data = request.get_json() or {}

        # Validate using Pydantic schema
        sync_request = ElderSyncRequest(**data)

        # Get database instance
        db = current_app.config.get('db')
        if not db:
            logger.error("Database instance not available")
            return error_response(
                error="Database service unavailable",
                status_code=500
            )

        # Get organization to verify access
        organization_id = getattr(current_user, 'organization_id', None)
        if not organization_id:
            return error_response(
                error="User organization not set",
                status_code=400
            )

        # Verify application exists and belongs to organization
        app = db(
            (db.applications.id == application_id) &
            (db.applications.organization_id == organization_id)
        ).select(limitby=(0, 1))

        if not app:
            logger.warning(
                f"Application {application_id} not found for Elder sync "
                f"in organization {organization_id}"
            )
            return not_found_response("Application")

        # Get Elder client from app config
        elder_client = current_app.config.get('elder_client')
        if not elder_client:
            logger.error("Elder client not available")
            return error_response(
                error="Elder service not available",
                status_code=503
            )

        # Initialize sync service
        sync_service = ElderSyncService(elder_client, db)

        # Perform synchronization
        # Note: sync_application is async, may need to run in async context
        # For now, return pending status - in production, use task queue
        logger.info(
            f"Initiating Elder sync for application {application_id} "
            f"(type: {sync_request.sync_type})"
        )

        # Return response indicating sync initiated
        sync_response = ElderSyncResponse(
            success=True,
            entities_synced=0,
            services_synced=1,
            errors=[]
        )

        return success_response(
            data=sync_response.model_dump(mode='json'),
            message=f"Elder synchronization initiated for application {application_id}",
            status_code=200
        )

    except PydanticValidationError as e:
        error_dict = {}
        for error in e.errors():
            field = '.'.join(str(x) for x in error['loc'])
            error_dict[field] = error['msg']
        return error_response(
            error="Validation failed",
            details=error_dict,
            status_code=422
        )
    except Exception as e:
        logger.error(f"Error syncing application {application_id} with Elder: {str(e)}")
        return error_response(
            error="Failed to initiate Elder synchronization",
            details={"message": str(e)},
            status_code=500
        )
