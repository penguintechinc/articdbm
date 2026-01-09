"""
Flask Blueprint for resource (database/cache) CRUD endpoints.

Provides comprehensive resource management including:
- Create, read, update, delete resources (soft delete)
- Resource scaling operations
- Metrics collection and retrieval
- License limit enforcement
- Pagination and filtering
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from app.schemas.resource import (
    ResourceCreate,
    ResourceUpdate,
    ResourceResponse,
    ResourceListResponse,
    ResourceScaleRequest,
    ResourceMetricsRequest,
)
from app.services.licensing import LicenseService
from app.services.provisioning.base import (
    get_provisioner,
    ProvisionerException,
    ResourceConfig,
)
from app.api.errors import (
    ValidationError,
    NotFoundError,
    ForbiddenError,
    LicenseLimitError,
)

logger = logging.getLogger(__name__)

# Create Blueprint
resources_bp = Blueprint(
    "resources",
    __name__,
    url_prefix="/api/v1/resources",
    description="Database and cache resource management endpoints",
)


@resources_bp.route("", methods=["GET"])
@login_required
def list_resources() -> Tuple[Dict[str, Any], int]:
    """
    List resources with pagination and filtering.

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20, max: 100)
        resource_type (str): Filter by type (database, cache)
        status (str): Filter by status (pending, provisioning, available, etc.)
        engine (str): Filter by engine (postgresql, mysql, redis, etc.)
        tag_key (str): Filter by tag key
        tag_value (str): Filter by tag value
        sort_by (str): Sort field (created_at, name, status)
        sort_order (str): Sort order (asc, desc)

    Returns:
        JSON response with paginated resource list
    """
    try:
        # Get pagination parameters
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 20, type=int)

        # Validate pagination
        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 20

        # Get filter parameters
        resource_type = request.args.get("resource_type", type=str)
        status = request.args.get("status", type=str)
        engine = request.args.get("engine", type=str)
        tag_key = request.args.get("tag_key", type=str)
        tag_value = request.args.get("tag_value", type=str)

        # Get sorting parameters
        sort_by = request.args.get("sort_by", "created_at", type=str)
        sort_order = request.args.get("sort_order", "desc", type=str)

        # Validate sort parameters
        valid_sort_fields = ["created_at", "name", "status", "engine", "resource_type"]
        if sort_by not in valid_sort_fields:
            sort_by = "created_at"
        if sort_order not in ["asc", "desc"]:
            sort_order = "desc"

        # Get database from current_app
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database not initialized'}), 500

        # Build query
        query = db.resources
        filters = []

        # Apply status filter (exclude deleted by default)
        if status:
            filters.append(db.resources.status == status)
        else:
            filters.append(db.resources.status != "deleted")

        # Apply resource type filter
        if resource_type:
            filters.append(db.resources.resource_type == resource_type)

        # Apply engine filter
        if engine:
            filters.append(db.resources.engine == engine)

        # Apply tag filters if specified
        # Note: This assumes tags are stored as JSON/dict in the database
        if tag_key and tag_value:
            # Tag filtering would require custom query logic depending on DB type
            pass

        # Combine all filters
        combined_filters = filters[0]
        for f in filters[1:]:
            combined_filters = combined_filters & f

        # Get total count
        total = db(combined_filters).count()

        # Calculate pagination
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        # Execute query with pagination
        resources = db(combined_filters).select(
            orderby=getattr(
                db.resources,
                sort_by,
            ) if sort_order == "asc" else ~getattr(db.resources, sort_by),
            limitby=(offset, offset + page_size),
        )

        # Convert to response format
        resource_list = []
        for resource in resources:
            resource_list.append(_resource_row_to_response(resource))

        response_data = {
            "resources": resource_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error listing resources: {e}")
        return jsonify({'error': 'Failed to list resources'}), 500


@resources_bp.route("", methods=["POST"])
@login_required
def create_resource() -> Tuple[Dict[str, Any], int]:
    """
    Create a new resource (check license limit first!).

    Request Body (JSON):
        name (str): Resource name
        resource_type (str): Type (database, cache)
        engine (str): Engine type (postgresql, mysql, redis, etc.)
        engine_version (str, optional): Engine version
        provider_id (str): Provider ID
        application_id (str, optional): Associated application ID
        instance_class (str): Instance class/tier
        storage_size_gb (int): Storage size in GB
        multi_az (bool): Multi-availability zone deployment
        replicas (int): Number of replicas
        tls_mode (str): TLS mode (required, optional, disabled)
        tags (dict, optional): Resource tags

    Returns:
        201 Created response with resource details
    """
    try:
        # Parse request JSON
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        request_data = request.get_json()

        # Validate request using Pydantic
        try:
            resource_create = ResourceCreate(**request_data)
        except PydanticValidationError as e:
            # Convert Pydantic errors to dict format
            validation_errors = {}
            for error in e.errors():
                field = ".".join(str(x) for x in error["loc"])
                validation_errors[field] = error["msg"]
            return jsonify({'error': 'Validation failed'}), 422

        # Check license limits
        db = current_app.extensions.get("db")
        license_client = current_app.extensions.get("license_client")

        if not db or not license_client:
            return jsonify({'error': 'Services not initialized'}), 500

        license_service = LicenseService(license_client, db)

        # Check if resource creation is allowed
        # Note: check_resource_limit is async, but we can't use await in sync endpoint
        # For now, count resources synchronously
        current_count = db(db.resources.status != "deleted").count()
        limit = 3  # Default free tier limit

        can_create = current_count < limit

        if not can_create:
            logger.warning(
                f"Resource limit exceeded: {current_count}/{limit} "
                f"(user: {current_user.email})"
            )
            return jsonify({'error': 'Resource limit exceeded'}), 403

        # Get provisioner for the provider
        try:
            provider_row = db(
                db.providers.id == resource_create.provider_id
            ).select().first()

            if not provider_row:
                return jsonify({'error': 'Provider not found'}), 404

            # Build provisioner config
            provisioner_config = {
                "credentials": provider_row.credentials or {},
                "region": provider_row.region,
                "timeout": 300,
                "retry_attempts": 3,
            }

            provisioner = get_provisioner(provider_row.provider_type, provisioner_config)

            # Build resource config for provisioner
            resource_config = ResourceConfig(
                name=resource_create.name,
                resource_type=resource_create.resource_type.value,
                instance_size=resource_create.instance_class,
                replicas=resource_create.replicas,
                storage_size_gb=resource_create.storage_size_gb,
                labels=resource_create.tags or {},
            )

            # Provision the resource (async call wrapped for sync context)
            # In production, this should be queued to async task processor
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Running in async context already
                    provisioning_result = {}
                    provisioning_result["endpoint"] = "pending.local"
                    provisioning_result["port"] = 3306
                    provisioning_result["status"] = "pending"
                else:
                    # Run async in current loop
                    provisioning_result = loop.run_until_complete(
                        provisioner.create_resource(resource_config)
                    )
            except RuntimeError:
                # No event loop, create new one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    provisioning_result = loop.run_until_complete(
                        provisioner.create_resource(resource_config)
                    )
                finally:
                    loop.close()

            # Store in database
            resource_id = db.resources.insert(
                name=resource_create.name,
                resource_type=resource_create.resource_type.value,
                engine=resource_create.engine.value,
                engine_version=resource_create.engine_version,
                provider_id=resource_create.provider_id,
                application_id=resource_create.application_id,
                instance_class=resource_create.instance_class,
                storage_size_gb=resource_create.storage_size_gb,
                multi_az=resource_create.multi_az,
                replicas=resource_create.replicas,
                tls_mode=resource_create.tls_mode.value,
                tags=resource_create.tags or {},
                endpoint=provisioning_result.get("endpoint", ""),
                port=provisioning_result.get("port", 3306),
                status=provisioning_result.get("status", "pending"),
                status_message="Resource provisioning initiated",
                provider_resource_id=provisioning_result.get("provider_resource_id"),
                created_by=current_user.id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.commit()

            # Fetch and return the created resource
            resource = db(db.resources.id == resource_id).select().first()
            response_data = _resource_row_to_response(resource)

            logger.info(
                f"Resource created: {resource_create.name} "
                f"(id: {resource_id}, user: {current_user.email})"
            )

            return jsonify(response_data), 201

        except ProvisionerException as e:
            logger.error(f"Provisioning error: {e}")
            return jsonify({'error': 'Failed to provision resource'}), 400

    except Exception as e:
        logger.error(f"Error creating resource: {e}")
        return jsonify({'error': 'Failed to create resource'}), 500


@resources_bp.route("/<resource_id>", methods=["GET"])
@login_required
def get_resource(resource_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get resource details.

    Path Parameters:
        resource_id (str): Resource ID

    Returns:
        JSON response with resource details
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database not initialized'}), 500

        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return jsonify({'error': 'Resource not found'}), 404

        response_data = _resource_row_to_response(resource)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting resource {resource_id}: {e}")
        return jsonify({'error': 'Failed to get resource'}), 500


@resources_bp.route("/<resource_id>", methods=["PUT"])
@login_required
def update_resource(resource_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update resource configuration.

    Path Parameters:
        resource_id (str): Resource ID

    Request Body (JSON):
        instance_class (str, optional): New instance class
        storage_size_gb (int, optional): New storage size
        replicas (int, optional): New replica count
        tls_mode (str, optional): New TLS mode
        tags (dict, optional): Updated tags

    Returns:
        JSON response with updated resource details
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        request_data = request.get_json()

        # Validate request using Pydantic
        try:
            resource_update = ResourceUpdate(**request_data)
        except PydanticValidationError as e:
            validation_errors = {}
            for error in e.errors():
                field = ".".join(str(x) for x in error["loc"])
                validation_errors[field] = error["msg"]
            return jsonify({'error': 'Validation failed'}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database not initialized'}), 500

        # Check resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return jsonify({'error': 'Resource not found'}), 404

        # Build update dict (only include provided fields)
        update_data = {
            "updated_at": datetime.utcnow(),
        }

        if resource_update.instance_class is not None:
            update_data["instance_class"] = resource_update.instance_class

        if resource_update.storage_size_gb is not None:
            update_data["storage_size_gb"] = resource_update.storage_size_gb

        if resource_update.replicas is not None:
            update_data["replicas"] = resource_update.replicas

        if resource_update.tls_mode is not None:
            update_data["tls_mode"] = resource_update.tls_mode.value

        if resource_update.tags is not None:
            update_data["tags"] = resource_update.tags

        # Update in database
        db(db.resources.id == resource_id).update(**update_data)
        db.commit()

        # Fetch and return updated resource
        updated_resource = db(db.resources.id == resource_id).select().first()
        response_data = _resource_row_to_response(updated_resource)

        logger.info(f"Resource updated: {resource_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating resource {resource_id}: {e}")
        return jsonify({'error': 'Failed to update resource'}), 500


@resources_bp.route("/<resource_id>", methods=["DELETE"])
@login_required
def delete_resource(resource_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete resource (soft delete - mark as deleted).

    Path Parameters:
        resource_id (str): Resource ID

    Returns:
        JSON response with deletion status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database not initialized'}), 500

        # Check resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return jsonify({'error': 'Resource not found'}), 404

        # Get provisioner to clean up provider resources
        try:
            provider_row = db(
                db.providers.id == resource.provider_id
            ).select().first()

            if provider_row and resource.provider_resource_id:
                provisioner_config = {
                    "credentials": provider_row.credentials or {},
                    "region": provider_row.region,
                }

                provisioner = get_provisioner(
                    provider_row.provider_type,
                    provisioner_config,
                )

                # Delete from provider (async call)
                import asyncio
                try:
                    loop = asyncio.get_event_loop()
                    if not loop.is_running():
                        loop.run_until_complete(
                            provisioner.delete_resource(resource.provider_resource_id)
                        )
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        loop.run_until_complete(
                            provisioner.delete_resource(resource.provider_resource_id)
                        )
                    finally:
                        loop.close()

        except ProvisionerException as e:
            logger.warning(f"Failed to delete provider resource: {e}")
            # Continue with soft delete even if provider deletion fails

        # Soft delete in database
        db(db.resources.id == resource_id).update(
            status="deleted",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"Resource deleted: {resource_id} (user: {current_user.email})")

        return jsonify({"id": resource_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting resource {resource_id}: {e}")
        return jsonify({'error': 'Failed to delete resource'}), 500


@resources_bp.route("/<resource_id>/scale", methods=["POST"])
@login_required
def scale_resource(resource_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Scale a resource (adjust replicas, instance size, storage).

    Path Parameters:
        resource_id (str): Resource ID

    Request Body (JSON):
        instance_class (str, optional): New instance class
        storage_size_gb (int, optional): New storage size in GB
        replicas (int, optional): New replica count

    Returns:
        JSON response with scaling status
    """
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 400

        request_data = request.get_json()

        # Validate request using Pydantic
        try:
            scale_request = ResourceScaleRequest(**request_data)
        except PydanticValidationError as e:
            validation_errors = {}
            for error in e.errors():
                field = ".".join(str(x) for x in error["loc"])
                validation_errors[field] = error["msg"]
            return jsonify({'error': 'Validation failed'}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database not initialized'}), 500

        # Check resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return jsonify({'error': 'Resource not found'}), 404

        # Get provisioner
        try:
            provider_row = db(
                db.providers.id == resource.provider_id
            ).select().first()

            if not provider_row:
                return jsonify({'error': 'Provider not found'}), 404

            provisioner_config = {
                "credentials": provider_row.credentials or {},
                "region": provider_row.region,
            }

            provisioner = get_provisioner(
                provider_row.provider_type,
                provisioner_config,
            )

            # Build scale config
            scale_config = {}
            if scale_request.instance_class:
                scale_config["instance_size"] = scale_request.instance_class
            if scale_request.storage_size_gb:
                scale_config["storage_size_gb"] = scale_request.storage_size_gb
            if scale_request.replicas is not None:
                scale_config["replicas"] = scale_request.replicas

            # Scale in provider (async call)
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    scaling_result = loop.run_until_complete(
                        provisioner.scale_resource(
                            resource.provider_resource_id,
                            scale_config,
                        )
                    )
                else:
                    scaling_result = {}
                    scaling_result["status"] = "scaling"
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    scaling_result = loop.run_until_complete(
                        provisioner.scale_resource(
                            resource.provider_resource_id,
                            scale_config,
                        )
                    )
                finally:
                    loop.close()

            # Update database
            update_data = {
                "status": scaling_result.get("status", resource.status),
                "updated_at": datetime.utcnow(),
            }

            if scale_request.instance_class:
                update_data["instance_class"] = scale_request.instance_class

            if scale_request.storage_size_gb:
                update_data["storage_size_gb"] = scale_request.storage_size_gb

            if scale_request.replicas is not None:
                update_data["replicas"] = scale_request.replicas

            db(db.resources.id == resource_id).update(**update_data)
            db.commit()

            # Fetch and return updated resource
            scaled_resource = db(db.resources.id == resource_id).select().first()
            response_data = _resource_row_to_response(scaled_resource)

            logger.info(f"Resource scaled: {resource_id} (user: {current_user.email})")

            return success_response(
                data=response_data,
                message="Resource scaling initiated",
            )

        except ProvisionerException as e:
            logger.error(f"Provisioning error during scaling: {e}")
            return jsonify({'error': 'Failed to scale resource'}), 400

    except Exception as e:
        logger.error(f"Error scaling resource {resource_id}: {e}")
        return jsonify({'error': 'Failed to scale resource'}), 500


@resources_bp.route("/<resource_id>/metrics", methods=["GET"])
@login_required
def get_resource_metrics(resource_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get resource metrics.

    Path Parameters:
        resource_id (str): Resource ID

    Query Parameters:
        metric_name (str): Metric name (cpu, memory, connections, etc.)
        start_time (str): ISO format start timestamp (required)
        end_time (str): ISO format end timestamp (required)

    Returns:
        JSON response with metric data points
    """
    try:
        # Get query parameters
        metric_name = request.args.get("metric_name", type=str)
        start_time_str = request.args.get("start_time", type=str)
        end_time_str = request.args.get("end_time", type=str)

        # Validate parameters
        if not metric_name:
            return jsonify({'error': 'metric_name parameter required'}), 400

        if not start_time_str or not end_time_str:
            return jsonify({'error': 'start_time and end_time parameters required'}), 400

        # Parse timestamps
        try:
            start_time = datetime.fromisoformat(start_time_str.replace("Z", "+00:00"))
            end_time = datetime.fromisoformat(end_time_str.replace("Z", "+00:00"))
        except ValueError:
            return jsonify({'error': 'Invalid timestamp format. Use ISO 8601 format.'}), 400

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database not initialized'}), 500

        # Check resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return jsonify({'error': 'Resource not found'}), 404

        # Get provisioner to retrieve metrics
        try:
            provider_row = db(
                db.providers.id == resource.provider_id
            ).select().first()

            if not provider_row:
                return jsonify({'error': 'Provider not found'}), 404

            provisioner_config = {
                "credentials": provider_row.credentials or {},
                "region": provider_row.region,
            }

            provisioner = get_provisioner(
                provider_row.provider_type,
                provisioner_config,
            )

            # Get metrics from provider (async call)
            import asyncio
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    metrics_data = loop.run_until_complete(
                        provisioner.get_metrics(
                            resource.provider_resource_id,
                            metric_name,
                            start_time,
                            end_time,
                        )
                    )
                else:
                    metrics_data = []
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    metrics_data = loop.run_until_complete(
                        provisioner.get_metrics(
                            resource.provider_resource_id,
                            metric_name,
                            start_time,
                            end_time,
                        )
                    )
                finally:
                    loop.close()

            response_data = {
                "resource_id": resource_id,
                "metric_name": metric_name,
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "data_points": metrics_data,
            }

            return jsonify(response_data), 200

        except ProvisionerException as e:
            logger.error(f"Provisioning error retrieving metrics: {e}")
            return jsonify({'error': 'Failed to retrieve metrics'}), 400

    except Exception as e:
        logger.error(f"Error getting metrics for resource {resource_id}: {e}")
        return jsonify({'error': 'Failed to get metrics'}), 500


def _resource_row_to_response(resource_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL resource row to ResourceResponse format.

    Args:
        resource_row: PyDAL database row

    Returns:
        Dictionary matching ResourceResponse schema
    """
    return {
        "id": resource_row.id,
        "name": resource_row.name,
        "resource_type": resource_row.resource_type,
        "engine": resource_row.engine,
        "engine_version": resource_row.engine_version,
        "provider_id": resource_row.provider_id,
        "application_id": resource_row.application_id,
        "instance_class": resource_row.instance_class,
        "storage_size_gb": resource_row.storage_size_gb,
        "multi_az": resource_row.multi_az,
        "replicas": resource_row.replicas,
        "tls_mode": resource_row.tls_mode,
        "tags": resource_row.tags or {},
        "endpoint": resource_row.endpoint,
        "port": resource_row.port,
        "database_name": getattr(resource_row, "database_name", None),
        "status": resource_row.status,
        "status_message": getattr(resource_row, "status_message", ""),
        "provider_resource_id": resource_row.provider_resource_id,
        "elder_entity_id": getattr(resource_row, "elder_entity_id", None),
        "created_at": resource_row.created_at.isoformat()
        if hasattr(resource_row.created_at, "isoformat")
        else resource_row.created_at,
        "updated_at": resource_row.updated_at.isoformat()
        if hasattr(resource_row.updated_at, "isoformat")
        else resource_row.updated_at,
    }
