"""
Flask Blueprint for MarchProxy integration endpoints.

Provides comprehensive MarchProxy management including:
- Connection status monitoring
- Route configuration and listing
- Resource-specific MarchProxy setup
- Configuration synchronization
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from manager.app.schemas.provider import (
    MarchProxyConfigRequest,
    MarchProxyStatusResponse,
)
from manager.app.integrations.marchproxy_client import MarchProxyClient
from manager.app.api.errors import (
    ValidationError,
    NotFoundError,
    ForbiddenError,
)
from manager.app.utils.api_responses import (
    success_response,
    error_response,
    validation_error_response,
)

logger = logging.getLogger(__name__)

# Create Blueprint
marchproxy_bp = Blueprint(
    "marchproxy",
    __name__,
    url_prefix="/api/v1/marchproxy",
    description="MarchProxy integration and route management endpoints",
)


@marchproxy_bp.route("/status", methods=["GET"])
@login_required
def get_marchproxy_status() -> Tuple[Dict[str, Any], int]:
    """
    Get MarchProxy connection status and configured routes.

    Query Parameters:
        detailed (bool, optional): Include detailed route information (default: false)

    Returns:
        JSON response with MarchProxy connection status and route count
    """
    try:
        # Get optional detailed flag
        detailed = request.args.get("detailed", False, type=bool)

        # Get MarchProxy client from app context
        marchproxy_client = current_app.extensions.get("marchproxy_client")
        if not marchproxy_client:
            return error_response(
                "MarchProxy client not initialized",
                status_code=500,
            )

        # Check connection status asynchronously
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Already in async context
                connected, message = (False, "Cannot check status in running loop")
            else:
                connected, message = loop.run_until_complete(
                    marchproxy_client.health_check()
                )
        except RuntimeError:
            # Create new event loop
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                connected, message = loop.run_until_complete(
                    marchproxy_client.health_check()
                )
            finally:
                loop.close()

        # Get routes if connected and detailed requested
        routes = []
        if connected and detailed:
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    routes = loop.run_until_complete(marchproxy_client.get_routes())
                else:
                    routes = []
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    routes = loop.run_until_complete(marchproxy_client.get_routes())
                finally:
                    loop.close()

        response_data = {
            "connected": connected,
            "message": message,
            "configured_routes": len(routes),
            "routes": routes if detailed else [],
        }

        return success_response(data=response_data)

    except Exception as e:
        logger.error(f"Error getting MarchProxy status: {e}")
        return error_response(
            f"Failed to get MarchProxy status: {str(e)}",
            status_code=500,
        )


@marchproxy_bp.route("/routes", methods=["GET"])
@login_required
def list_marchproxy_routes() -> Tuple[Dict[str, Any], int]:
    """
    List all configured MarchProxy routes.

    Query Parameters:
        include_metrics (bool, optional): Include route metrics (default: false)

    Returns:
        JSON response with list of configured routes
    """
    try:
        include_metrics = request.args.get("include_metrics", False, type=bool)

        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Get all configured MarchProxy routes from database
        routes = db(db.marchproxy_configs.status != "deleted").select()

        route_list = []
        for route in routes:
            route_data = {
                "id": route.id,
                "resource_id": route.resource_id,
                "enabled": route.enabled,
                "listen_port": route.listen_port,
                "connection_rate_limit": route.connection_rate_limit,
                "query_rate_limit": route.query_rate_limit,
                "enable_sql_injection_detection": route.enable_sql_injection_detection,
                "status": route.status,
                "created_at": route.created_at.isoformat()
                if hasattr(route.created_at, "isoformat")
                else route.created_at,
                "updated_at": route.updated_at.isoformat()
                if hasattr(route.updated_at, "isoformat")
                else route.updated_at,
            }

            # Get associated resource info
            resource = db(db.resources.id == route.resource_id).select().first()
            if resource:
                route_data["resource_name"] = resource.name
                route_data["resource_type"] = resource.resource_type
                route_data["engine"] = resource.engine

            # Optionally include metrics from MarchProxy
            if include_metrics:
                marchproxy_client = current_app.extensions.get("marchproxy_client")
                if marchproxy_client:
                    try:
                        loop = asyncio.get_event_loop()
                        if not loop.is_running():
                            metrics = loop.run_until_complete(
                                marchproxy_client.get_metrics(
                                    f"resource-{route.resource_id}"
                                )
                            )
                            route_data["metrics"] = metrics
                    except RuntimeError:
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        try:
                            metrics = loop.run_until_complete(
                                marchproxy_client.get_metrics(
                                    f"resource-{route.resource_id}"
                                )
                            )
                            route_data["metrics"] = metrics
                        finally:
                            loop.close()

            route_list.append(route_data)

        response_data = {
            "total": len(route_list),
            "routes": route_list,
        }

        return success_response(data=response_data)

    except Exception as e:
        logger.error(f"Error listing MarchProxy routes: {e}")
        return error_response(
            f"Failed to list routes: {str(e)}",
            status_code=500,
        )


@marchproxy_bp.route("/resources/<resource_id>/marchproxy", methods=["PUT"])
@login_required
def configure_resource_marchproxy(resource_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Configure MarchProxy for a specific resource.

    Path Parameters:
        resource_id (str): Resource ID

    Request Body (JSON):
        enabled (bool): Enable MarchProxy routing
        listen_port (int): Port MarchProxy listens on (1-65535)
        connection_rate_limit (int): Max concurrent connections (>0)
        query_rate_limit (int): Max queries per second (>0)
        enable_sql_injection_detection (bool): Enable SQL injection detection

    Returns:
        JSON response with updated MarchProxy configuration
    """
    try:
        if not request.is_json:
            return error_response(
                "Content-Type must be application/json",
                status_code=400,
            )

        request_data = request.get_json()

        # Validate request using Pydantic
        try:
            config_request = MarchProxyConfigRequest(**request_data)
        except PydanticValidationError as e:
            validation_errors = {}
            for error in e.errors():
                field = ".".join(str(x) for x in error["loc"])
                validation_errors[field] = error["msg"]
            return validation_error_response(validation_errors)

        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Check resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return error_response("Resource not found", status_code=404)

        # Check if MarchProxy config exists for resource
        existing_config = db(
            (db.marchproxy_configs.resource_id == resource_id)
            & (db.marchproxy_configs.status != "deleted")
        ).select().first()

        if existing_config:
            # Update existing configuration
            db(db.marchproxy_configs.id == existing_config.id).update(
                enabled=config_request.enabled,
                listen_port=config_request.listen_port,
                connection_rate_limit=config_request.connection_rate_limit,
                query_rate_limit=config_request.query_rate_limit,
                enable_sql_injection_detection=config_request.enable_sql_injection_detection,
                status="configured",
                updated_at=datetime.utcnow(),
            )
            config_id = existing_config.id
            message = "MarchProxy configuration updated"
        else:
            # Create new configuration
            config_id = db.marchproxy_configs.insert(
                resource_id=resource_id,
                enabled=config_request.enabled,
                listen_port=config_request.listen_port,
                connection_rate_limit=config_request.connection_rate_limit,
                query_rate_limit=config_request.query_rate_limit,
                enable_sql_injection_detection=config_request.enable_sql_injection_detection,
                status="configured",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                created_by=current_user.id,
            )
            message = "MarchProxy configuration created"

        db.commit()

        # If enabled, push config to MarchProxy
        if config_request.enabled:
            marchproxy_client = current_app.extensions.get("marchproxy_client")
            if marchproxy_client:
                try:
                    # Build route config from resource and MarchProxy config
                    route_config = {
                        "name": f"resource-{resource_id}",
                        "protocol": _get_protocol_from_engine(resource.engine),
                        "listen_port": config_request.listen_port,
                        "backend_host": resource.endpoint,
                        "backend_port": resource.port,
                        "max_connections": config_request.connection_rate_limit,
                        "enable_sql_injection_detection": config_request.enable_sql_injection_detection,
                    }

                    loop = asyncio.get_event_loop()
                    if not loop.is_running():
                        result = loop.run_until_complete(
                            marchproxy_client.create_route(route_config)
                        )
                        if result.get("success"):
                            db(db.marchproxy_configs.id == config_id).update(
                                status="synced"
                            )
                            db.commit()
                    else:
                        # Can't run async in running loop
                        pass
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        result = loop.run_until_complete(
                            marchproxy_client.create_route(route_config)
                        )
                        if result.get("success"):
                            db(db.marchproxy_configs.id == config_id).update(
                                status="synced"
                            )
                            db.commit()
                    except Exception as e:
                        logger.warning(f"Failed to sync to MarchProxy: {e}")
                    finally:
                        loop.close()

        # Fetch and return updated configuration
        config = db(db.marchproxy_configs.id == config_id).select().first()
        response_data = {
            "id": config.id,
            "resource_id": config.resource_id,
            "enabled": config.enabled,
            "listen_port": config.listen_port,
            "connection_rate_limit": config.connection_rate_limit,
            "query_rate_limit": config.query_rate_limit,
            "enable_sql_injection_detection": config.enable_sql_injection_detection,
            "status": config.status,
            "created_at": config.created_at.isoformat()
            if hasattr(config.created_at, "isoformat")
            else config.created_at,
            "updated_at": config.updated_at.isoformat()
            if hasattr(config.updated_at, "isoformat")
            else config.updated_at,
        }

        logger.info(
            f"MarchProxy configured for resource {resource_id} "
            f"(user: {current_user.email})"
        )

        return success_response(data=response_data, message=message)

    except Exception as e:
        logger.error(f"Error configuring MarchProxy for resource {resource_id}: {e}")
        return error_response(
            f"Failed to configure MarchProxy: {str(e)}",
            status_code=500,
        )


@marchproxy_bp.route("/resources/<resource_id>/marchproxy", methods=["DELETE"])
@login_required
def remove_resource_marchproxy(resource_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Remove MarchProxy configuration from a resource.

    Path Parameters:
        resource_id (str): Resource ID

    Returns:
        JSON response with deletion status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Check resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return error_response("Resource not found", status_code=404)

        # Find and delete MarchProxy config
        config = db(
            (db.marchproxy_configs.resource_id == resource_id)
            & (db.marchproxy_configs.status != "deleted")
        ).select().first()

        if not config:
            return error_response(
                "MarchProxy configuration not found for resource",
                status_code=404,
            )

        # Soft delete configuration
        db(db.marchproxy_configs.id == config.id).update(
            status="deleted",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        # Try to delete route from MarchProxy if enabled
        if config.enabled:
            marchproxy_client = current_app.extensions.get("marchproxy_client")
            if marchproxy_client:
                try:
                    route_name = f"resource-{resource_id}"
                    loop = asyncio.get_event_loop()
                    if not loop.is_running():
                        loop.run_until_complete(
                            marchproxy_client.delete_route(route_name)
                        )
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        route_name = f"resource-{resource_id}"
                        loop.run_until_complete(
                            marchproxy_client.delete_route(route_name)
                        )
                    except Exception as e:
                        logger.warning(f"Failed to delete route from MarchProxy: {e}")
                    finally:
                        loop.close()

        logger.info(
            f"MarchProxy configuration removed from resource {resource_id} "
            f"(user: {current_user.email})"
        )

        return success_response(
            data={"resource_id": resource_id, "status": "deleted"},
            message="MarchProxy configuration removed successfully",
        )

    except Exception as e:
        logger.error(f"Error removing MarchProxy from resource {resource_id}: {e}")
        return error_response(
            f"Failed to remove MarchProxy configuration: {str(e)}",
            status_code=500,
        )


@marchproxy_bp.route("/sync", methods=["POST"])
@login_required
def sync_marchproxy_configs() -> Tuple[Dict[str, Any], int]:
    """
    Synchronize all enabled MarchProxy configurations to MarchProxy.

    Syncs all enabled MarchProxy configurations from the database to the
    MarchProxy service, creating/updating routes as needed.

    Query Parameters:
        force (bool, optional): Force re-sync even if already synced (default: false)

    Returns:
        JSON response with sync results
    """
    try:
        force = request.args.get("force", False, type=bool)

        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        marchproxy_client = current_app.extensions.get("marchproxy_client")
        if not marchproxy_client:
            return error_response(
                "MarchProxy client not initialized",
                status_code=500,
            )

        # Get all enabled configurations
        configs = db(
            (db.marchproxy_configs.enabled == True)
            & (db.marchproxy_configs.status != "deleted")
        ).select()

        sync_results = []
        errors = []

        for config in configs:
            try:
                # Check if already synced (unless force requested)
                if config.status == "synced" and not force:
                    sync_results.append(
                        {
                            "resource_id": config.resource_id,
                            "status": "skipped",
                            "message": "Already synced",
                        }
                    )
                    continue

                # Get associated resource
                resource = db(db.resources.id == config.resource_id).select().first()
                if not resource:
                    errors.append(
                        {
                            "resource_id": config.resource_id,
                            "error": "Resource not found",
                        }
                    )
                    continue

                # Build route config
                route_config = {
                    "name": f"resource-{config.resource_id}",
                    "protocol": _get_protocol_from_engine(resource.engine),
                    "listen_port": config.listen_port,
                    "backend_host": resource.endpoint,
                    "backend_port": resource.port,
                    "max_connections": config.connection_rate_limit,
                    "enable_sql_injection_detection": config.enable_sql_injection_detection,
                }

                # Create/update route in MarchProxy
                loop = asyncio.get_event_loop()
                if not loop.is_running():
                    result = loop.run_until_complete(
                        marchproxy_client.create_route(route_config)
                    )
                    if result.get("success"):
                        db(db.marchproxy_configs.id == config.id).update(
                            status="synced",
                            updated_at=datetime.utcnow(),
                        )
                        db.commit()
                        sync_results.append(
                            {
                                "resource_id": config.resource_id,
                                "status": "synced",
                                "message": "Configuration synced successfully",
                            }
                        )
                    else:
                        errors.append(
                            {
                                "resource_id": config.resource_id,
                                "error": result.get("error", "Unknown error"),
                            }
                        )
                else:
                    # Can't run async in running loop
                    sync_results.append(
                        {
                            "resource_id": config.resource_id,
                            "status": "skipped",
                            "message": "Event loop already running",
                        }
                    )

            except Exception as e:
                logger.error(f"Error syncing resource {config.resource_id}: {e}")
                errors.append(
                    {
                        "resource_id": config.resource_id,
                        "error": str(e),
                    }
                )

        response_data = {
            "synced": len(sync_results),
            "sync_results": sync_results,
        }

        if errors:
            response_data["errors"] = errors
            response_data["error_count"] = len(errors)

        status_code = 200 if not errors else 207
        return success_response(
            data=response_data,
            message=f"Synced {len(sync_results)} configurations",
            status_code=status_code,
        )

    except Exception as e:
        logger.error(f"Error syncing MarchProxy configurations: {e}")
        return error_response(
            f"Failed to sync MarchProxy configurations: {str(e)}",
            status_code=500,
        )


def _get_protocol_from_engine(engine: str) -> str:
    """
    Convert ArticDBM engine type to MarchProxy protocol.

    Args:
        engine: Engine type from ArticDBM (postgresql, mysql, sqlite, etc.)

    Returns:
        Protocol name for MarchProxy (postgresql, mysql, etc.)
    """
    protocol_mapping = {
        "postgres": "postgresql",
        "postgresql": "postgresql",
        "mysql": "mysql",
        "mariadb": "mysql",
        "sqlite": "sqlite",
        "redis": "redis",
        "valkey": "redis",
    }

    engine_lower = (engine or "postgresql").lower()
    return protocol_mapping.get(engine_lower, "postgresql")
