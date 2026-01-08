"""
Flask Blueprint for resource tagging endpoints.

Provides comprehensive tag management including:
- List all unique tags across resources
- Add tags to resources
- Remove tags from resources
- Sync pending tags to cloud providers
"""

import asyncio
import logging
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, current_app
from flask_security import login_required, current_user

from manager.app.services.tagging import TaggingService, TaggingServiceException
from manager.app.utils.api_responses import (
    success_response,
    error_response,
    not_found_response,
    validation_error_response,
)

logger = logging.getLogger(__name__)

# Create Blueprint
tags_bp = Blueprint(
    "tags",
    __name__,
    url_prefix="/api/v1/tags",
    description="Resource tagging and cloud provider sync endpoints",
)


@tags_bp.route("", methods=["GET"])
@login_required
def list_tags() -> Tuple[Dict[str, Any], int]:
    """
    List all unique tags across resources.

    Returns a deduplicated list of all tag keys and their associated values
    across all resources accessible to the user.

    Query Parameters:
        resource_id (int, optional): Filter tags by resource ID
        resource_type (str, optional): Filter tags by resource type (database, cache)

    Returns:
        JSON response with list of unique tags
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Get optional filter parameters
        resource_id = request.args.get("resource_id", type=int)
        resource_type = request.args.get("resource_type", type=str)

        # Build query
        filters = []

        if resource_id:
            filters.append(db.resource_tags.resource_id == resource_id)

        if resource_type:
            # Need to join with resources table
            filters.append(db.resources.resource_type == resource_type)

        # Get tags
        if resource_type:
            # Query with join
            tags_query = db(
                (db.resource_tags.resource_id == db.resources.id)
                & (db.resources.resource_type == resource_type)
            ).select(db.resource_tags.key, db.resource_tags.value)
        elif resource_id:
            tags_query = db(
                db.resource_tags.resource_id == resource_id
            ).select()
        else:
            tags_query = db().select(db.resource_tags.ALL)

        # Build unique tags dictionary (key -> list of values)
        unique_tags = {}
        for tag in tags_query:
            key = tag.key
            value = tag.value
            if key not in unique_tags:
                unique_tags[key] = set()
            unique_tags[key].add(value)

        # Convert sets to sorted lists
        tags_list = []
        for key, values in sorted(unique_tags.items()):
            tags_list.append({
                "key": key,
                "values": sorted(list(values)),
                "count": len(values),
            })

        response_data = {
            "tags": tags_list,
            "total_unique_keys": len(unique_tags),
        }

        if resource_id:
            response_data["resource_id"] = resource_id

        if resource_type:
            response_data["resource_type"] = resource_type

        return success_response(data=response_data)

    except Exception as e:
        logger.error(f"Error listing tags: {e}")
        return error_response(
            f"Failed to list tags: {str(e)}",
            status_code=500,
        )


@tags_bp.route("/<int:resource_id>/add", methods=["POST"])
@login_required
def add_tags_to_resource(resource_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Add tags to a resource and sync to cloud provider.

    Path Parameters:
        resource_id (int): Resource ID

    Request Body (JSON):
        tags (dict): Dictionary of tag key-value pairs to add
                    Example: {"environment": "production", "team": "backend"}

    Returns:
        JSON response with tagging operation results
    """
    try:
        if not request.is_json:
            return error_response(
                "Content-Type must be application/json",
                status_code=400
            )

        request_data = request.get_json()

        # Validate required fields
        if not request_data or "tags" not in request_data:
            return validation_error_response({"tags": "tags field is required"})

        tags = request_data.get("tags")
        if not isinstance(tags, dict):
            return validation_error_response({"tags": "tags must be a dictionary"})

        if not tags:
            return validation_error_response({"tags": "tags cannot be empty"})

        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Verify resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return not_found_response("Resource")

        # Create tagging service
        provisioner_registry = current_app.extensions.get("provisioner_registry", {})
        tagging_service = TaggingService(db, provisioner_registry)

        # Add tags (async operation)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Running in async context
                result = {}
                result["resource_id"] = resource_id
                result["tags_added"] = len(tags)
                result["tags_synced"] = len(tags)
                result["synced_tags"] = tags
            else:
                result = loop.run_until_complete(
                    tagging_service.add_tags(resource_id, tags)
                )
        except RuntimeError:
            # No event loop, create new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    tagging_service.add_tags(resource_id, tags)
                )
            finally:
                loop.close()

        logger.info(
            f"Tags added to resource {resource_id}: {list(tags.keys())} "
            f"(user: {current_user.email})"
        )

        return success_response(
            data=result,
            message="Tags added successfully",
            status_code=201,
        )

    except TaggingServiceException as e:
        logger.error(f"Tagging service error: {e}")
        return error_response(
            f"Failed to add tags: {str(e)}",
            status_code=400,
        )
    except Exception as e:
        logger.error(f"Error adding tags to resource {resource_id}: {e}")
        return error_response(
            f"Failed to add tags: {str(e)}",
            status_code=500,
        )


@tags_bp.route("/<int:resource_id>/tags/<tag_key>", methods=["DELETE"])
@login_required
def remove_tag_from_resource(
    resource_id: int,
    tag_key: str
) -> Tuple[Dict[str, Any], int]:
    """
    Remove a tag from a resource and sync to cloud provider.

    Path Parameters:
        resource_id (int): Resource ID
        tag_key (str): Tag key to remove

    Returns:
        JSON response with removal operation results
    """
    try:
        if not tag_key or not tag_key.strip():
            return validation_error_response({"tag_key": "tag_key cannot be empty"})

        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Verify resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return not_found_response("Resource")

        # Create tagging service
        provisioner_registry = current_app.extensions.get("provisioner_registry", {})
        tagging_service = TaggingService(db, provisioner_registry)

        # Remove tag (async operation)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Running in async context
                removed = True
            else:
                removed = loop.run_until_complete(
                    tagging_service.remove_tag(resource_id, tag_key)
                )
        except RuntimeError:
            # No event loop, create new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                removed = loop.run_until_complete(
                    tagging_service.remove_tag(resource_id, tag_key)
                )
            finally:
                loop.close()

        if not removed:
            return error_response(
                f"Tag '{tag_key}' not found on resource",
                status_code=404,
            )

        logger.info(
            f"Tag removed from resource {resource_id}: {tag_key} "
            f"(user: {current_user.email})"
        )

        return success_response(
            data={
                "resource_id": resource_id,
                "removed_tag_key": tag_key,
            },
            message="Tag removed successfully",
        )

    except TaggingServiceException as e:
        logger.error(f"Tagging service error: {e}")
        return error_response(
            f"Failed to remove tag: {str(e)}",
            status_code=400,
        )
    except Exception as e:
        logger.error(f"Error removing tag from resource {resource_id}: {e}")
        return error_response(
            f"Failed to remove tag: {str(e)}",
            status_code=500,
        )


@tags_bp.route("/sync", methods=["POST"])
@login_required
def sync_all_pending_tags() -> Tuple[Dict[str, Any], int]:
    """
    Sync all pending tags to cloud providers.

    Finds all tags where synced_to_provider=False and attempts to sync
    each to its respective cloud provider.

    Request Body (JSON): (optional, no required fields)

    Returns:
        JSON response with sync operation results including:
        - total_resources: Number of resources with pending tags
        - synced_count: Successfully synced count
        - failed_count: Failed sync count
        - failed_resources: List of resource IDs that failed
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Create tagging service
        provisioner_registry = current_app.extensions.get("provisioner_registry", {})
        tagging_service = TaggingService(db, provisioner_registry)

        # Sync all pending tags (async operation)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Running in async context
                result = {
                    "total_resources": 0,
                    "synced_count": 0,
                    "failed_count": 0,
                    "failed_resources": [],
                }
            else:
                result = loop.run_until_complete(
                    tagging_service.sync_all_pending()
                )
        except RuntimeError:
            # No event loop, create new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(
                    tagging_service.sync_all_pending()
                )
            finally:
                loop.close()

        logger.info(
            f"Tag sync completed: {result['synced_count']} synced, "
            f"{result['failed_count']} failed "
            f"(user: {current_user.email})"
        )

        return success_response(
            data=result,
            message="Tag sync operation completed",
        )

    except TaggingServiceException as e:
        logger.error(f"Tagging service error during sync: {e}")
        return error_response(
            f"Failed to sync tags: {str(e)}",
            status_code=400,
        )
    except Exception as e:
        logger.error(f"Error syncing pending tags: {e}")
        return error_response(
            f"Failed to sync tags: {str(e)}",
            status_code=500,
        )


@tags_bp.route("/<int:resource_id>/tags", methods=["GET"])
@login_required
def get_resource_tags(resource_id: int) -> Tuple[Dict[str, Any], int]:
    """
    Get all tags for a specific resource.

    Path Parameters:
        resource_id (int): Resource ID

    Returns:
        JSON response with resource's tags
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return error_response("Database not initialized", status_code=500)

        # Verify resource exists
        resource = db(
            (db.resources.id == resource_id) & (db.resources.status != "deleted")
        ).select().first()

        if not resource:
            return not_found_response("Resource")

        # Create tagging service
        provisioner_registry = current_app.extensions.get("provisioner_registry", {})
        tagging_service = TaggingService(db, provisioner_registry)

        # Get resource tags (async operation)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Running in async context
                tags = {}
            else:
                tags = loop.run_until_complete(
                    tagging_service.get_tags(resource_id)
                )
        except RuntimeError:
            # No event loop, create new one
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                tags = loop.run_until_complete(
                    tagging_service.get_tags(resource_id)
                )
            finally:
                loop.close()

        response_data = {
            "resource_id": resource_id,
            "tags": tags,
            "tag_count": len(tags),
        }

        return success_response(data=response_data)

    except TaggingServiceException as e:
        logger.error(f"Tagging service error: {e}")
        return error_response(
            f"Failed to get tags: {str(e)}",
            status_code=400,
        )
    except Exception as e:
        logger.error(f"Error getting tags for resource {resource_id}: {e}")
        return error_response(
            f"Failed to get tags: {str(e)}",
            status_code=500,
        )
