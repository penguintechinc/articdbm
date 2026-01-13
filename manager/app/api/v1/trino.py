"""Flask Blueprint for Trino query engine management endpoints.

Provides comprehensive Trino cluster operations including:
- Create, read, update, delete clusters
- Cluster scaling operations
- Catalog management (create, update, delete)
- SQL query execution
- Query metrics collection
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from app.schemas.trino import (
    TrinoClusterCreate,
    TrinoClusterUpdate,
    TrinoClusterResponse,
    TrinoClusterListResponse,
    TrinoClusterScaleRequest,
    TrinoCatalogCreate,
    TrinoCatalogUpdate,
    TrinoCatalogResponse,
)

logger = logging.getLogger(__name__)

trino_bp = Blueprint(
    "trino",
    __name__,
    url_prefix="/trino",
    description="Trino query engine management endpoints",
)


@trino_bp.route("", methods=["GET"])
@login_required
def list_trino_clusters() -> Tuple[Dict[str, Any], int]:
    """
    List Trino clusters with pagination and filtering.

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20, max: 100)
        status (str): Filter by status
        application_id (str): Filter by application ID
        sort_by (str): Sort field (created_at, name, state)
        sort_order (str): Sort order (asc, desc)

    Returns:
        JSON response with paginated cluster list
    """
    try:
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 20, type=int)
        status = request.args.get("status", type=str)
        application_id = request.args.get("application_id", type=str)
        sort_by = request.args.get("sort_by", "created_at", type=str)
        sort_order = request.args.get("sort_order", "desc", type=str)

        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 20

        valid_sort_fields = ["created_at", "name", "state"]
        if sort_by not in valid_sort_fields:
            sort_by = "created_at"
        if sort_order not in ["asc", "desc"]:
            sort_order = "desc"

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        query = db.trino_clusters.state != "deleted"

        if status:
            query = query & (db.trino_clusters.state == status)

        if application_id:
            query = query & (db.trino_clusters.application_id == application_id)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        clusters = db(query).select(
            orderby=getattr(db.trino_clusters, sort_by)
            if sort_order == "asc"
            else ~getattr(db.trino_clusters, sort_by),
            limitby=(offset, offset + page_size),
        )

        cluster_list = [_cluster_row_to_response(c) for c in clusters]

        response_data = {
            "clusters": cluster_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error listing Trino clusters: {e}")
        return jsonify({"error": "Failed to list clusters"}), 500


@trino_bp.route("", methods=["POST"])
@login_required
def create_trino_cluster() -> Tuple[Dict[str, Any], int]:
    """
    Create a new Trino cluster.

    Request Body (JSON):
        name (str): Cluster name
        cluster_mode (str): Deployment mode
        coordinator_nodes (int): Number of coordinator nodes
        worker_nodes (int): Number of worker nodes
        worker_instance_type (str): Worker instance type
        memory_per_node_gb (int): Memory per node
        cores_per_node (int): CPU cores per node
        trino_version (str): Trino version
        provider_id (str): Provider ID
        application_id (str, optional): Application ID
        catalogs (list, optional): Catalog configurations
        tags (dict, optional): Cluster tags

    Returns:
        201 Created response with cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_create = TrinoClusterCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Services not initialized"}), 500

        cluster_id = db.trino_clusters.insert(
            name=cluster_create.name,
            engine_type=cluster_create.engine_type.value,
            cluster_mode=cluster_create.cluster_mode.value,
            coordinator_nodes=cluster_create.coordinator_nodes,
            worker_nodes=cluster_create.worker_nodes,
            worker_instance_type=cluster_create.worker_instance_type,
            coordinator_instance_type=cluster_create.coordinator_instance_type,
            memory_per_node_gb=cluster_create.memory_per_node_gb,
            cores_per_node=cluster_create.cores_per_node,
            trino_version=cluster_create.trino_version,
            provider_id=cluster_create.provider_id,
            application_id=cluster_create.application_id,
            discovery_uri=cluster_create.discovery_uri,
            http_port=cluster_create.http_port,
            https_enabled=cluster_create.https_enabled,
            https_port=cluster_create.https_port,
            query_max_memory_gb=cluster_create.query_max_memory_gb,
            query_queue_max_wait_minutes=cluster_create.query_queue_max_wait_minutes,
            exchange_manager_type=cluster_create.exchange_manager_type,
            spill_enabled=cluster_create.spill_enabled,
            spill_order_by_enabled=cluster_create.spill_order_by_enabled,
            spill_join_enabled=cluster_create.spill_join_enabled,
            jvm_heap_memory_gb=cluster_create.jvm_heap_memory_gb,
            trino_config=cluster_create.trino_config,
            tags=cluster_create.tags,
            state="pending",
            state_message="Cluster provisioning initiated",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        cluster = db(db.trino_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(cluster)

        logger.info(
            f"Trino cluster created: {cluster_create.name} "
            f"(id: {cluster_id}, user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating Trino cluster: {e}")
        return jsonify({"error": "Failed to create cluster"}), 500


@trino_bp.route("/<cluster_id>", methods=["GET"])
@login_required
def get_trino_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get Trino cluster details.

    Path Parameters:
        cluster_id (str): Cluster ID

    Returns:
        JSON response with cluster details
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        response_data = _cluster_row_to_response(cluster)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting Trino cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to get cluster"}), 500


@trino_bp.route("/<cluster_id>", methods=["PUT"])
@login_required
def update_trino_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update Trino cluster configuration.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        worker_nodes (int, optional): New worker count
        memory_per_node_gb (int, optional): New memory
        cores_per_node (int, optional): New cores
        query_max_memory_gb (int, optional): New query memory limit
        spill_enabled (bool, optional): Update spill setting
        tags (dict, optional): Updated tags

    Returns:
        JSON response with updated cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_update = TrinoClusterUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {"updated_at": datetime.utcnow()}

        if cluster_update.worker_nodes is not None:
            update_data["worker_nodes"] = cluster_update.worker_nodes

        if cluster_update.memory_per_node_gb is not None:
            update_data["memory_per_node_gb"] = cluster_update.memory_per_node_gb

        if cluster_update.cores_per_node is not None:
            update_data["cores_per_node"] = cluster_update.cores_per_node

        if cluster_update.query_max_memory_gb is not None:
            update_data["query_max_memory_gb"] = cluster_update.query_max_memory_gb

        if cluster_update.query_queue_max_wait_minutes is not None:
            update_data["query_queue_max_wait_minutes"] = cluster_update.query_queue_max_wait_minutes

        if cluster_update.spill_enabled is not None:
            update_data["spill_enabled"] = cluster_update.spill_enabled

        if cluster_update.spill_order_by_enabled is not None:
            update_data["spill_order_by_enabled"] = cluster_update.spill_order_by_enabled

        if cluster_update.spill_join_enabled is not None:
            update_data["spill_join_enabled"] = cluster_update.spill_join_enabled

        if cluster_update.trino_config is not None:
            update_data["trino_config"] = cluster_update.trino_config

        if cluster_update.tags is not None:
            update_data["tags"] = cluster_update.tags

        db(db.trino_clusters.id == cluster_id).update(**update_data)
        db.commit()

        updated_cluster = db(db.trino_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(updated_cluster)

        logger.info(f"Trino cluster updated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating Trino cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to update cluster"}), 500


@trino_bp.route("/<cluster_id>", methods=["DELETE"])
@login_required
def delete_trino_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete Trino cluster (soft delete - mark as deleted).

    Path Parameters:
        cluster_id (str): Cluster ID

    Returns:
        JSON response with deletion status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        db(db.trino_clusters.id == cluster_id).update(
            state="deleted",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"Trino cluster deleted: {cluster_id} (user: {current_user.email})")

        return jsonify({"id": cluster_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting Trino cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to delete cluster"}), 500


@trino_bp.route("/<cluster_id>/scale", methods=["POST"])
@login_required
def scale_trino_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Scale a Trino cluster (adjust worker nodes, memory, cores).

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        worker_nodes (int, optional): New worker count
        memory_per_node_gb (int, optional): New memory per node
        cores_per_node (int, optional): New cores per node

    Returns:
        JSON response with scaling status
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            scale_request = TrinoClusterScaleRequest(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {
            "state": "scaling",
            "state_message": "Cluster scaling in progress",
            "updated_at": datetime.utcnow(),
        }

        if scale_request.worker_nodes is not None:
            update_data["worker_nodes"] = scale_request.worker_nodes

        if scale_request.memory_per_node_gb is not None:
            update_data["memory_per_node_gb"] = scale_request.memory_per_node_gb

        if scale_request.cores_per_node is not None:
            update_data["cores_per_node"] = scale_request.cores_per_node

        db(db.trino_clusters.id == cluster_id).update(**update_data)
        db.commit()

        scaled_cluster = db(db.trino_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(scaled_cluster)

        logger.info(f"Trino cluster scaling initiated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error scaling Trino cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to scale cluster"}), 500


@trino_bp.route("/<cluster_id>/catalogs", methods=["GET"])
@login_required
def list_trino_catalogs(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    List Trino catalogs for a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20)

    Returns:
        JSON response with paginated catalog list
    """
    try:
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 20, type=int)

        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 20

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        query = db.trino_catalogs.cluster_id == cluster_id

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        catalogs = db(query).select(
            orderby=~db.trino_catalogs.created_at,
            limitby=(offset, offset + page_size),
        )

        catalog_list = [_catalog_row_to_response(c) for c in catalogs]

        response_data = {
            "catalogs": catalog_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error listing Trino catalogs for cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to list catalogs"}), 500


@trino_bp.route("/<cluster_id>/catalogs", methods=["POST"])
@login_required
def create_trino_catalog(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Create a new Trino catalog for a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        name (str): Catalog name
        connector_type (str): Connector type (hive, iceberg, postgres, etc.)
        connector_properties (dict): Connector-specific properties
        description (str, optional): Catalog description

    Returns:
        201 Created response with catalog details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            catalog_create = TrinoCatalogCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        catalog_id = db.trino_catalogs.insert(
            cluster_id=cluster_id,
            name=catalog_create.name,
            connector_type=catalog_create.connector_type.value,
            connector_properties=catalog_create.connector_properties,
            description=catalog_create.description,
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        catalog = db(db.trino_catalogs.id == catalog_id).select().first()
        response_data = _catalog_row_to_response(catalog)

        logger.info(
            f"Trino catalog created: {catalog_create.name} "
            f"for cluster {cluster_id} (user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating Trino catalog for cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to create catalog"}), 500


@trino_bp.route("/<cluster_id>/catalogs/<catalog_id>", methods=["PUT"])
@login_required
def update_trino_catalog(cluster_id: str, catalog_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update a Trino catalog configuration.

    Path Parameters:
        cluster_id (str): Cluster ID
        catalog_id (str): Catalog ID

    Request Body (JSON):
        connector_properties (dict, optional): Updated properties
        description (str, optional): Updated description

    Returns:
        JSON response with updated catalog details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            catalog_update = TrinoCatalogUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        catalog = db(
            (db.trino_catalogs.id == catalog_id)
            & (db.trino_catalogs.cluster_id == cluster_id)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        update_data = {"updated_at": datetime.utcnow()}

        if catalog_update.connector_properties is not None:
            update_data["connector_properties"] = catalog_update.connector_properties

        if catalog_update.description is not None:
            update_data["description"] = catalog_update.description

        db(db.trino_catalogs.id == catalog_id).update(**update_data)
        db.commit()

        updated_catalog = db(db.trino_catalogs.id == catalog_id).select().first()
        response_data = _catalog_row_to_response(updated_catalog)

        logger.info(
            f"Trino catalog updated: {catalog_id} "
            f"(user: {current_user.email})"
        )

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating Trino catalog {catalog_id}: {e}")
        return jsonify({"error": "Failed to update catalog"}), 500


@trino_bp.route("/<cluster_id>/catalogs/<catalog_id>", methods=["DELETE"])
@login_required
def delete_trino_catalog(cluster_id: str, catalog_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete a Trino catalog.

    Path Parameters:
        cluster_id (str): Cluster ID
        catalog_id (str): Catalog ID

    Returns:
        JSON response with deletion status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        catalog = db(
            (db.trino_catalogs.id == catalog_id)
            & (db.trino_catalogs.cluster_id == cluster_id)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        db(db.trino_catalogs.id == catalog_id).delete()
        db.commit()

        logger.info(f"Trino catalog deleted: {catalog_id} (user: {current_user.email})")

        return jsonify({"id": catalog_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting Trino catalog {catalog_id}: {e}")
        return jsonify({"error": "Failed to delete catalog"}), 500


@trino_bp.route("/<cluster_id>/query", methods=["POST"])
@login_required
def execute_trino_query(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Execute a SQL query on a Trino cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        query (str): SQL query to execute
        catalog (str, optional): Catalog to use
        schema (str, optional): Schema to use
        max_result_rows (int, optional): Max rows to return (default: 1000)

    Returns:
        JSON response with query results or job status
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        query_text = request_data.get("query")
        if not query_text:
            return jsonify({"error": "query parameter is required"}), 400

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.trino_clusters.id == cluster_id) & (db.trino_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        query_id = db.trino_queries.insert(
            cluster_id=cluster_id,
            query_text=query_text,
            catalog=request_data.get("catalog"),
            schema=request_data.get("schema"),
            state="queued",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.commit()

        query_row = db(db.trino_queries.id == query_id).select().first()

        response_data = {
            "id": query_row.id,
            "cluster_id": query_row.cluster_id,
            "query_text": query_row.query_text,
            "state": query_row.state,
            "created_at": query_row.created_at.isoformat()
            if hasattr(query_row.created_at, "isoformat")
            else query_row.created_at,
        }

        logger.info(
            f"Trino query submitted to cluster {cluster_id} "
            f"(user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error executing Trino query on cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to execute query"}), 500


def _cluster_row_to_response(cluster_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL cluster row to response format.

    Args:
        cluster_row: PyDAL database row

    Returns:
        Dictionary matching TrinoClusterResponse schema
    """
    return {
        "id": cluster_row.id,
        "name": cluster_row.name,
        "engine_type": cluster_row.engine_type,
        "cluster_mode": cluster_row.cluster_mode,
        "coordinator_nodes": cluster_row.coordinator_nodes,
        "worker_nodes": cluster_row.worker_nodes,
        "worker_instance_type": cluster_row.worker_instance_type,
        "coordinator_instance_type": cluster_row.coordinator_instance_type,
        "memory_per_node_gb": cluster_row.memory_per_node_gb,
        "cores_per_node": cluster_row.cores_per_node,
        "trino_version": cluster_row.trino_version,
        "provider_id": cluster_row.provider_id,
        "application_id": cluster_row.application_id,
        "discovery_uri": cluster_row.discovery_uri,
        "http_port": cluster_row.http_port,
        "https_enabled": cluster_row.https_enabled,
        "https_port": cluster_row.https_port,
        "query_max_memory_gb": cluster_row.query_max_memory_gb,
        "query_queue_max_wait_minutes": cluster_row.query_queue_max_wait_minutes,
        "exchange_manager_type": cluster_row.exchange_manager_type,
        "spill_enabled": cluster_row.spill_enabled,
        "spill_order_by_enabled": cluster_row.spill_order_by_enabled,
        "spill_join_enabled": cluster_row.spill_join_enabled,
        "jvm_heap_memory_gb": cluster_row.jvm_heap_memory_gb,
        "trino_config": cluster_row.trino_config or {},
        "tags": cluster_row.tags or {},
        "state": cluster_row.state,
        "state_message": getattr(cluster_row, "state_message", ""),
        "coordinator_endpoint": getattr(cluster_row, "coordinator_endpoint", None),
        "web_ui_endpoint": getattr(cluster_row, "web_ui_endpoint", None),
        "provider_cluster_id": getattr(cluster_row, "provider_cluster_id", None),
        "created_at": cluster_row.created_at.isoformat()
        if hasattr(cluster_row.created_at, "isoformat")
        else cluster_row.created_at,
        "updated_at": cluster_row.updated_at.isoformat()
        if hasattr(cluster_row.updated_at, "isoformat")
        else cluster_row.updated_at,
    }


def _catalog_row_to_response(catalog_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL catalog row to response format.

    Args:
        catalog_row: PyDAL database row

    Returns:
        Dictionary matching TrinoCatalogResponse schema
    """
    return {
        "id": catalog_row.id,
        "name": catalog_row.name,
        "connector_type": catalog_row.connector_type,
        "connector_properties": catalog_row.connector_properties or {},
        "description": catalog_row.description,
        "created_at": catalog_row.created_at.isoformat()
        if hasattr(catalog_row.created_at, "isoformat")
        else catalog_row.created_at,
        "updated_at": catalog_row.updated_at.isoformat()
        if hasattr(catalog_row.updated_at, "isoformat")
        else catalog_row.updated_at,
    }
