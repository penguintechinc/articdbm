"""Flask Blueprint for Apache HBase cluster management endpoints.

Provides comprehensive HBase cluster operations including:
- Create, read, update, delete clusters
- Cluster scaling operations
- Table management (create, update, delete, list)
- Cluster metrics collection
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from app.schemas.hbase import (
    HBaseClusterCreate,
    HBaseClusterUpdate,
    HBaseClusterResponse,
    HBaseClusterListResponse,
    HBaseClusterScaleRequest,
    HBaseTableCreate,
    HBaseTableResponse,
)

logger = logging.getLogger(__name__)

hbase_bp = Blueprint(
    "hbase",
    __name__,
    url_prefix="/hbase",
    description="Apache HBase cluster management endpoints",
)


@hbase_bp.route("", methods=["GET"])
@login_required
def list_hbase_clusters() -> Tuple[Dict[str, Any], int]:
    """
    List HBase clusters with pagination and filtering.

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

        query = db.hbase_clusters.state != "deleted"

        if status:
            query = query & (db.hbase_clusters.state == status)

        if application_id:
            query = query & (db.hbase_clusters.application_id == application_id)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        clusters = db(query).select(
            orderby=getattr(db.hbase_clusters, sort_by)
            if sort_order == "asc"
            else ~getattr(db.hbase_clusters, sort_by),
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
        logger.error(f"Error listing HBase clusters: {e}")
        return jsonify({"error": "Failed to list clusters"}), 500


@hbase_bp.route("", methods=["POST"])
@login_required
def create_hbase_cluster() -> Tuple[Dict[str, Any], int]:
    """
    Create a new HBase cluster.

    Request Body (JSON):
        name (str): Cluster name
        master_nodes (int): Number of HMaster nodes
        regionserver_nodes (int): Number of RegionServer nodes
        regionserver_instance_type (str): RegionServer instance type
        memory_per_regionserver_gb (int): Memory per RegionServer
        cores_per_regionserver (int): CPU cores per RegionServer
        hbase_version (str): HBase version
        provider_id (str): Provider ID
        application_id (str, optional): Application ID
        write_ahead_log_enabled (bool): Enable WAL
        tags (dict, optional): Cluster tags

    Returns:
        201 Created response with cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_create = HBaseClusterCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Services not initialized"}), 500

        cluster_id = db.hbase_clusters.insert(
            name=cluster_create.name,
            engine_type=cluster_create.engine_type.value,
            cluster_mode=cluster_create.cluster_mode.value,
            master_nodes=cluster_create.master_nodes,
            regionserver_nodes=cluster_create.regionserver_nodes,
            regionserver_instance_type=cluster_create.regionserver_instance_type,
            master_instance_type=cluster_create.master_instance_type,
            memory_per_regionserver_gb=cluster_create.memory_per_regionserver_gb,
            cores_per_regionserver=cluster_create.cores_per_regionserver,
            hbase_version=cluster_create.hbase_version,
            hadoop_version=cluster_create.hadoop_version,
            zookeeper_quorum=cluster_create.zookeeper_quorum,
            provider_id=cluster_create.provider_id,
            application_id=cluster_create.application_id,
            hmaster_port=cluster_create.hmaster_port,
            regionserver_port=cluster_create.regionserver_port,
            write_ahead_log_enabled=cluster_create.write_ahead_log_enabled,
            log_replication_factor=cluster_create.log_replication_factor,
            memstore_size_mb=cluster_create.memstore_size_mb,
            blocksize_mb=cluster_create.blocksize_mb,
            compression_type=cluster_create.compression_type,
            bloom_filter_type=cluster_create.bloom_filter_type,
            tags=cluster_create.tags,
            state="pending",
            state_message="Cluster provisioning initiated",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        cluster = db(db.hbase_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(cluster)

        logger.info(
            f"HBase cluster created: {cluster_create.name} "
            f"(id: {cluster_id}, user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating HBase cluster: {e}")
        return jsonify({"error": "Failed to create cluster"}), 500


@hbase_bp.route("/<cluster_id>", methods=["GET"])
@login_required
def get_hbase_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get HBase cluster details.

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
            (db.hbase_clusters.id == cluster_id) & (db.hbase_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        response_data = _cluster_row_to_response(cluster)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting HBase cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to get cluster"}), 500


@hbase_bp.route("/<cluster_id>", methods=["PUT"])
@login_required
def update_hbase_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update HBase cluster configuration.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        regionserver_nodes (int, optional): New RegionServer count
        memory_per_regionserver_gb (int, optional): New memory
        cores_per_regionserver (int, optional): New cores
        memstore_size_mb (int, optional): New MemStore size
        compression_type (str, optional): New compression type
        tags (dict, optional): Updated tags

    Returns:
        JSON response with updated cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_update = HBaseClusterUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.hbase_clusters.id == cluster_id) & (db.hbase_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {"updated_at": datetime.utcnow()}

        if cluster_update.regionserver_nodes is not None:
            update_data["regionserver_nodes"] = cluster_update.regionserver_nodes

        if cluster_update.memory_per_regionserver_gb is not None:
            update_data["memory_per_regionserver_gb"] = cluster_update.memory_per_regionserver_gb

        if cluster_update.cores_per_regionserver is not None:
            update_data["cores_per_regionserver"] = cluster_update.cores_per_regionserver

        if cluster_update.memstore_size_mb is not None:
            update_data["memstore_size_mb"] = cluster_update.memstore_size_mb

        if cluster_update.blocksize_mb is not None:
            update_data["blocksize_mb"] = cluster_update.blocksize_mb

        if cluster_update.compression_type is not None:
            update_data["compression_type"] = cluster_update.compression_type

        if cluster_update.tags is not None:
            update_data["tags"] = cluster_update.tags

        db(db.hbase_clusters.id == cluster_id).update(**update_data)
        db.commit()

        updated_cluster = db(db.hbase_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(updated_cluster)

        logger.info(f"HBase cluster updated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating HBase cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to update cluster"}), 500


@hbase_bp.route("/<cluster_id>", methods=["DELETE"])
@login_required
def delete_hbase_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete HBase cluster (soft delete - mark as deleted).

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
            (db.hbase_clusters.id == cluster_id) & (db.hbase_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        db(db.hbase_clusters.id == cluster_id).update(
            state="deleted",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"HBase cluster deleted: {cluster_id} (user: {current_user.email})")

        return jsonify({"id": cluster_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting HBase cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to delete cluster"}), 500


@hbase_bp.route("/<cluster_id>/scale", methods=["POST"])
@login_required
def scale_hbase_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Scale an HBase cluster (add/remove RegionServers, adjust resources).

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        regionserver_nodes (int, optional): New RegionServer count
        memory_per_regionserver_gb (int, optional): New memory per RegionServer
        cores_per_regionserver (int, optional): New cores per RegionServer

    Returns:
        JSON response with scaling status
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            scale_request = HBaseClusterScaleRequest(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.hbase_clusters.id == cluster_id) & (db.hbase_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {
            "state": "scaling",
            "state_message": "Cluster scaling in progress",
            "updated_at": datetime.utcnow(),
        }

        if scale_request.regionserver_nodes is not None:
            update_data["regionserver_nodes"] = scale_request.regionserver_nodes

        if scale_request.memory_per_regionserver_gb is not None:
            update_data["memory_per_regionserver_gb"] = scale_request.memory_per_regionserver_gb

        if scale_request.cores_per_regionserver is not None:
            update_data["cores_per_regionserver"] = scale_request.cores_per_regionserver

        db(db.hbase_clusters.id == cluster_id).update(**update_data)
        db.commit()

        scaled_cluster = db(db.hbase_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(scaled_cluster)

        logger.info(f"HBase cluster scaling initiated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error scaling HBase cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to scale cluster"}), 500


@hbase_bp.route("/<cluster_id>/tables", methods=["GET"])
@login_required
def list_hbase_tables(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    List HBase tables in a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20)

    Returns:
        JSON response with paginated table list
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
            (db.hbase_clusters.id == cluster_id) & (db.hbase_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        query = db.hbase_tables.cluster_id == cluster_id

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        tables = db(query).select(
            orderby=~db.hbase_tables.created_at,
            limitby=(offset, offset + page_size),
        )

        table_list = [_table_row_to_response(t) for t in tables]

        response_data = {
            "tables": table_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error listing HBase tables for cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to list tables"}), 500


@hbase_bp.route("/<cluster_id>/tables", methods=["POST"])
@login_required
def create_hbase_table(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Create a new HBase table in a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        name (str): Table name
        column_families (list): List of column family names
        max_filesize_mb (int, optional): Max file size
        region_split_count (int, optional): Number of initial regions
        compression_type (str, optional): Compression type

    Returns:
        201 Created response with table details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            table_create = HBaseTableCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.hbase_clusters.id == cluster_id) & (db.hbase_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        table_id = db.hbase_tables.insert(
            cluster_id=cluster_id,
            name=table_create.name,
            column_families=table_create.column_families,
            max_filesize_mb=table_create.max_filesize_mb,
            region_split_count=table_create.region_split_count,
            compression_type=table_create.compression_type,
            enabled=True,
            created_by=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.commit()

        table = db(db.hbase_tables.id == table_id).select().first()
        response_data = _table_row_to_response(table)

        logger.info(
            f"HBase table created: {table_create.name} "
            f"in cluster {cluster_id} (user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating HBase table in cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to create table"}), 500


@hbase_bp.route("/<cluster_id>/tables/<table_id>", methods=["DELETE"])
@login_required
def delete_hbase_table(cluster_id: str, table_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete an HBase table from a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID
        table_id (str): Table ID

    Returns:
        JSON response with deletion status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.hbase_clusters.id == cluster_id) & (db.hbase_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        table = db(
            (db.hbase_tables.id == table_id)
            & (db.hbase_tables.cluster_id == cluster_id)
        ).select().first()

        if not table:
            return jsonify({"error": "Table not found"}), 404

        db(db.hbase_tables.id == table_id).delete()
        db.commit()

        logger.info(f"HBase table deleted: {table_id} (user: {current_user.email})")

        return jsonify({"id": table_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting HBase table {table_id}: {e}")
        return jsonify({"error": "Failed to delete table"}), 500


def _cluster_row_to_response(cluster_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL cluster row to response format.

    Args:
        cluster_row: PyDAL database row

    Returns:
        Dictionary matching HBaseClusterResponse schema
    """
    return {
        "id": cluster_row.id,
        "name": cluster_row.name,
        "engine_type": cluster_row.engine_type,
        "cluster_mode": cluster_row.cluster_mode,
        "master_nodes": cluster_row.master_nodes,
        "regionserver_nodes": cluster_row.regionserver_nodes,
        "regionserver_instance_type": cluster_row.regionserver_instance_type,
        "master_instance_type": cluster_row.master_instance_type,
        "memory_per_regionserver_gb": cluster_row.memory_per_regionserver_gb,
        "cores_per_regionserver": cluster_row.cores_per_regionserver,
        "hbase_version": cluster_row.hbase_version,
        "hadoop_version": cluster_row.hadoop_version,
        "zookeeper_quorum": cluster_row.zookeeper_quorum,
        "provider_id": cluster_row.provider_id,
        "application_id": cluster_row.application_id,
        "hmaster_port": cluster_row.hmaster_port,
        "regionserver_port": cluster_row.regionserver_port,
        "write_ahead_log_enabled": cluster_row.write_ahead_log_enabled,
        "log_replication_factor": cluster_row.log_replication_factor,
        "memstore_size_mb": cluster_row.memstore_size_mb,
        "blocksize_mb": cluster_row.blocksize_mb,
        "compression_type": cluster_row.compression_type,
        "bloom_filter_type": cluster_row.bloom_filter_type,
        "tags": cluster_row.tags or {},
        "state": cluster_row.state,
        "state_message": getattr(cluster_row, "state_message", ""),
        "hmaster_endpoint": getattr(cluster_row, "hmaster_endpoint", None),
        "web_ui_endpoint": getattr(cluster_row, "web_ui_endpoint", None),
        "provider_cluster_id": getattr(cluster_row, "provider_cluster_id", None),
        "created_at": cluster_row.created_at.isoformat()
        if hasattr(cluster_row.created_at, "isoformat")
        else cluster_row.created_at,
        "updated_at": cluster_row.updated_at.isoformat()
        if hasattr(cluster_row.updated_at, "isoformat")
        else cluster_row.updated_at,
    }


def _table_row_to_response(table_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL table row to response format.

    Args:
        table_row: PyDAL database row

    Returns:
        Dictionary matching HBaseTableResponse schema
    """
    return {
        "id": table_row.id,
        "name": table_row.name,
        "column_families": table_row.column_families or [],
        "max_filesize_mb": table_row.max_filesize_mb,
        "region_split_count": table_row.region_split_count,
        "compression_type": table_row.compression_type,
        "enabled": table_row.enabled,
        "created_at": table_row.created_at.isoformat()
        if hasattr(table_row.created_at, "isoformat")
        else table_row.created_at,
    }
