"""Flask Blueprint for Hadoop HDFS cluster management endpoints.

Provides comprehensive HDFS cluster operations including:
- Create, read, update, delete clusters
- Cluster scaling operations
- Metrics collection (disk usage, replication, nodes)
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from app.schemas.hdfs import (
    HDFSClusterCreate,
    HDFSClusterUpdate,
    HDFSClusterResponse,
    HDFSClusterListResponse,
    HDFSClusterScaleRequest,
)

logger = logging.getLogger(__name__)

hdfs_bp = Blueprint(
    "hdfs",
    __name__,
    url_prefix="/hdfs",
    description="Hadoop HDFS cluster management endpoints",
)


@hdfs_bp.route("", methods=["GET"])
@login_required
def list_hdfs_clusters() -> Tuple[Dict[str, Any], int]:
    """
    List HDFS clusters with pagination and filtering.

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

        query = db.hdfs_clusters.state != "deleted"

        if status:
            query = query & (db.hdfs_clusters.state == status)

        if application_id:
            query = query & (db.hdfs_clusters.application_id == application_id)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        clusters = db(query).select(
            orderby=getattr(db.hdfs_clusters, sort_by)
            if sort_order == "asc"
            else ~getattr(db.hdfs_clusters, sort_by),
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
        logger.error(f"Error listing HDFS clusters: {e}")
        return jsonify({"error": "Failed to list clusters"}), 500


@hdfs_bp.route("", methods=["POST"])
@login_required
def create_hdfs_cluster() -> Tuple[Dict[str, Any], int]:
    """
    Create a new HDFS cluster.

    Request Body (JSON):
        name (str): Cluster name
        namenode_count (int): Number of NameNodes
        datanode_count (int): Number of DataNodes
        datanode_instance_type (str): DataNode instance type
        disk_size_gb_per_datanode (int): Disk size per DataNode
        replication_factor (int): Default replication factor
        hadoop_version (str): Hadoop version
        provider_id (str): Provider ID
        application_id (str, optional): Application ID
        ha_enabled (bool): Enable High Availability
        tags (dict, optional): Cluster tags

    Returns:
        201 Created response with cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_create = HDFSClusterCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Services not initialized"}), 500

        cluster_id = db.hdfs_clusters.insert(
            name=cluster_create.name,
            engine_type=cluster_create.engine_type.value,
            cluster_mode=cluster_create.cluster_mode.value,
            namenode_count=cluster_create.namenode_count,
            datanode_count=cluster_create.datanode_count,
            datanode_instance_type=cluster_create.datanode_instance_type,
            namenode_instance_type=cluster_create.namenode_instance_type,
            disk_size_gb_per_datanode=cluster_create.disk_size_gb_per_datanode,
            replication_factor=cluster_create.replication_factor,
            block_size_mb=cluster_create.block_size_mb,
            hadoop_version=cluster_create.hadoop_version,
            java_version=cluster_create.java_version,
            provider_id=cluster_create.provider_id,
            application_id=cluster_create.application_id,
            namenode_port=cluster_create.namenode_port,
            webhdfs_port=cluster_create.webhdfs_port,
            datanode_port=cluster_create.datanode_port,
            secondary_namenode_enabled=cluster_create.secondary_namenode_enabled,
            ha_enabled=cluster_create.ha_enabled,
            ha_zookeeper_quorum=cluster_create.ha_zookeeper_quorum,
            ha_automatic_failover=cluster_create.ha_automatic_failover,
            rack_awareness_enabled=cluster_create.rack_awareness_enabled,
            dfs_namenode_safemode_threshold_pct=cluster_create.dfs_namenode_safemode_threshold_pct,
            dfs_rebalance_blockpinning_enabled=cluster_create.dfs_rebalance_blockpinning_enabled,
            hdfs_config=cluster_create.hdfs_config,
            tags=cluster_create.tags,
            state="pending",
            state_message="Cluster provisioning initiated",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        cluster = db(db.hdfs_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(cluster)

        logger.info(
            f"HDFS cluster created: {cluster_create.name} "
            f"(id: {cluster_id}, user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating HDFS cluster: {e}")
        return jsonify({"error": "Failed to create cluster"}), 500


@hdfs_bp.route("/<cluster_id>", methods=["GET"])
@login_required
def get_hdfs_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get HDFS cluster details.

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
            (db.hdfs_clusters.id == cluster_id) & (db.hdfs_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        response_data = _cluster_row_to_response(cluster)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting HDFS cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to get cluster"}), 500


@hdfs_bp.route("/<cluster_id>", methods=["PUT"])
@login_required
def update_hdfs_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update HDFS cluster configuration.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        datanode_count (int, optional): New DataNode count
        disk_size_gb_per_datanode (int, optional): New disk size
        replication_factor (int, optional): New replication factor
        secondary_namenode_enabled (bool, optional): Update secondary NameNode
        rack_awareness_enabled (bool, optional): Update rack awareness
        tags (dict, optional): Updated tags

    Returns:
        JSON response with updated cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_update = HDFSClusterUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.hdfs_clusters.id == cluster_id) & (db.hdfs_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {"updated_at": datetime.utcnow()}

        if cluster_update.datanode_count is not None:
            update_data["datanode_count"] = cluster_update.datanode_count

        if cluster_update.disk_size_gb_per_datanode is not None:
            update_data["disk_size_gb_per_datanode"] = cluster_update.disk_size_gb_per_datanode

        if cluster_update.replication_factor is not None:
            update_data["replication_factor"] = cluster_update.replication_factor

        if cluster_update.block_size_mb is not None:
            update_data["block_size_mb"] = cluster_update.block_size_mb

        if cluster_update.secondary_namenode_enabled is not None:
            update_data["secondary_namenode_enabled"] = cluster_update.secondary_namenode_enabled

        if cluster_update.rack_awareness_enabled is not None:
            update_data["rack_awareness_enabled"] = cluster_update.rack_awareness_enabled

        if cluster_update.dfs_namenode_safemode_threshold_pct is not None:
            update_data["dfs_namenode_safemode_threshold_pct"] = cluster_update.dfs_namenode_safemode_threshold_pct

        if cluster_update.hdfs_config is not None:
            update_data["hdfs_config"] = cluster_update.hdfs_config

        if cluster_update.tags is not None:
            update_data["tags"] = cluster_update.tags

        db(db.hdfs_clusters.id == cluster_id).update(**update_data)
        db.commit()

        updated_cluster = db(db.hdfs_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(updated_cluster)

        logger.info(f"HDFS cluster updated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating HDFS cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to update cluster"}), 500


@hdfs_bp.route("/<cluster_id>", methods=["DELETE"])
@login_required
def delete_hdfs_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete HDFS cluster (soft delete - mark as deleted).

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
            (db.hdfs_clusters.id == cluster_id) & (db.hdfs_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        db(db.hdfs_clusters.id == cluster_id).update(
            state="deleted",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"HDFS cluster deleted: {cluster_id} (user: {current_user.email})")

        return jsonify({"id": cluster_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting HDFS cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to delete cluster"}), 500


@hdfs_bp.route("/<cluster_id>/scale", methods=["POST"])
@login_required
def scale_hdfs_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Scale an HDFS cluster (add/remove DataNodes, adjust storage).

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        datanode_count (int, optional): New DataNode count
        disk_size_gb_per_datanode (int, optional): New disk size per DataNode

    Returns:
        JSON response with scaling status
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            scale_request = HDFSClusterScaleRequest(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.hdfs_clusters.id == cluster_id) & (db.hdfs_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {
            "state": "scaling",
            "state_message": "Cluster scaling in progress",
            "updated_at": datetime.utcnow(),
        }

        if scale_request.datanode_count is not None:
            update_data["datanode_count"] = scale_request.datanode_count

        if scale_request.disk_size_gb_per_datanode is not None:
            update_data["disk_size_gb_per_datanode"] = scale_request.disk_size_gb_per_datanode

        db(db.hdfs_clusters.id == cluster_id).update(**update_data)
        db.commit()

        scaled_cluster = db(db.hdfs_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(scaled_cluster)

        logger.info(f"HDFS cluster scaling initiated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error scaling HDFS cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to scale cluster"}), 500


@hdfs_bp.route("/<cluster_id>/metrics", methods=["GET"])
@login_required
def get_hdfs_cluster_metrics(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get HDFS cluster metrics (disk usage, replication, nodes).

    Path Parameters:
        cluster_id (str): Cluster ID

    Returns:
        JSON response with cluster metrics
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.hdfs_clusters.id == cluster_id) & (db.hdfs_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        metrics_data = {
            "cluster_id": cluster_id,
            "cluster_name": cluster.name,
            "total_capacity_gb": cluster.datanode_count * cluster.disk_size_gb_per_datanode,
            "datanode_count": cluster.datanode_count,
            "namenode_count": cluster.namenode_count,
            "replication_factor": cluster.replication_factor,
            "block_size_mb": cluster.block_size_mb,
            "ha_enabled": cluster.ha_enabled,
            "secondary_namenode_enabled": cluster.secondary_namenode_enabled,
            "timestamp": datetime.utcnow().isoformat(),
        }

        return jsonify(metrics_data), 200

    except Exception as e:
        logger.error(f"Error getting HDFS cluster metrics for {cluster_id}: {e}")
        return jsonify({"error": "Failed to get metrics"}), 500


def _cluster_row_to_response(cluster_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL cluster row to response format.

    Args:
        cluster_row: PyDAL database row

    Returns:
        Dictionary matching HDFSClusterResponse schema
    """
    return {
        "id": cluster_row.id,
        "name": cluster_row.name,
        "engine_type": cluster_row.engine_type,
        "cluster_mode": cluster_row.cluster_mode,
        "namenode_count": cluster_row.namenode_count,
        "datanode_count": cluster_row.datanode_count,
        "datanode_instance_type": cluster_row.datanode_instance_type,
        "namenode_instance_type": cluster_row.namenode_instance_type,
        "disk_size_gb_per_datanode": cluster_row.disk_size_gb_per_datanode,
        "replication_factor": cluster_row.replication_factor,
        "block_size_mb": cluster_row.block_size_mb,
        "hadoop_version": cluster_row.hadoop_version,
        "java_version": cluster_row.java_version,
        "provider_id": cluster_row.provider_id,
        "application_id": cluster_row.application_id,
        "namenode_port": cluster_row.namenode_port,
        "webhdfs_port": cluster_row.webhdfs_port,
        "datanode_port": cluster_row.datanode_port,
        "secondary_namenode_enabled": cluster_row.secondary_namenode_enabled,
        "ha_enabled": cluster_row.ha_enabled,
        "ha_zookeeper_quorum": cluster_row.ha_zookeeper_quorum,
        "ha_automatic_failover": cluster_row.ha_automatic_failover,
        "rack_awareness_enabled": cluster_row.rack_awareness_enabled,
        "dfs_namenode_safemode_threshold_pct": cluster_row.dfs_namenode_safemode_threshold_pct,
        "dfs_rebalance_blockpinning_enabled": cluster_row.dfs_rebalance_blockpinning_enabled,
        "hdfs_config": cluster_row.hdfs_config or {},
        "tags": cluster_row.tags or {},
        "state": cluster_row.state,
        "state_message": getattr(cluster_row, "state_message", ""),
        "namenode_endpoint": getattr(cluster_row, "namenode_endpoint", None),
        "webhdfs_endpoint": getattr(cluster_row, "webhdfs_endpoint", None),
        "provider_cluster_id": getattr(cluster_row, "provider_cluster_id", None),
        "created_at": cluster_row.created_at.isoformat()
        if hasattr(cluster_row.created_at, "isoformat")
        else cluster_row.created_at,
        "updated_at": cluster_row.updated_at.isoformat()
        if hasattr(cluster_row.updated_at, "isoformat")
        else cluster_row.updated_at,
    }
