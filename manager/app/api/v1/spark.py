"""Flask Blueprint for Apache Spark cluster management endpoints.

Provides comprehensive Spark cluster operations including:
- Create, read, update, delete clusters
- Cluster scaling operations
- Job submission, listing, and cancellation
- Job metrics collection
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from app.schemas.spark import (
    SparkClusterCreate,
    SparkClusterUpdate,
    SparkClusterResponse,
    SparkClusterListResponse,
    SparkClusterScaleRequest,
    SparkJobMetricsResponse,
)

logger = logging.getLogger(__name__)

spark_bp = Blueprint(
    "spark",
    __name__,
    url_prefix="/spark",
    description="Apache Spark cluster management endpoints",
)


@spark_bp.route("", methods=["GET"])
@login_required
def list_spark_clusters() -> Tuple[Dict[str, Any], int]:
    """
    List Spark clusters with pagination and filtering.

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20, max: 100)
        status (str): Filter by status (pending, provisioning, available, failed)
        application_id (str): Filter by application ID
        sort_by (str): Sort field (created_at, name, status)
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

        query = db.spark_clusters.state != "deleted"

        if status:
            query = query & (db.spark_clusters.state == status)

        if application_id:
            query = query & (db.spark_clusters.application_id == application_id)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        clusters = db(query).select(
            orderby=getattr(db.spark_clusters, sort_by)
            if sort_order == "asc"
            else ~getattr(db.spark_clusters, sort_by),
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
        logger.error(f"Error listing Spark clusters: {e}")
        return jsonify({"error": "Failed to list clusters"}), 500


@spark_bp.route("", methods=["POST"])
@login_required
def create_spark_cluster() -> Tuple[Dict[str, Any], int]:
    """
    Create a new Spark cluster.

    Request Body (JSON):
        name (str): Cluster name
        cluster_mode (str): Deployment mode (STANDALONE, YARN, K8S)
        worker_nodes (int): Number of worker nodes
        worker_instance_type (str): Worker instance type
        memory_per_node_gb (int): Memory per node
        cores_per_node (int): CPU cores per node
        spark_version (str): Spark version
        provider_id (str): Provider ID
        application_id (str, optional): Application ID
        enable_dynamic_allocation (bool): Enable dynamic allocation
        tags (dict, optional): Cluster tags

    Returns:
        201 Created response with cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_create = SparkClusterCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Services not initialized"}), 500

        cluster_id = db.spark_clusters.insert(
            name=cluster_create.name,
            engine_type=cluster_create.engine_type.value,
            cluster_mode=cluster_create.cluster_mode.value,
            master_nodes=cluster_create.master_nodes,
            worker_nodes=cluster_create.worker_nodes,
            worker_instance_type=cluster_create.worker_instance_type,
            master_instance_type=cluster_create.master_instance_type,
            memory_per_node_gb=cluster_create.memory_per_node_gb,
            cores_per_node=cluster_create.cores_per_node,
            spark_version=cluster_create.spark_version,
            hadoop_version=cluster_create.hadoop_version,
            provider_id=cluster_create.provider_id,
            application_id=cluster_create.application_id,
            yarn_queue=cluster_create.yarn_queue,
            enable_dynamic_allocation=cluster_create.enable_dynamic_allocation,
            min_executors=cluster_create.min_executors,
            max_executors=cluster_create.max_executors,
            executor_memory_gb=cluster_create.executor_memory_gb,
            executor_cores=cluster_create.executor_cores,
            driver_memory_gb=cluster_create.driver_memory_gb,
            driver_cores=cluster_create.driver_cores,
            log_s3_path=cluster_create.log_s3_path,
            bootstrap_scripts=cluster_create.bootstrap_scripts,
            spark_config=cluster_create.spark_config,
            hive_metastore_enabled=cluster_create.hive_metastore_enabled,
            tags=cluster_create.tags,
            state="pending",
            state_message="Cluster provisioning initiated",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        cluster = db(db.spark_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(cluster)

        logger.info(
            f"Spark cluster created: {cluster_create.name} "
            f"(id: {cluster_id}, user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating Spark cluster: {e}")
        return jsonify({"error": "Failed to create cluster"}), 500


@spark_bp.route("/<cluster_id>", methods=["GET"])
@login_required
def get_spark_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get Spark cluster details.

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
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        response_data = _cluster_row_to_response(cluster)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting Spark cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to get cluster"}), 500


@spark_bp.route("/<cluster_id>", methods=["PUT"])
@login_required
def update_spark_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update Spark cluster configuration.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        worker_nodes (int, optional): New worker count
        memory_per_node_gb (int, optional): New memory
        cores_per_node (int, optional): New cores
        enable_dynamic_allocation (bool, optional): Dynamic allocation setting
        min_executors (int, optional): Min executors
        max_executors (int, optional): Max executors
        tags (dict, optional): Updated tags

    Returns:
        JSON response with updated cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_update = SparkClusterUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
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

        if cluster_update.enable_dynamic_allocation is not None:
            update_data["enable_dynamic_allocation"] = cluster_update.enable_dynamic_allocation

        if cluster_update.min_executors is not None:
            update_data["min_executors"] = cluster_update.min_executors

        if cluster_update.max_executors is not None:
            update_data["max_executors"] = cluster_update.max_executors

        if cluster_update.executor_memory_gb is not None:
            update_data["executor_memory_gb"] = cluster_update.executor_memory_gb

        if cluster_update.executor_cores is not None:
            update_data["executor_cores"] = cluster_update.executor_cores

        if cluster_update.spark_config is not None:
            update_data["spark_config"] = cluster_update.spark_config

        if cluster_update.tags is not None:
            update_data["tags"] = cluster_update.tags

        db(db.spark_clusters.id == cluster_id).update(**update_data)
        db.commit()

        updated_cluster = db(db.spark_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(updated_cluster)

        logger.info(f"Spark cluster updated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating Spark cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to update cluster"}), 500


@spark_bp.route("/<cluster_id>", methods=["DELETE"])
@login_required
def delete_spark_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete Spark cluster (soft delete - mark as deleted).

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
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        db(db.spark_clusters.id == cluster_id).update(
            state="deleted",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"Spark cluster deleted: {cluster_id} (user: {current_user.email})")

        return jsonify({"id": cluster_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting Spark cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to delete cluster"}), 500


@spark_bp.route("/<cluster_id>/scale", methods=["POST"])
@login_required
def scale_spark_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Scale a Spark cluster (adjust worker nodes, instance size, memory).

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        worker_nodes (int, optional): New worker node count
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
            scale_request = SparkClusterScaleRequest(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
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

        db(db.spark_clusters.id == cluster_id).update(**update_data)
        db.commit()

        scaled_cluster = db(db.spark_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(scaled_cluster)

        logger.info(f"Spark cluster scaling initiated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error scaling Spark cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to scale cluster"}), 500


@spark_bp.route("/<cluster_id>/jobs", methods=["GET"])
@login_required
def list_spark_jobs(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    List Spark jobs for a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20)
        status (str): Filter by job status

    Returns:
        JSON response with paginated job list
    """
    try:
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 20, type=int)
        status = request.args.get("status", type=str)

        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 20

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        query = db.spark_jobs.cluster_id == cluster_id

        if status:
            query = query & (db.spark_jobs.status == status)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        jobs = db(query).select(
            orderby=~db.spark_jobs.created_at,
            limitby=(offset, offset + page_size),
        )

        job_list = []
        for job in jobs:
            job_list.append({
                "id": job.id,
                "cluster_id": job.cluster_id,
                "job_name": job.job_name,
                "status": job.status,
                "submitted_at": job.created_at.isoformat()
                if hasattr(job.created_at, "isoformat")
                else job.created_at,
                "duration_seconds": getattr(job, "duration_seconds", None),
            })

        response_data = {
            "jobs": job_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error listing Spark jobs for cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to list jobs"}), 500


@spark_bp.route("/<cluster_id>/jobs", methods=["POST"])
@login_required
def submit_spark_job(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Submit a new Spark job to a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        job_name (str): Job name
        main_class (str): Main class or script path
        jar_uri (str, optional): JAR file URI
        python_uri (str, optional): Python script URI
        arguments (list, optional): Job arguments
        parallelism (int, optional): Job parallelism

    Returns:
        JSON response with job submission status
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        job_id = db.spark_jobs.insert(
            cluster_id=cluster_id,
            job_name=request_data.get("job_name", "unknown"),
            main_class=request_data.get("main_class"),
            jar_uri=request_data.get("jar_uri"),
            python_uri=request_data.get("python_uri"),
            arguments=request_data.get("arguments", []),
            parallelism=request_data.get("parallelism"),
            status="submitted",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.commit()

        job = db(db.spark_jobs.id == job_id).select().first()

        response_data = {
            "id": job.id,
            "cluster_id": job.cluster_id,
            "job_name": job.job_name,
            "status": job.status,
            "submitted_at": job.created_at.isoformat()
            if hasattr(job.created_at, "isoformat")
            else job.created_at,
        }

        logger.info(
            f"Spark job submitted: {request_data.get('job_name')} "
            f"to cluster {cluster_id} (user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error submitting Spark job to cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to submit job"}), 500


@spark_bp.route("/<cluster_id>/jobs/<job_id>", methods=["GET"])
@login_required
def get_spark_job(cluster_id: str, job_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get Spark job details.

    Path Parameters:
        cluster_id (str): Cluster ID
        job_id (str): Job ID

    Returns:
        JSON response with job details and metrics
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        job = db(
            (db.spark_jobs.id == job_id) & (db.spark_jobs.cluster_id == cluster_id)
        ).select().first()

        if not job:
            return jsonify({"error": "Job not found"}), 404

        response_data = {
            "id": job.id,
            "cluster_id": job.cluster_id,
            "job_name": job.job_name,
            "status": job.status,
            "main_class": job.main_class,
            "jar_uri": job.jar_uri,
            "python_uri": job.python_uri,
            "arguments": job.arguments or [],
            "submitted_at": job.created_at.isoformat()
            if hasattr(job.created_at, "isoformat")
            else job.created_at,
            "duration_seconds": getattr(job, "duration_seconds", None),
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting Spark job {job_id}: {e}")
        return jsonify({"error": "Failed to get job"}), 500


@spark_bp.route("/<cluster_id>/jobs/<job_id>", methods=["DELETE"])
@login_required
def kill_spark_job(cluster_id: str, job_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Kill/cancel a Spark job.

    Path Parameters:
        cluster_id (str): Cluster ID
        job_id (str): Job ID

    Returns:
        JSON response with cancellation status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.spark_clusters.id == cluster_id) & (db.spark_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        job = db(
            (db.spark_jobs.id == job_id) & (db.spark_jobs.cluster_id == cluster_id)
        ).select().first()

        if not job:
            return jsonify({"error": "Job not found"}), 404

        db(db.spark_jobs.id == job_id).update(
            status="cancelled",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"Spark job cancelled: {job_id} (user: {current_user.email})")

        return jsonify({"id": job_id, "status": "cancelled"}), 200

    except Exception as e:
        logger.error(f"Error killing Spark job {job_id}: {e}")
        return jsonify({"error": "Failed to kill job"}), 500


def _cluster_row_to_response(cluster_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL cluster row to response format.

    Args:
        cluster_row: PyDAL database row

    Returns:
        Dictionary matching SparkClusterResponse schema
    """
    return {
        "id": cluster_row.id,
        "name": cluster_row.name,
        "engine_type": cluster_row.engine_type,
        "cluster_mode": cluster_row.cluster_mode,
        "master_nodes": cluster_row.master_nodes,
        "worker_nodes": cluster_row.worker_nodes,
        "worker_instance_type": cluster_row.worker_instance_type,
        "master_instance_type": cluster_row.master_instance_type,
        "memory_per_node_gb": cluster_row.memory_per_node_gb,
        "cores_per_node": cluster_row.cores_per_node,
        "spark_version": cluster_row.spark_version,
        "hadoop_version": cluster_row.hadoop_version,
        "provider_id": cluster_row.provider_id,
        "application_id": cluster_row.application_id,
        "yarn_queue": cluster_row.yarn_queue,
        "enable_dynamic_allocation": cluster_row.enable_dynamic_allocation,
        "min_executors": cluster_row.min_executors,
        "max_executors": cluster_row.max_executors,
        "executor_memory_gb": cluster_row.executor_memory_gb,
        "executor_cores": cluster_row.executor_cores,
        "driver_memory_gb": cluster_row.driver_memory_gb,
        "driver_cores": cluster_row.driver_cores,
        "log_s3_path": cluster_row.log_s3_path,
        "bootstrap_scripts": cluster_row.bootstrap_scripts or [],
        "spark_config": cluster_row.spark_config or {},
        "hive_metastore_enabled": cluster_row.hive_metastore_enabled,
        "tags": cluster_row.tags or {},
        "state": cluster_row.state,
        "state_message": getattr(cluster_row, "state_message", ""),
        "master_endpoint": getattr(cluster_row, "master_endpoint", None),
        "application_endpoint": getattr(cluster_row, "application_endpoint", None),
        "provider_cluster_id": getattr(cluster_row, "provider_cluster_id", None),
        "created_at": cluster_row.created_at.isoformat()
        if hasattr(cluster_row.created_at, "isoformat")
        else cluster_row.created_at,
        "updated_at": cluster_row.updated_at.isoformat()
        if hasattr(cluster_row.updated_at, "isoformat")
        else cluster_row.updated_at,
    }
