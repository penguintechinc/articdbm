"""Flask Blueprint for Apache Flink cluster management endpoints.

Provides comprehensive Flink cluster operations including:
- Create, read, update, delete clusters
- Cluster scaling operations
- Job submission, listing, and cancellation
- Savepoint management for fault tolerance
- Job metrics collection
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from app.schemas.flink import (
    FlinkClusterCreate,
    FlinkClusterUpdate,
    FlinkClusterResponse,
    FlinkClusterListResponse,
    FlinkClusterScaleRequest,
)

logger = logging.getLogger(__name__)

flink_bp = Blueprint(
    "flink",
    __name__,
    url_prefix="/flink",
    description="Apache Flink cluster management endpoints",
)


@flink_bp.route("", methods=["GET"])
@login_required
def list_flink_clusters() -> Tuple[Dict[str, Any], int]:
    """
    List Flink clusters with pagination and filtering.

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

        query = db.flink_clusters.state != "deleted"

        if status:
            query = query & (db.flink_clusters.state == status)

        if application_id:
            query = query & (db.flink_clusters.application_id == application_id)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        clusters = db(query).select(
            orderby=getattr(db.flink_clusters, sort_by)
            if sort_order == "asc"
            else ~getattr(db.flink_clusters, sort_by),
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
        logger.error(f"Error listing Flink clusters: {e}")
        return jsonify({"error": "Failed to list clusters"}), 500


@flink_bp.route("", methods=["POST"])
@login_required
def create_flink_cluster() -> Tuple[Dict[str, Any], int]:
    """
    Create a new Flink cluster.

    Request Body (JSON):
        name (str): Cluster name
        cluster_mode (str): Deployment mode (STANDALONE, YARN, K8S)
        taskmanager_nodes (int): Number of TaskManager nodes
        taskmanager_instance_type (str): TaskManager instance type
        memory_per_taskmanager_gb (int): Memory per TaskManager
        cpu_per_taskmanager (int): CPU cores per TaskManager
        flink_version (str): Flink version
        provider_id (str): Provider ID
        application_id (str, optional): Application ID
        checkpointing_enabled (bool): Enable checkpointing
        tags (dict, optional): Cluster tags

    Returns:
        201 Created response with cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_create = FlinkClusterCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Services not initialized"}), 500

        cluster_id = db.flink_clusters.insert(
            name=cluster_create.name,
            engine_type=cluster_create.engine_type.value,
            cluster_mode=cluster_create.cluster_mode.value,
            jobmanager_nodes=cluster_create.jobmanager_nodes,
            taskmanager_nodes=cluster_create.taskmanager_nodes,
            taskmanager_instance_type=cluster_create.taskmanager_instance_type,
            jobmanager_instance_type=cluster_create.jobmanager_instance_type,
            memory_per_taskmanager_gb=cluster_create.memory_per_taskmanager_gb,
            cpu_per_taskmanager=cluster_create.cpu_per_taskmanager,
            jobmanager_memory_gb=cluster_create.jobmanager_memory_gb,
            flink_version=cluster_create.flink_version,
            hadoop_version=cluster_create.hadoop_version,
            provider_id=cluster_create.provider_id,
            application_id=cluster_create.application_id,
            yarn_queue=cluster_create.yarn_queue,
            task_slots_per_taskmanager=cluster_create.task_slots_per_taskmanager,
            parallelism=cluster_create.parallelism,
            checkpointing_enabled=cluster_create.checkpointing_enabled,
            checkpoint_interval_seconds=cluster_create.checkpoint_interval_seconds,
            state_backend=cluster_create.state_backend,
            state_checkpoint_dir=cluster_create.state_checkpoint_dir,
            log_s3_path=cluster_create.log_s3_path,
            flink_config=cluster_create.flink_config,
            tags=cluster_create.tags,
            state="pending",
            state_message="Cluster provisioning initiated",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        cluster = db(db.flink_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(cluster)

        logger.info(
            f"Flink cluster created: {cluster_create.name} "
            f"(id: {cluster_id}, user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating Flink cluster: {e}")
        return jsonify({"error": "Failed to create cluster"}), 500


@flink_bp.route("/<cluster_id>", methods=["GET"])
@login_required
def get_flink_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get Flink cluster details.

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
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        response_data = _cluster_row_to_response(cluster)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting Flink cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to get cluster"}), 500


@flink_bp.route("/<cluster_id>", methods=["PUT"])
@login_required
def update_flink_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update Flink cluster configuration.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        taskmanager_nodes (int, optional): New TaskManager count
        memory_per_taskmanager_gb (int, optional): New memory
        cpu_per_taskmanager (int, optional): New CPU cores
        parallelism (int, optional): New parallelism
        checkpointing_enabled (bool, optional): Update checkpointing
        tags (dict, optional): Updated tags

    Returns:
        JSON response with updated cluster details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            cluster_update = FlinkClusterUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {"updated_at": datetime.utcnow()}

        if cluster_update.taskmanager_nodes is not None:
            update_data["taskmanager_nodes"] = cluster_update.taskmanager_nodes

        if cluster_update.memory_per_taskmanager_gb is not None:
            update_data["memory_per_taskmanager_gb"] = cluster_update.memory_per_taskmanager_gb

        if cluster_update.cpu_per_taskmanager is not None:
            update_data["cpu_per_taskmanager"] = cluster_update.cpu_per_taskmanager

        if cluster_update.task_slots_per_taskmanager is not None:
            update_data["task_slots_per_taskmanager"] = cluster_update.task_slots_per_taskmanager

        if cluster_update.parallelism is not None:
            update_data["parallelism"] = cluster_update.parallelism

        if cluster_update.checkpointing_enabled is not None:
            update_data["checkpointing_enabled"] = cluster_update.checkpointing_enabled

        if cluster_update.checkpoint_interval_seconds is not None:
            update_data["checkpoint_interval_seconds"] = cluster_update.checkpoint_interval_seconds

        if cluster_update.state_backend is not None:
            update_data["state_backend"] = cluster_update.state_backend

        if cluster_update.flink_config is not None:
            update_data["flink_config"] = cluster_update.flink_config

        if cluster_update.tags is not None:
            update_data["tags"] = cluster_update.tags

        db(db.flink_clusters.id == cluster_id).update(**update_data)
        db.commit()

        updated_cluster = db(db.flink_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(updated_cluster)

        logger.info(f"Flink cluster updated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating Flink cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to update cluster"}), 500


@flink_bp.route("/<cluster_id>", methods=["DELETE"])
@login_required
def delete_flink_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete Flink cluster (soft delete - mark as deleted).

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
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        db(db.flink_clusters.id == cluster_id).update(
            state="deleted",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"Flink cluster deleted: {cluster_id} (user: {current_user.email})")

        return jsonify({"id": cluster_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting Flink cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to delete cluster"}), 500


@flink_bp.route("/<cluster_id>/scale", methods=["POST"])
@login_required
def scale_flink_cluster(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Scale a Flink cluster (adjust TaskManager nodes, instance size, memory).

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        taskmanager_nodes (int, optional): New TaskManager count
        memory_per_taskmanager_gb (int, optional): New memory per TaskManager
        cpu_per_taskmanager (int, optional): New CPU cores per TaskManager

    Returns:
        JSON response with scaling status
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            scale_request = FlinkClusterScaleRequest(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        update_data = {
            "state": "scaling",
            "state_message": "Cluster scaling in progress",
            "updated_at": datetime.utcnow(),
        }

        if scale_request.taskmanager_nodes is not None:
            update_data["taskmanager_nodes"] = scale_request.taskmanager_nodes

        if scale_request.memory_per_taskmanager_gb is not None:
            update_data["memory_per_taskmanager_gb"] = scale_request.memory_per_taskmanager_gb

        if scale_request.cpu_per_taskmanager is not None:
            update_data["cpu_per_taskmanager"] = scale_request.cpu_per_taskmanager

        db(db.flink_clusters.id == cluster_id).update(**update_data)
        db.commit()

        scaled_cluster = db(db.flink_clusters.id == cluster_id).select().first()
        response_data = _cluster_row_to_response(scaled_cluster)

        logger.info(f"Flink cluster scaling initiated: {cluster_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error scaling Flink cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to scale cluster"}), 500


@flink_bp.route("/<cluster_id>/jobs", methods=["GET"])
@login_required
def list_flink_jobs(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    List Flink jobs for a cluster.

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
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        query = db.flink_jobs.cluster_id == cluster_id

        if status:
            query = query & (db.flink_jobs.status == status)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        jobs = db(query).select(
            orderby=~db.flink_jobs.created_at,
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
        logger.error(f"Error listing Flink jobs for cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to list jobs"}), 500


@flink_bp.route("/<cluster_id>/jobs", methods=["POST"])
@login_required
def submit_flink_job(cluster_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Submit a new Flink job to a cluster.

    Path Parameters:
        cluster_id (str): Cluster ID

    Request Body (JSON):
        job_name (str): Job name
        jar_uri (str, optional): JAR file URI
        class_name (str, optional): Main class name
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
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        job_id = db.flink_jobs.insert(
            cluster_id=cluster_id,
            job_name=request_data.get("job_name", "unknown"),
            jar_uri=request_data.get("jar_uri"),
            class_name=request_data.get("class_name"),
            arguments=request_data.get("arguments", []),
            parallelism=request_data.get("parallelism"),
            status="submitted",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.commit()

        job = db(db.flink_jobs.id == job_id).select().first()

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
            f"Flink job submitted: {request_data.get('job_name')} "
            f"to cluster {cluster_id} (user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error submitting Flink job to cluster {cluster_id}: {e}")
        return jsonify({"error": "Failed to submit job"}), 500


@flink_bp.route("/<cluster_id>/jobs/<job_id>", methods=["GET"])
@login_required
def get_flink_job(cluster_id: str, job_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get Flink job details.

    Path Parameters:
        cluster_id (str): Cluster ID
        job_id (str): Job ID

    Returns:
        JSON response with job details
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        job = db(
            (db.flink_jobs.id == job_id) & (db.flink_jobs.cluster_id == cluster_id)
        ).select().first()

        if not job:
            return jsonify({"error": "Job not found"}), 404

        response_data = {
            "id": job.id,
            "cluster_id": job.cluster_id,
            "job_name": job.job_name,
            "status": job.status,
            "jar_uri": job.jar_uri,
            "class_name": job.class_name,
            "arguments": job.arguments or [],
            "parallelism": job.parallelism,
            "submitted_at": job.created_at.isoformat()
            if hasattr(job.created_at, "isoformat")
            else job.created_at,
            "duration_seconds": getattr(job, "duration_seconds", None),
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting Flink job {job_id}: {e}")
        return jsonify({"error": "Failed to get job"}), 500


@flink_bp.route("/<cluster_id>/jobs/<job_id>", methods=["DELETE"])
@login_required
def kill_flink_job(cluster_id: str, job_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Kill/cancel a Flink job.

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
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        job = db(
            (db.flink_jobs.id == job_id) & (db.flink_jobs.cluster_id == cluster_id)
        ).select().first()

        if not job:
            return jsonify({"error": "Job not found"}), 404

        db(db.flink_jobs.id == job_id).update(
            status="cancelled",
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"Flink job cancelled: {job_id} (user: {current_user.email})")

        return jsonify({"id": job_id, "status": "cancelled"}), 200

    except Exception as e:
        logger.error(f"Error killing Flink job {job_id}: {e}")
        return jsonify({"error": "Failed to kill job"}), 500


@flink_bp.route("/<cluster_id>/jobs/<job_id>/savepoint", methods=["POST"])
@login_required
def create_flink_savepoint(cluster_id: str, job_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Create a savepoint for a Flink job for fault tolerance and recovery.

    Path Parameters:
        cluster_id (str): Cluster ID
        job_id (str): Job ID

    Request Body (JSON):
        target_directory (str): Target directory for savepoint
        cancel_job (bool, optional): Cancel job after savepoint (default: False)

    Returns:
        JSON response with savepoint creation status
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        cluster = db(
            (db.flink_clusters.id == cluster_id) & (db.flink_clusters.state != "deleted")
        ).select().first()

        if not cluster:
            return jsonify({"error": "Cluster not found"}), 404

        job = db(
            (db.flink_jobs.id == job_id) & (db.flink_jobs.cluster_id == cluster_id)
        ).select().first()

        if not job:
            return jsonify({"error": "Job not found"}), 404

        target_directory = request_data.get("target_directory")
        if not target_directory:
            return jsonify({"error": "target_directory is required"}), 400

        cancel_job = request_data.get("cancel_job", False)

        savepoint_id = db.flink_savepoints.insert(
            job_id=job_id,
            cluster_id=cluster_id,
            target_directory=target_directory,
            cancel_job_after=cancel_job,
            status="in_progress",
            created_by=current_user.id,
            created_at=datetime.utcnow(),
        )
        db.commit()

        savepoint = db(db.flink_savepoints.id == savepoint_id).select().first()

        response_data = {
            "id": savepoint.id,
            "job_id": savepoint.job_id,
            "cluster_id": savepoint.cluster_id,
            "target_directory": savepoint.target_directory,
            "status": savepoint.status,
            "created_at": savepoint.created_at.isoformat()
            if hasattr(savepoint.created_at, "isoformat")
            else savepoint.created_at,
        }

        logger.info(
            f"Flink savepoint initiated for job {job_id} "
            f"(user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating Flink savepoint for job {job_id}: {e}")
        return jsonify({"error": "Failed to create savepoint"}), 500


def _cluster_row_to_response(cluster_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL cluster row to response format.

    Args:
        cluster_row: PyDAL database row

    Returns:
        Dictionary matching FlinkClusterResponse schema
    """
    return {
        "id": cluster_row.id,
        "name": cluster_row.name,
        "engine_type": cluster_row.engine_type,
        "cluster_mode": cluster_row.cluster_mode,
        "jobmanager_nodes": cluster_row.jobmanager_nodes,
        "taskmanager_nodes": cluster_row.taskmanager_nodes,
        "taskmanager_instance_type": cluster_row.taskmanager_instance_type,
        "jobmanager_instance_type": cluster_row.jobmanager_instance_type,
        "memory_per_taskmanager_gb": cluster_row.memory_per_taskmanager_gb,
        "cpu_per_taskmanager": cluster_row.cpu_per_taskmanager,
        "jobmanager_memory_gb": cluster_row.jobmanager_memory_gb,
        "flink_version": cluster_row.flink_version,
        "hadoop_version": cluster_row.hadoop_version,
        "provider_id": cluster_row.provider_id,
        "application_id": cluster_row.application_id,
        "yarn_queue": cluster_row.yarn_queue,
        "task_slots_per_taskmanager": cluster_row.task_slots_per_taskmanager,
        "parallelism": cluster_row.parallelism,
        "checkpointing_enabled": cluster_row.checkpointing_enabled,
        "checkpoint_interval_seconds": cluster_row.checkpoint_interval_seconds,
        "state_backend": cluster_row.state_backend,
        "state_checkpoint_dir": cluster_row.state_checkpoint_dir,
        "log_s3_path": cluster_row.log_s3_path,
        "flink_config": cluster_row.flink_config or {},
        "tags": cluster_row.tags or {},
        "state": cluster_row.state,
        "state_message": getattr(cluster_row, "state_message", ""),
        "jobmanager_endpoint": getattr(cluster_row, "jobmanager_endpoint", None),
        "web_ui_endpoint": getattr(cluster_row, "web_ui_endpoint", None),
        "provider_cluster_id": getattr(cluster_row, "provider_cluster_id", None),
        "created_at": cluster_row.created_at.isoformat()
        if hasattr(cluster_row.created_at, "isoformat")
        else cluster_row.created_at,
        "updated_at": cluster_row.updated_at.isoformat()
        if hasattr(cluster_row.updated_at, "isoformat")
        else cluster_row.updated_at,
    }
