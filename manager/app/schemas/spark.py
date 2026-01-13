"""Pydantic schemas for Apache Spark cluster management."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BigDataEngineType,
    ClusterMode,
    ClusterState,
)


class SparkClusterCreate(BaseModel):
    """Schema for creating a new Spark cluster."""

    name: str = Field(..., min_length=1, max_length=255, description="Cluster name")
    engine_type: BigDataEngineType = Field(
        BigDataEngineType.SPARK_BATCH,
        description="Spark engine type (batch or streaming)",
    )
    cluster_mode: ClusterMode = Field(
        ClusterMode.STANDALONE, description="Cluster deployment mode"
    )
    master_nodes: int = Field(1, ge=1, le=3, description="Number of master nodes")
    worker_nodes: int = Field(..., ge=1, description="Number of worker nodes")
    worker_instance_type: str = Field(
        ..., min_length=1, description="Worker node instance type"
    )
    master_instance_type: Optional[str] = Field(
        None, description="Master node instance type"
    )
    memory_per_node_gb: int = Field(..., gt=0, description="Memory per node in GB")
    cores_per_node: int = Field(..., gt=0, description="CPU cores per node")
    spark_version: str = Field(..., description="Spark version")
    hadoop_version: Optional[str] = Field(None, description="Hadoop version")
    provider_id: str = Field(..., min_length=1, description="Provider ID")
    application_id: Optional[str] = Field(None, description="Associated application ID")
    yarn_queue: Optional[str] = Field(None, description="YARN queue name")
    enable_dynamic_allocation: bool = Field(
        True, description="Enable dynamic resource allocation"
    )
    min_executors: Optional[int] = Field(None, ge=1, description="Minimum executors")
    max_executors: Optional[int] = Field(None, ge=1, description="Maximum executors")
    executor_memory_gb: Optional[int] = Field(
        None, gt=0, description="Executor memory in GB"
    )
    executor_cores: Optional[int] = Field(None, gt=0, description="Executor cores")
    driver_memory_gb: Optional[int] = Field(
        None, gt=0, description="Driver memory in GB"
    )
    driver_cores: Optional[int] = Field(None, gt=0, description="Driver cores")
    log_s3_path: Optional[str] = Field(
        None, description="S3 path for cluster logs (EMR)"
    )
    bootstrap_scripts: List[str] = Field(
        default_factory=list, description="Bootstrap script paths"
    )
    spark_config: Dict[str, str] = Field(
        default_factory=dict, description="Spark configuration overrides"
    )
    hive_metastore_enabled: bool = Field(
        False, description="Enable Hive metastore"
    )
    tags: Dict[str, str] = Field(default_factory=dict, description="Cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class SparkClusterUpdate(BaseModel):
    """Schema for updating Spark cluster configuration."""

    worker_nodes: Optional[int] = Field(None, ge=1, description="New worker node count")
    memory_per_node_gb: Optional[int] = Field(
        None, gt=0, description="New memory per node"
    )
    cores_per_node: Optional[int] = Field(
        None, gt=0, description="New cores per node"
    )
    enable_dynamic_allocation: Optional[bool] = Field(
        None, description="Update dynamic allocation setting"
    )
    min_executors: Optional[int] = Field(None, ge=1, description="New min executors")
    max_executors: Optional[int] = Field(None, ge=1, description="New max executors")
    executor_memory_gb: Optional[int] = Field(
        None, gt=0, description="New executor memory"
    )
    executor_cores: Optional[int] = Field(None, gt=0, description="New executor cores")
    spark_config: Optional[Dict[str, str]] = Field(
        None, description="Updated Spark configuration"
    )
    tags: Optional[Dict[str, str]] = Field(None, description="Updated cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class SparkClusterResponse(BaseModel):
    """Complete Spark cluster information response."""

    id: str = Field(..., description="Cluster ID")
    name: str = Field(..., description="Cluster name")
    engine_type: BigDataEngineType = Field(..., description="Spark engine type")
    cluster_mode: ClusterMode = Field(..., description="Deployment mode")
    master_nodes: int = Field(..., ge=1, description="Number of master nodes")
    worker_nodes: int = Field(..., ge=1, description="Number of worker nodes")
    worker_instance_type: str = Field(..., description="Worker instance type")
    master_instance_type: Optional[str] = Field(None, description="Master instance type")
    memory_per_node_gb: int = Field(..., gt=0, description="Memory per node")
    cores_per_node: int = Field(..., gt=0, description="Cores per node")
    spark_version: str = Field(..., description="Spark version")
    hadoop_version: Optional[str] = Field(None, description="Hadoop version")
    provider_id: str = Field(..., description="Provider ID")
    application_id: Optional[str] = Field(None, description="Application ID")
    yarn_queue: Optional[str] = Field(None, description="YARN queue")
    enable_dynamic_allocation: bool = Field(..., description="Dynamic allocation enabled")
    min_executors: Optional[int] = Field(None, description="Minimum executors")
    max_executors: Optional[int] = Field(None, description="Maximum executors")
    executor_memory_gb: Optional[int] = Field(None, description="Executor memory")
    executor_cores: Optional[int] = Field(None, description="Executor cores")
    driver_memory_gb: Optional[int] = Field(None, description="Driver memory")
    driver_cores: Optional[int] = Field(None, description="Driver cores")
    log_s3_path: Optional[str] = Field(None, description="S3 logs path")
    bootstrap_scripts: List[str] = Field(..., description="Bootstrap scripts")
    spark_config: Dict[str, str] = Field(..., description="Spark configuration")
    hive_metastore_enabled: bool = Field(..., description="Hive metastore enabled")
    tags: Dict[str, str] = Field(..., description="Cluster tags")
    state: ClusterState = Field(..., description="Cluster state")
    state_message: str = Field(..., description="Cluster state details")
    master_endpoint: Optional[str] = Field(None, description="Master endpoint URL")
    application_endpoint: Optional[str] = Field(None, description="Spark UI endpoint")
    provider_cluster_id: Optional[str] = Field(None, description="Provider cluster ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class SparkClusterListResponse(BaseModel):
    """Paginated list of Spark clusters."""

    clusters: List[SparkClusterResponse] = Field(..., description="List of clusters")
    total: int = Field(..., ge=0, description="Total cluster count")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether next page exists")
    has_previous: bool = Field(..., description="Whether previous page exists")


class SparkClusterScaleRequest(BaseModel):
    """Request to scale a Spark cluster."""

    worker_nodes: Optional[int] = Field(None, ge=1, description="New worker node count")
    memory_per_node_gb: Optional[int] = Field(
        None, gt=0, description="New memory per node"
    )
    cores_per_node: Optional[int] = Field(
        None, gt=0, description="New cores per node"
    )

    model_config = ConfigDict(use_enum_values=True)


class SparkJobMetricsResponse(BaseModel):
    """Spark job metrics and performance data."""

    job_id: str = Field(..., description="Job ID")
    task_count: int = Field(..., ge=0, description="Total tasks")
    completed_tasks: int = Field(..., ge=0, description="Completed tasks")
    failed_tasks: int = Field(..., ge=0, description="Failed tasks")
    duration_seconds: float = Field(..., ge=0, description="Job duration in seconds")
    input_bytes: int = Field(..., ge=0, description="Input data bytes")
    output_bytes: int = Field(..., ge=0, description="Output data bytes")
    shuffle_bytes: int = Field(..., ge=0, description="Shuffle data bytes")

    model_config = ConfigDict(from_attributes=True)
