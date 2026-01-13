"""Pydantic schemas for Apache Flink cluster management."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BigDataEngineType,
    ClusterMode,
    ClusterState,
)


class FlinkClusterCreate(BaseModel):
    """Schema for creating a new Flink cluster."""

    name: str = Field(..., min_length=1, max_length=255, description="Cluster name")
    engine_type: BigDataEngineType = Field(
        BigDataEngineType.FLINK_STREAMING,
        description="Flink engine type (batch or streaming)",
    )
    cluster_mode: ClusterMode = Field(
        ClusterMode.YARN, description="Cluster deployment mode"
    )
    jobmanager_nodes: int = Field(1, ge=1, le=3, description="Number of JobManager nodes")
    taskmanager_nodes: int = Field(
        ..., ge=1, description="Number of TaskManager nodes"
    )
    taskmanager_instance_type: str = Field(
        ..., min_length=1, description="TaskManager instance type"
    )
    jobmanager_instance_type: Optional[str] = Field(
        None, description="JobManager instance type"
    )
    memory_per_taskmanager_gb: int = Field(
        ..., gt=0, description="Memory per TaskManager in GB"
    )
    cpu_per_taskmanager: int = Field(
        ..., gt=0, description="CPU cores per TaskManager"
    )
    jobmanager_memory_gb: Optional[int] = Field(
        None, gt=0, description="JobManager memory in GB"
    )
    flink_version: str = Field(..., description="Flink version")
    hadoop_version: Optional[str] = Field(None, description="Hadoop version")
    provider_id: str = Field(..., min_length=1, description="Provider ID")
    application_id: Optional[str] = Field(None, description="Associated application ID")
    yarn_queue: Optional[str] = Field(None, description="YARN queue name")
    task_slots_per_taskmanager: int = Field(
        default=4, ge=1, description="Task slots per TaskManager"
    )
    parallelism: Optional[int] = Field(None, ge=1, description="Default parallelism")
    checkpointing_enabled: bool = Field(
        True, description="Enable checkpointing for fault tolerance"
    )
    checkpoint_interval_seconds: Optional[int] = Field(
        None, gt=0, description="Checkpoint interval in seconds"
    )
    state_backend: Optional[str] = Field(
        None, description="State backend (rocksdb, filesystem)"
    )
    state_checkpoint_dir: Optional[str] = Field(
        None, description="Checkpoint storage directory"
    )
    log_s3_path: Optional[str] = Field(
        None, description="S3 path for cluster logs"
    )
    flink_config: Dict[str, str] = Field(
        default_factory=dict, description="Flink configuration overrides"
    )
    tags: Dict[str, str] = Field(default_factory=dict, description="Cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class FlinkClusterUpdate(BaseModel):
    """Schema for updating Flink cluster configuration."""

    taskmanager_nodes: Optional[int] = Field(
        None, ge=1, description="New TaskManager count"
    )
    memory_per_taskmanager_gb: Optional[int] = Field(
        None, gt=0, description="New TaskManager memory"
    )
    cpu_per_taskmanager: Optional[int] = Field(
        None, gt=0, description="New CPU per TaskManager"
    )
    task_slots_per_taskmanager: Optional[int] = Field(
        None, ge=1, description="New task slots"
    )
    parallelism: Optional[int] = Field(None, ge=1, description="New default parallelism")
    checkpointing_enabled: Optional[bool] = Field(
        None, description="Update checkpointing"
    )
    checkpoint_interval_seconds: Optional[int] = Field(
        None, gt=0, description="New checkpoint interval"
    )
    state_backend: Optional[str] = Field(None, description="New state backend")
    flink_config: Optional[Dict[str, str]] = Field(
        None, description="Updated Flink configuration"
    )
    tags: Optional[Dict[str, str]] = Field(None, description="Updated cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class FlinkClusterResponse(BaseModel):
    """Complete Flink cluster information response."""

    id: str = Field(..., description="Cluster ID")
    name: str = Field(..., description="Cluster name")
    engine_type: BigDataEngineType = Field(..., description="Flink engine type")
    cluster_mode: ClusterMode = Field(..., description="Deployment mode")
    jobmanager_nodes: int = Field(..., ge=1, description="Number of JobManager nodes")
    taskmanager_nodes: int = Field(..., ge=1, description="Number of TaskManager nodes")
    taskmanager_instance_type: str = Field(..., description="TaskManager instance type")
    jobmanager_instance_type: Optional[str] = Field(
        None, description="JobManager instance type"
    )
    memory_per_taskmanager_gb: int = Field(..., gt=0, description="TaskManager memory")
    cpu_per_taskmanager: int = Field(..., gt=0, description="TaskManager CPU cores")
    jobmanager_memory_gb: Optional[int] = Field(None, description="JobManager memory")
    flink_version: str = Field(..., description="Flink version")
    hadoop_version: Optional[str] = Field(None, description="Hadoop version")
    provider_id: str = Field(..., description="Provider ID")
    application_id: Optional[str] = Field(None, description="Application ID")
    yarn_queue: Optional[str] = Field(None, description="YARN queue")
    task_slots_per_taskmanager: int = Field(..., description="Task slots per TaskManager")
    parallelism: Optional[int] = Field(None, description="Default parallelism")
    checkpointing_enabled: bool = Field(..., description="Checkpointing enabled")
    checkpoint_interval_seconds: Optional[int] = Field(
        None, description="Checkpoint interval"
    )
    state_backend: Optional[str] = Field(None, description="State backend type")
    state_checkpoint_dir: Optional[str] = Field(None, description="Checkpoint directory")
    log_s3_path: Optional[str] = Field(None, description="S3 logs path")
    flink_config: Dict[str, str] = Field(..., description="Flink configuration")
    tags: Dict[str, str] = Field(..., description="Cluster tags")
    state: ClusterState = Field(..., description="Cluster state")
    state_message: str = Field(..., description="Cluster state details")
    jobmanager_endpoint: Optional[str] = Field(
        None, description="JobManager endpoint URL"
    )
    taskmanager_endpoints: List[str] = Field(
        default_factory=list, description="TaskManager endpoint URLs"
    )
    web_ui_endpoint: Optional[str] = Field(None, description="Web UI endpoint")
    provider_cluster_id: Optional[str] = Field(None, description="Provider cluster ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class FlinkClusterListResponse(BaseModel):
    """Paginated list of Flink clusters."""

    clusters: List[FlinkClusterResponse] = Field(..., description="List of clusters")
    total: int = Field(..., ge=0, description="Total cluster count")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether next page exists")
    has_previous: bool = Field(..., description="Whether previous page exists")


class FlinkClusterScaleRequest(BaseModel):
    """Request to scale a Flink cluster."""

    taskmanager_nodes: Optional[int] = Field(
        None, ge=1, description="New TaskManager count"
    )
    memory_per_taskmanager_gb: Optional[int] = Field(
        None, gt=0, description="New TaskManager memory"
    )
    cpu_per_taskmanager: Optional[int] = Field(
        None, gt=0, description="New CPU per TaskManager"
    )

    model_config = ConfigDict(use_enum_values=True)


class FlinkJobMetricsResponse(BaseModel):
    """Flink job metrics and performance data."""

    job_id: str = Field(..., description="Job ID")
    parallelism: int = Field(..., ge=1, description="Job parallelism")
    uptime_seconds: float = Field(..., ge=0, description="Job uptime in seconds")
    records_received_rate: float = Field(
        ..., ge=0, description="Records received per second"
    )
    records_emitted_rate: float = Field(
        ..., ge=0, description="Records emitted per second"
    )
    backpressure_high_percent: float = Field(
        ..., ge=0, le=100, description="High backpressure percentage"
    )
    checkpoint_count: int = Field(..., ge=0, description="Completed checkpoints")
    last_checkpoint_duration_seconds: Optional[float] = Field(
        None, ge=0, description="Last checkpoint duration"
    )

    model_config = ConfigDict(from_attributes=True)
