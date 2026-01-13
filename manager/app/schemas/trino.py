"""Pydantic schemas for Trino query engine management."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BigDataEngineType,
    ClusterMode,
    ClusterState,
    TrinoCatalogConnector,
)


class TrinoCatalogCreate(BaseModel):
    """Schema for creating a Trino catalog connector."""

    name: str = Field(..., min_length=1, max_length=255, description="Catalog name")
    connector_type: TrinoCatalogConnector = Field(
        ..., description="Catalog connector type"
    )
    connector_properties: Dict[str, str] = Field(
        ..., description="Connector-specific properties"
    )
    description: Optional[str] = Field(None, description="Catalog description")

    model_config = ConfigDict(use_enum_values=True)


class TrinoCatalogUpdate(BaseModel):
    """Schema for updating Trino catalog configuration."""

    connector_properties: Optional[Dict[str, str]] = Field(
        None, description="Updated connector properties"
    )
    description: Optional[str] = Field(None, description="Updated description")

    model_config = ConfigDict(use_enum_values=True)


class TrinoCatalogResponse(BaseModel):
    """Complete Trino catalog information."""

    id: str = Field(..., description="Catalog ID")
    name: str = Field(..., description="Catalog name")
    connector_type: TrinoCatalogConnector = Field(..., description="Connector type")
    connector_properties: Dict[str, str] = Field(..., description="Connector properties")
    description: Optional[str] = Field(None, description="Catalog description")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class TrinoClusterCreate(BaseModel):
    """Schema for creating a new Trino cluster."""

    name: str = Field(..., min_length=1, max_length=255, description="Cluster name")
    engine_type: BigDataEngineType = Field(
        BigDataEngineType.TRINO, description="Engine type"
    )
    cluster_mode: ClusterMode = Field(
        ClusterMode.STANDALONE, description="Cluster deployment mode"
    )
    coordinator_nodes: int = Field(1, ge=1, le=3, description="Number of coordinators")
    worker_nodes: int = Field(..., ge=0, description="Number of worker nodes")
    worker_instance_type: str = Field(
        ..., min_length=1, description="Worker instance type"
    )
    coordinator_instance_type: Optional[str] = Field(
        None, description="Coordinator instance type"
    )
    memory_per_node_gb: int = Field(..., gt=0, description="Memory per node in GB")
    cores_per_node: int = Field(..., gt=0, description="CPU cores per node")
    trino_version: str = Field(..., description="Trino version")
    provider_id: str = Field(..., min_length=1, description="Provider ID")
    application_id: Optional[str] = Field(None, description="Associated application ID")
    catalogs: List[TrinoCatalogCreate] = Field(
        default_factory=list, description="Catalog configurations"
    )
    discovery_uri: Optional[str] = Field(
        None, description="Catalog discovery URI (Hive metastore)"
    )
    http_port: int = Field(
        default=8080, ge=1, le=65535, description="HTTP server port"
    )
    https_enabled: bool = Field(False, description="Enable HTTPS")
    https_port: int = Field(
        default=8443, ge=1, le=65535, description="HTTPS server port"
    )
    query_max_memory_gb: Optional[int] = Field(
        None, gt=0, description="Max memory per query"
    )
    query_queue_max_wait_minutes: Optional[int] = Field(
        None, gt=0, description="Max query queue wait time"
    )
    exchange_manager_type: Optional[str] = Field(
        None, description="Exchange manager type (local, s3, gcs)"
    )
    spill_enabled: bool = Field(True, description="Enable spilling to disk")
    spill_order_by_enabled: bool = Field(True, description="Enable spill for ORDER BY")
    spill_join_enabled: bool = Field(True, description="Enable spill for JOIN")
    jvm_heap_memory_gb: Optional[int] = Field(
        None, gt=0, description="JVM heap memory in GB"
    )
    trino_config: Dict[str, str] = Field(
        default_factory=dict, description="Trino configuration overrides"
    )
    tags: Dict[str, str] = Field(default_factory=dict, description="Cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class TrinoClusterUpdate(BaseModel):
    """Schema for updating Trino cluster configuration."""

    worker_nodes: Optional[int] = Field(None, ge=0, description="New worker count")
    memory_per_node_gb: Optional[int] = Field(
        None, gt=0, description="New memory per node"
    )
    cores_per_node: Optional[int] = Field(
        None, gt=0, description="New cores per node"
    )
    catalogs: Optional[List[TrinoCatalogCreate]] = Field(
        None, description="Updated catalogs"
    )
    query_max_memory_gb: Optional[int] = Field(
        None, gt=0, description="New query memory limit"
    )
    query_queue_max_wait_minutes: Optional[int] = Field(
        None, gt=0, description="New query queue timeout"
    )
    spill_enabled: Optional[bool] = Field(None, description="Update spill setting")
    spill_order_by_enabled: Optional[bool] = Field(
        None, description="Update ORDER BY spill"
    )
    spill_join_enabled: Optional[bool] = Field(
        None, description="Update JOIN spill"
    )
    trino_config: Optional[Dict[str, str]] = Field(
        None, description="Updated Trino configuration"
    )
    tags: Optional[Dict[str, str]] = Field(None, description="Updated cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class TrinoClusterResponse(BaseModel):
    """Complete Trino cluster information response."""

    id: str = Field(..., description="Cluster ID")
    name: str = Field(..., description="Cluster name")
    engine_type: BigDataEngineType = Field(..., description="Engine type")
    cluster_mode: ClusterMode = Field(..., description="Deployment mode")
    coordinator_nodes: int = Field(..., ge=1, description="Number of coordinators")
    worker_nodes: int = Field(..., ge=0, description="Number of workers")
    worker_instance_type: str = Field(..., description="Worker instance type")
    coordinator_instance_type: Optional[str] = Field(None, description="Coordinator type")
    memory_per_node_gb: int = Field(..., gt=0, description="Memory per node")
    cores_per_node: int = Field(..., gt=0, description="Cores per node")
    trino_version: str = Field(..., description="Trino version")
    provider_id: str = Field(..., description="Provider ID")
    application_id: Optional[str] = Field(None, description="Application ID")
    catalogs: List[TrinoCatalogResponse] = Field(
        default_factory=list, description="Configured catalogs"
    )
    discovery_uri: Optional[str] = Field(None, description="Catalog discovery URI")
    http_port: int = Field(..., ge=1, le=65535, description="HTTP port")
    https_enabled: bool = Field(..., description="HTTPS enabled")
    https_port: int = Field(..., ge=1, le=65535, description="HTTPS port")
    query_max_memory_gb: Optional[int] = Field(None, description="Max query memory")
    query_queue_max_wait_minutes: Optional[int] = Field(None, description="Queue timeout")
    exchange_manager_type: Optional[str] = Field(None, description="Exchange manager")
    spill_enabled: bool = Field(..., description="Spilling enabled")
    spill_order_by_enabled: bool = Field(..., description="ORDER BY spill enabled")
    spill_join_enabled: bool = Field(..., description="JOIN spill enabled")
    jvm_heap_memory_gb: Optional[int] = Field(None, description="JVM heap memory")
    trino_config: Dict[str, str] = Field(..., description="Trino configuration")
    tags: Dict[str, str] = Field(..., description="Cluster tags")
    state: ClusterState = Field(..., description="Cluster state")
    state_message: str = Field(..., description="Cluster state details")
    coordinator_endpoint: Optional[str] = Field(None, description="Coordinator endpoint")
    web_ui_endpoint: Optional[str] = Field(None, description="Web UI endpoint")
    provider_cluster_id: Optional[str] = Field(None, description="Provider cluster ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class TrinoClusterListResponse(BaseModel):
    """Paginated list of Trino clusters."""

    clusters: List[TrinoClusterResponse] = Field(..., description="List of clusters")
    total: int = Field(..., ge=0, description="Total cluster count")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether next page exists")
    has_previous: bool = Field(..., description="Whether previous page exists")


class TrinoClusterScaleRequest(BaseModel):
    """Request to scale a Trino cluster."""

    worker_nodes: Optional[int] = Field(None, ge=0, description="New worker count")
    memory_per_node_gb: Optional[int] = Field(
        None, gt=0, description="New memory per node"
    )
    cores_per_node: Optional[int] = Field(
        None, gt=0, description="New cores per node"
    )

    model_config = ConfigDict(use_enum_values=True)


class TrinoQueryMetricsResponse(BaseModel):
    """Trino query metrics and performance data."""

    query_id: str = Field(..., description="Query ID")
    state: str = Field(..., description="Query state")
    user: str = Field(..., description="Query user")
    query_text: str = Field(..., description="Query text (truncated)")
    duration_seconds: float = Field(..., ge=0, description="Query duration")
    queued_time_seconds: float = Field(..., ge=0, description="Queued time")
    scheduled_time_seconds: float = Field(..., ge=0, description="Scheduled time")
    analysis_time_seconds: float = Field(..., ge=0, description="Analysis time")
    planning_time_seconds: float = Field(..., ge=0, description="Planning time")
    execution_time_seconds: float = Field(..., ge=0, description="Execution time")
    input_rows: int = Field(..., ge=0, description="Input rows")
    input_bytes: int = Field(..., ge=0, description="Input bytes")
    output_rows: int = Field(..., ge=0, description="Output rows")
    output_bytes: int = Field(..., ge=0, description="Output bytes")
    peak_memory_bytes: int = Field(..., ge=0, description="Peak memory usage")

    model_config = ConfigDict(from_attributes=True)
