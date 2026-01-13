"""Pydantic schemas for Hadoop HDFS cluster management."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BigDataEngineType,
    ClusterMode,
    ClusterState,
)


class HDFSClusterCreate(BaseModel):
    """Schema for creating a new HDFS cluster."""

    name: str = Field(..., min_length=1, max_length=255, description="Cluster name")
    engine_type: BigDataEngineType = Field(
        BigDataEngineType.HADOOP_HDFS, description="Engine type"
    )
    cluster_mode: ClusterMode = Field(
        ClusterMode.STANDALONE, description="Cluster deployment mode"
    )
    namenode_count: int = Field(1, ge=1, le=3, description="Number of NameNodes")
    datanode_count: int = Field(..., ge=1, description="Number of DataNodes")
    datanode_instance_type: str = Field(
        ..., min_length=1, description="DataNode instance type"
    )
    namenode_instance_type: Optional[str] = Field(
        None, description="NameNode instance type"
    )
    disk_size_gb_per_datanode: int = Field(
        ..., gt=0, description="Disk size per DataNode in GB"
    )
    replication_factor: int = Field(
        default=3, ge=1, le=10, description="Default replication factor"
    )
    block_size_mb: int = Field(
        default=128, gt=0, description="Block size in MB"
    )
    hadoop_version: str = Field(..., description="Hadoop version")
    java_version: Optional[str] = Field(None, description="Java version")
    provider_id: str = Field(..., min_length=1, description="Provider ID")
    application_id: Optional[str] = Field(None, description="Associated application ID")
    namenode_port: int = Field(
        default=9000, ge=1, le=65535, description="NameNode RPC port"
    )
    webhdfs_port: int = Field(
        default=50070, ge=1, le=65535, description="WebHDFS port"
    )
    datanode_port: int = Field(
        default=50010, ge=1, le=65535, description="DataNode port"
    )
    secondary_namenode_enabled: bool = Field(
        True, description="Enable Secondary NameNode"
    )
    ha_enabled: bool = Field(False, description="Enable High Availability (HA)")
    ha_zookeeper_quorum: Optional[str] = Field(
        None, description="ZooKeeper quorum for HA"
    )
    ha_automatic_failover: bool = Field(
        False, description="Enable automatic failover"
    )
    rack_awareness_enabled: bool = Field(True, description="Enable rack awareness")
    dfs_namenode_safemode_threshold_pct: float = Field(
        default=0.999, ge=0, le=1, description="Safe mode threshold"
    )
    dfs_rebalance_blockpinning_enabled: bool = Field(
        False, description="Enable block pinning for balancing"
    )
    hdfs_config: Dict[str, str] = Field(
        default_factory=dict, description="HDFS configuration overrides"
    )
    tags: Dict[str, str] = Field(default_factory=dict, description="Cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class HDFSClusterUpdate(BaseModel):
    """Schema for updating HDFS cluster configuration."""

    datanode_count: Optional[int] = Field(None, ge=1, description="New DataNode count")
    disk_size_gb_per_datanode: Optional[int] = Field(
        None, gt=0, description="New disk size per DataNode"
    )
    replication_factor: Optional[int] = Field(
        None, ge=1, le=10, description="New replication factor"
    )
    block_size_mb: Optional[int] = Field(None, gt=0, description="New block size")
    secondary_namenode_enabled: Optional[bool] = Field(
        None, description="Update secondary NameNode setting"
    )
    rack_awareness_enabled: Optional[bool] = Field(
        None, description="Update rack awareness"
    )
    dfs_namenode_safemode_threshold_pct: Optional[float] = Field(
        None, ge=0, le=1, description="New safe mode threshold"
    )
    hdfs_config: Optional[Dict[str, str]] = Field(
        None, description="Updated HDFS configuration"
    )
    tags: Optional[Dict[str, str]] = Field(None, description="Updated cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class HDFSClusterResponse(BaseModel):
    """Complete HDFS cluster information response."""

    id: str = Field(..., description="Cluster ID")
    name: str = Field(..., description="Cluster name")
    engine_type: BigDataEngineType = Field(..., description="Engine type")
    cluster_mode: ClusterMode = Field(..., description="Deployment mode")
    namenode_count: int = Field(..., ge=1, description="Number of NameNodes")
    datanode_count: int = Field(..., ge=1, description="Number of DataNodes")
    datanode_instance_type: str = Field(..., description="DataNode instance type")
    namenode_instance_type: Optional[str] = Field(None, description="NameNode type")
    disk_size_gb_per_datanode: int = Field(..., gt=0, description="Disk per DataNode")
    replication_factor: int = Field(..., ge=1, le=10, description="Replication factor")
    block_size_mb: int = Field(..., gt=0, description="Block size in MB")
    hadoop_version: str = Field(..., description="Hadoop version")
    java_version: Optional[str] = Field(None, description="Java version")
    provider_id: str = Field(..., description="Provider ID")
    application_id: Optional[str] = Field(None, description="Application ID")
    namenode_port: int = Field(..., ge=1, le=65535, description="NameNode RPC port")
    webhdfs_port: int = Field(..., ge=1, le=65535, description="WebHDFS port")
    datanode_port: int = Field(..., ge=1, le=65535, description="DataNode port")
    secondary_namenode_enabled: bool = Field(..., description="Secondary NameNode")
    ha_enabled: bool = Field(..., description="HA enabled")
    ha_zookeeper_quorum: Optional[str] = Field(None, description="ZooKeeper quorum")
    ha_automatic_failover: bool = Field(..., description="Automatic failover")
    rack_awareness_enabled: bool = Field(..., description="Rack awareness")
    dfs_namenode_safemode_threshold_pct: float = Field(
        ..., ge=0, le=1, description="Safe mode threshold"
    )
    dfs_rebalance_blockpinning_enabled: bool = Field(
        ..., description="Block pinning enabled"
    )
    hdfs_config: Dict[str, str] = Field(..., description="HDFS configuration")
    tags: Dict[str, str] = Field(..., description="Cluster tags")
    state: ClusterState = Field(..., description="Cluster state")
    state_message: str = Field(..., description="Cluster state details")
    namenode_endpoint: Optional[str] = Field(None, description="NameNode endpoint")
    webhdfs_endpoint: Optional[str] = Field(None, description="WebHDFS endpoint")
    total_storage_gb: Optional[int] = Field(None, description="Total cluster storage")
    used_storage_gb: Optional[int] = Field(None, description="Used cluster storage")
    available_storage_gb: Optional[int] = Field(None, description="Available storage")
    provider_cluster_id: Optional[str] = Field(None, description="Provider cluster ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class HDFSClusterListResponse(BaseModel):
    """Paginated list of HDFS clusters."""

    clusters: List[HDFSClusterResponse] = Field(..., description="List of clusters")
    total: int = Field(..., ge=0, description="Total cluster count")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether next page exists")
    has_previous: bool = Field(..., description="Whether previous page exists")


class HDFSClusterScaleRequest(BaseModel):
    """Request to scale an HDFS cluster."""

    datanode_count: Optional[int] = Field(None, ge=1, description="New DataNode count")
    disk_size_gb_per_datanode: Optional[int] = Field(
        None, gt=0, description="New disk size per DataNode"
    )

    model_config = ConfigDict(use_enum_values=True)


class HDFSHealthResponse(BaseModel):
    """HDFS cluster health and storage metrics."""

    cluster_id: str = Field(..., description="Cluster ID")
    live_datanodes: int = Field(..., ge=0, description="Live DataNodes")
    dead_datanodes: int = Field(..., ge=0, description="Dead DataNodes")
    total_blocks: int = Field(..., ge=0, description="Total blocks")
    corrupted_blocks: int = Field(..., ge=0, description="Corrupted blocks")
    missing_blocks: int = Field(..., ge=0, description="Missing blocks")
    under_replicated_blocks: int = Field(..., ge=0, description="Under-replicated blocks")
    total_storage_gb: int = Field(..., ge=0, description="Total storage in GB")
    used_storage_gb: int = Field(..., ge=0, description="Used storage in GB")
    available_storage_gb: int = Field(..., ge=0, description="Available storage in GB")
    namenode_safemode: bool = Field(..., description="NameNode in safe mode")
    namenode_uptime_seconds: float = Field(..., ge=0, description="NameNode uptime")

    model_config = ConfigDict(from_attributes=True)
