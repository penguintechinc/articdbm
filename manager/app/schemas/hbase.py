"""Pydantic schemas for Apache HBase cluster management."""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BigDataEngineType,
    ClusterMode,
    ClusterState,
)


class HBaseTableCreate(BaseModel):
    """Schema for creating an HBase table."""

    name: str = Field(..., min_length=1, max_length=255, description="Table name")
    column_families: List[str] = Field(
        ..., min_items=1, description="Column family names"
    )
    max_filesize_mb: int = Field(
        default=1024, gt=0, description="Max region file size in MB"
    )
    region_split_count: int = Field(
        default=1, ge=1, description="Initial region split count"
    )
    compression_type: Optional[str] = Field(
        None, description="Compression type (snappy, lz4, gz)"
    )

    model_config = ConfigDict(use_enum_values=True)


class HBaseTableResponse(BaseModel):
    """HBase table information."""

    id: str = Field(..., description="Table ID")
    name: str = Field(..., description="Table name")
    column_families: List[str] = Field(..., description="Column families")
    max_filesize_mb: int = Field(..., gt=0, description="Max file size")
    region_split_count: int = Field(..., ge=1, description="Region count")
    compression_type: Optional[str] = Field(None, description="Compression type")
    enabled: bool = Field(..., description="Table enabled")
    created_at: datetime = Field(..., description="Creation timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class HBaseClusterCreate(BaseModel):
    """Schema for creating a new HBase cluster."""

    name: str = Field(..., min_length=1, max_length=255, description="Cluster name")
    engine_type: BigDataEngineType = Field(
        BigDataEngineType.HBASE, description="Engine type"
    )
    cluster_mode: ClusterMode = Field(
        ClusterMode.STANDALONE, description="Cluster deployment mode"
    )
    master_nodes: int = Field(1, ge=1, le=3, description="Number of HMasters")
    regionserver_nodes: int = Field(..., ge=1, description="Number of RegionServers")
    regionserver_instance_type: str = Field(
        ..., min_length=1, description="RegionServer instance type"
    )
    master_instance_type: Optional[str] = Field(
        None, description="HMaster instance type"
    )
    memory_per_regionserver_gb: int = Field(
        ..., gt=0, description="Memory per RegionServer in GB"
    )
    cores_per_regionserver: int = Field(
        ..., gt=0, description="CPU cores per RegionServer"
    )
    hbase_version: str = Field(..., description="HBase version")
    hadoop_version: Optional[str] = Field(None, description="Hadoop version")
    zookeeper_quorum: Optional[str] = Field(
        None, description="ZooKeeper quorum (external or embedded)"
    )
    provider_id: str = Field(..., min_length=1, description="Provider ID")
    application_id: Optional[str] = Field(None, description="Associated application ID")
    hmaster_port: int = Field(
        default=16000, ge=1, le=65535, description="HMaster port"
    )
    regionserver_port: int = Field(
        default=16020, ge=1, le=65535, description="RegionServer port"
    )
    write_ahead_log_enabled: bool = Field(True, description="Enable WAL (Write-Ahead Log)")
    log_replication_factor: int = Field(
        default=3, ge=1, le=10, description="WAL replication factor"
    )
    memstore_size_mb: int = Field(
        default=128, gt=0, description="MemStore size in MB"
    )
    blocksize_mb: int = Field(
        default=64, gt=0, description="Block size in MB"
    )
    compression_type: Optional[str] = Field(
        None, description="Default compression type"
    )
    bloom_filter_type: Optional[str] = Field(
        None, description="Bloom filter type (row, rowcol)"
    )
    auto_create_tables: bool = Field(
        False, description="Auto-create tables on first write"
    )
    table_definitions: List[HBaseTableCreate] = Field(
        default_factory=list, description="Pre-defined tables"
    )
    hbase_config: Dict[str, str] = Field(
        default_factory=dict, description="HBase configuration overrides"
    )
    tags: Dict[str, str] = Field(default_factory=dict, description="Cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class HBaseClusterUpdate(BaseModel):
    """Schema for updating HBase cluster configuration."""

    regionserver_nodes: Optional[int] = Field(
        None, ge=1, description="New RegionServer count"
    )
    memory_per_regionserver_gb: Optional[int] = Field(
        None, gt=0, description="New RegionServer memory"
    )
    cores_per_regionserver: Optional[int] = Field(
        None, gt=0, description="New RegionServer cores"
    )
    memstore_size_mb: Optional[int] = Field(
        None, gt=0, description="New MemStore size"
    )
    blocksize_mb: Optional[int] = Field(None, gt=0, description="New block size")
    compression_type: Optional[str] = Field(None, description="New compression type")
    bloom_filter_type: Optional[str] = Field(None, description="New bloom filter type")
    hbase_config: Optional[Dict[str, str]] = Field(
        None, description="Updated HBase configuration"
    )
    tags: Optional[Dict[str, str]] = Field(None, description="Updated cluster tags")

    model_config = ConfigDict(use_enum_values=True)


class HBaseClusterResponse(BaseModel):
    """Complete HBase cluster information response."""

    id: str = Field(..., description="Cluster ID")
    name: str = Field(..., description="Cluster name")
    engine_type: BigDataEngineType = Field(..., description="Engine type")
    cluster_mode: ClusterMode = Field(..., description="Deployment mode")
    master_nodes: int = Field(..., ge=1, description="Number of HMasters")
    regionserver_nodes: int = Field(..., ge=1, description="Number of RegionServers")
    regionserver_instance_type: str = Field(..., description="RegionServer type")
    master_instance_type: Optional[str] = Field(None, description="HMaster type")
    memory_per_regionserver_gb: int = Field(..., gt=0, description="RegionServer memory")
    cores_per_regionserver: int = Field(..., gt=0, description="RegionServer cores")
    hbase_version: str = Field(..., description="HBase version")
    hadoop_version: Optional[str] = Field(None, description="Hadoop version")
    zookeeper_quorum: Optional[str] = Field(None, description="ZooKeeper quorum")
    provider_id: str = Field(..., description="Provider ID")
    application_id: Optional[str] = Field(None, description="Application ID")
    hmaster_port: int = Field(..., ge=1, le=65535, description="HMaster port")
    regionserver_port: int = Field(..., ge=1, le=65535, description="RegionServer port")
    write_ahead_log_enabled: bool = Field(..., description="WAL enabled")
    log_replication_factor: int = Field(..., ge=1, le=10, description="WAL replication")
    memstore_size_mb: int = Field(..., gt=0, description="MemStore size")
    blocksize_mb: int = Field(..., gt=0, description="Block size in MB")
    compression_type: Optional[str] = Field(None, description="Compression type")
    bloom_filter_type: Optional[str] = Field(None, description="Bloom filter type")
    auto_create_tables: bool = Field(..., description="Auto-create tables")
    tables: List[HBaseTableResponse] = Field(
        default_factory=list, description="Cluster tables"
    )
    hbase_config: Dict[str, str] = Field(..., description="HBase configuration")
    tags: Dict[str, str] = Field(..., description="Cluster tags")
    state: ClusterState = Field(..., description="Cluster state")
    state_message: str = Field(..., description="Cluster state details")
    hmaster_endpoint: Optional[str] = Field(None, description="HMaster endpoint")
    regionserver_endpoints: List[str] = Field(
        default_factory=list, description="RegionServer endpoints"
    )
    provider_cluster_id: Optional[str] = Field(None, description="Provider cluster ID")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class HBaseClusterListResponse(BaseModel):
    """Paginated list of HBase clusters."""

    clusters: List[HBaseClusterResponse] = Field(..., description="List of clusters")
    total: int = Field(..., ge=0, description="Total cluster count")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether next page exists")
    has_previous: bool = Field(..., description="Whether previous page exists")


class HBaseClusterScaleRequest(BaseModel):
    """Request to scale an HBase cluster."""

    regionserver_nodes: Optional[int] = Field(
        None, ge=1, description="New RegionServer count"
    )
    memory_per_regionserver_gb: Optional[int] = Field(
        None, gt=0, description="New RegionServer memory"
    )
    cores_per_regionserver: Optional[int] = Field(
        None, gt=0, description="New RegionServer cores"
    )

    model_config = ConfigDict(use_enum_values=True)


class HBaseClusterHealthResponse(BaseModel):
    """HBase cluster health and performance metrics."""

    cluster_id: str = Field(..., description="Cluster ID")
    live_regionservers: int = Field(..., ge=0, description="Live RegionServers")
    dead_regionservers: int = Field(..., ge=0, description="Dead RegionServers")
    hmaster_alive: bool = Field(..., description="HMaster alive")
    average_load: float = Field(..., ge=0, description="Average cluster load")
    total_tables: int = Field(..., ge=0, description="Total tables")
    total_regions: int = Field(..., ge=0, description="Total regions")
    requests_per_second: float = Field(..., ge=0, description="Requests per second")
    zookeeper_quorum_status: Optional[str] = Field(
        None, description="ZooKeeper quorum health"
    )

    model_config = ConfigDict(from_attributes=True)
