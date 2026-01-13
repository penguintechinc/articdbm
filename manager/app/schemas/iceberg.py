"""Pydantic schemas for Apache Iceberg table format and catalog management."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.enums import (
    BigDataEngineType,
    CatalogType,
)


class IcebergCatalogCreate(BaseModel):
    """Schema for creating a new Iceberg catalog."""

    name: str = Field(..., min_length=1, max_length=255, description="Catalog name")
    catalog_type: CatalogType = Field(..., description="Catalog type")
    warehouse_location: str = Field(
        ..., min_length=1, description="Warehouse path (S3, GCS, HDFS, etc.)"
    )
    description: Optional[str] = Field(None, description="Catalog description")
    # Hive metastore
    hive_metastore_uri: Optional[str] = Field(
        None, description="Hive metastore URI (thrift://host:port)"
    )
    # AWS Glue
    glue_catalog_id: Optional[str] = Field(
        None, description="AWS Glue catalog ID (for Glue catalog)"
    )
    glue_region: Optional[str] = Field(None, description="AWS Glue region")
    # REST catalog
    rest_catalog_uri: Optional[str] = Field(
        None, description="REST catalog server URI"
    )
    rest_catalog_auth_type: Optional[str] = Field(
        None, description="REST catalog auth type (basic, bearer, oauth2)"
    )
    rest_catalog_auth_token: Optional[str] = Field(
        None, description="REST catalog auth token"
    )
    rest_catalog_auth_config: Optional[Dict[str, str]] = Field(
        None, description="REST catalog auth configuration"
    )
    # JDBC catalog
    jdbc_driver_class: Optional[str] = Field(None, description="JDBC driver class")
    jdbc_connection_url: Optional[str] = Field(None, description="JDBC connection URL")
    jdbc_user: Optional[str] = Field(None, description="JDBC user")
    jdbc_password: Optional[str] = Field(None, description="JDBC password")
    # Nessie catalog
    nessie_server_uri: Optional[str] = Field(
        None, description="Nessie server URI"
    )
    nessie_auth_type: Optional[str] = Field(
        None, description="Nessie auth type"
    )
    nessie_auth_token: Optional[str] = Field(None, description="Nessie auth token")
    # Storage configuration
    storage_type: Optional[str] = Field(
        None, description="Storage type (s3, gcs, azure, hdfs)"
    )
    storage_endpoint: Optional[str] = Field(None, description="Storage endpoint")
    storage_access_key: Optional[str] = Field(None, description="Storage access key")
    storage_secret_key: Optional[str] = Field(None, description="Storage secret key")
    # Common settings
    io_impl: Optional[str] = Field(
        None, description="IO implementation class"
    )
    compression_codec: Optional[str] = Field(
        None, description="Compression codec (snappy, gzip, zstd)"
    )
    enable_statistics: bool = Field(True, description="Enable column statistics")
    enable_parquet_bloom_filter: bool = Field(
        False, description="Enable Parquet bloom filters"
    )
    enable_s3_access_grants: bool = Field(
        False, description="Enable S3 access grants (AWS)"
    )
    enable_manifest_caching: bool = Field(
        True, description="Enable manifest file caching"
    )
    manifest_cache_ttl_minutes: int = Field(
        default=30, gt=0, description="Manifest cache TTL in minutes"
    )
    tls_enabled: bool = Field(True, description="Enable TLS")
    tls_verify: bool = Field(True, description="Verify TLS certificates")
    tags: Dict[str, str] = Field(default_factory=dict, description="Catalog tags")

    model_config = ConfigDict(use_enum_values=True)


class IcebergCatalogUpdate(BaseModel):
    """Schema for updating Iceberg catalog configuration."""

    warehouse_location: Optional[str] = Field(None, description="New warehouse location")
    description: Optional[str] = Field(None, description="Updated description")
    storage_endpoint: Optional[str] = Field(None, description="New storage endpoint")
    compression_codec: Optional[str] = Field(None, description="New compression codec")
    enable_statistics: Optional[bool] = Field(None, description="Update statistics")
    enable_parquet_bloom_filter: Optional[bool] = Field(
        None, description="Update bloom filters"
    )
    enable_manifest_caching: Optional[bool] = Field(
        None, description="Update manifest caching"
    )
    manifest_cache_ttl_minutes: Optional[int] = Field(
        None, gt=0, description="New cache TTL"
    )
    tls_enabled: Optional[bool] = Field(None, description="Update TLS")
    tls_verify: Optional[bool] = Field(None, description="Update TLS verification")
    tags: Optional[Dict[str, str]] = Field(None, description="Updated catalog tags")

    model_config = ConfigDict(use_enum_values=True)


class IcebergCatalogResponse(BaseModel):
    """Complete Iceberg catalog information response."""

    id: str = Field(..., description="Catalog ID")
    name: str = Field(..., description="Catalog name")
    catalog_type: CatalogType = Field(..., description="Catalog type")
    warehouse_location: str = Field(..., description="Warehouse location")
    description: Optional[str] = Field(None, description="Catalog description")
    hive_metastore_uri: Optional[str] = Field(None, description="Hive metastore URI")
    glue_catalog_id: Optional[str] = Field(None, description="Glue catalog ID")
    glue_region: Optional[str] = Field(None, description="Glue region")
    rest_catalog_uri: Optional[str] = Field(None, description="REST catalog URI")
    rest_catalog_auth_type: Optional[str] = Field(None, description="REST auth type")
    jdbc_driver_class: Optional[str] = Field(None, description="JDBC driver")
    jdbc_connection_url: Optional[str] = Field(None, description="JDBC URL")
    nessie_server_uri: Optional[str] = Field(None, description="Nessie server URI")
    nessie_auth_type: Optional[str] = Field(None, description="Nessie auth type")
    storage_type: Optional[str] = Field(None, description="Storage type")
    storage_endpoint: Optional[str] = Field(None, description="Storage endpoint")
    io_impl: Optional[str] = Field(None, description="IO implementation")
    compression_codec: Optional[str] = Field(None, description="Compression codec")
    enable_statistics: bool = Field(..., description="Statistics enabled")
    enable_parquet_bloom_filter: bool = Field(..., description="Bloom filters enabled")
    enable_s3_access_grants: bool = Field(..., description="S3 access grants enabled")
    enable_manifest_caching: bool = Field(..., description="Manifest caching enabled")
    manifest_cache_ttl_minutes: int = Field(..., gt=0, description="Cache TTL")
    tls_enabled: bool = Field(..., description="TLS enabled")
    tls_verify: bool = Field(..., description="TLS verification enabled")
    tags: Dict[str, str] = Field(..., description="Catalog tags")
    status: str = Field(..., description="Catalog status")
    status_message: str = Field(..., description="Status details")
    table_count: int = Field(..., ge=0, description="Number of tables in catalog")
    namespace_count: int = Field(..., ge=0, description="Number of namespaces")
    last_metadata_update: Optional[datetime] = Field(
        None, description="Last metadata update"
    )
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class IcebergCatalogListResponse(BaseModel):
    """Paginated list of Iceberg catalogs."""

    catalogs: List[IcebergCatalogResponse] = Field(
        ..., description="List of catalogs"
    )
    total: int = Field(..., ge=0, description="Total catalog count")
    page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, description="Items per page")
    total_pages: int = Field(..., ge=0, description="Total number of pages")
    has_next: bool = Field(..., description="Whether next page exists")
    has_previous: bool = Field(..., description="Whether previous page exists")


class IcebergTablePartitionSpec(BaseModel):
    """Iceberg table partition specification."""

    source_column: str = Field(..., description="Source column name")
    partition_field: str = Field(..., description="Partition field name")
    transform_type: str = Field(
        ..., description="Transform type (identity, bucket, truncate, year, month, day, hour)"
    )
    transform_param: Optional[int] = Field(
        None, description="Transform parameter (bucket size, truncate length)"
    )

    model_config = ConfigDict(use_enum_values=True)


class IcebergTableCreate(BaseModel):
    """Schema for creating an Iceberg table."""

    namespace: str = Field(..., min_length=1, description="Namespace name")
    table_name: str = Field(..., min_length=1, description="Table name")
    schema_definition: str = Field(
        ..., description="Table schema in Avro/Parquet format (JSON)"
    )
    primary_keys: List[str] = Field(
        default_factory=list, description="Primary key columns"
    )
    partition_specs: List[IcebergTablePartitionSpec] = Field(
        default_factory=list, description="Partition specifications"
    )
    sort_order: Optional[List[str]] = Field(None, description="Sort order columns")
    file_format: Optional[str] = Field(
        default="parquet", description="File format (parquet, orc, avro)"
    )
    format_version: Optional[int] = Field(
        default=2, description="Iceberg format version (1 or 2)"
    )
    compression_codec: Optional[str] = Field(
        None, description="Compression codec"
    )

    model_config = ConfigDict(use_enum_values=True)


class IcebergTableResponse(BaseModel):
    """Iceberg table information."""

    id: str = Field(..., description="Table ID")
    namespace: str = Field(..., description="Namespace")
    table_name: str = Field(..., description="Table name")
    schema_definition: str = Field(..., description="Table schema")
    primary_keys: List[str] = Field(..., description="Primary keys")
    partition_specs: List[IcebergTablePartitionSpec] = Field(
        ..., description="Partition specs"
    )
    sort_order: Optional[List[str]] = Field(None, description="Sort order")
    file_format: str = Field(..., description="File format")
    format_version: int = Field(..., description="Format version")
    compression_codec: Optional[str] = Field(None, description="Compression codec")
    row_count: int = Field(..., ge=0, description="Number of rows")
    file_count: int = Field(..., ge=0, description="Number of data files")
    total_size_gb: float = Field(..., ge=0, description="Total size in GB")
    snapshot_count: int = Field(..., ge=0, description="Number of snapshots")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(use_enum_values=True, from_attributes=True)


class IcebergTableMetricsResponse(BaseModel):
    """Iceberg table metrics and statistics."""

    table_id: str = Field(..., description="Table ID")
    row_count: int = Field(..., ge=0, description="Total rows")
    file_count: int = Field(..., ge=0, description="Total files")
    total_size_gb: float = Field(..., ge=0, description="Total size in GB")
    snapshot_count: int = Field(..., ge=0, description="Total snapshots")
    latest_snapshot_id: str = Field(..., description="Latest snapshot ID")
    partition_count: int = Field(..., ge=0, description="Partition count")
    avg_record_size_bytes: float = Field(
        ..., ge=0, description="Average record size in bytes"
    )
    column_statistics: Optional[Dict[str, Dict[str, Any]]] = Field(
        None, description="Column-level statistics"
    )
    last_stats_update: Optional[datetime] = Field(
        None, description="Last statistics update"
    )

    model_config = ConfigDict(from_attributes=True)
