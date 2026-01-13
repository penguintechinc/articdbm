"""ArticDBM Enumeration Types"""

from enum import Enum


class ResourceType(Enum):
    """Supported resource types"""
    # Traditional databases
    DATABASE = "database"
    CACHE = "cache"
    # Big Data - Processing
    SPARK = "spark"
    FLINK = "flink"
    # Big Data - Query Engines / Data Warehouses
    TRINO = "trino"
    BIGQUERY = "bigquery"
    # Big Data - Wide-column stores
    HBASE = "hbase"
    BIGTABLE = "bigtable"
    # Big Data - Storage layer (HDFS for compute, not object storage)
    HDFS = "hdfs"
    # Table Catalogs (metadata, references external storage managed by NEST)
    ICEBERG_CATALOG = "iceberg_catalog"


class EngineType(Enum):
    """Supported database and cache engines"""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    MSSQL = "mssql"
    MONGODB = "mongodb"
    REDIS = "redis"
    VALKEY = "valkey"
    MEMCACHED = "memcached"
    DOCUMENTDB = "documentdb"


class ProviderType(Enum):
    """Infrastructure providers"""
    KUBERNETES = "kubernetes"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    VULTR = "vultr"


class CredentialType(Enum):
    """Authentication credential types"""
    PASSWORD = "password"
    IAM_ROLE = "iam_role"
    JWT = "jwt"
    MTLS = "mtls"


class TLSMode(Enum):
    """TLS enforcement modes"""
    REQUIRED = "required"
    OPTIONAL = "optional"
    DISABLED = "disabled"


class ResourceStatus(Enum):
    """Resource provisioning and operational status"""
    PENDING = "pending"
    PROVISIONING = "provisioning"
    AVAILABLE = "available"
    MODIFYING = "modifying"
    DELETING = "deleting"
    DELETED = "deleted"
    FAILED = "failed"


class DeploymentModel(Enum):
    """Deployment model for resources"""
    SHARED = "shared"
    SEPARATE = "separate"


class LicenseTier(Enum):
    """License tier levels"""
    FREE = "free"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class SyncDirection(Enum):
    """Data synchronization direction"""
    PUSH = "push"
    PULL = "pull"
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(Enum):
    """Data synchronization status"""
    PENDING = "pending"
    SYNCED = "synced"
    ERROR = "error"


class BigDataEngineType(Enum):
    """Big data processing and query engines"""
    # HDFS (distributed filesystem for compute clusters)
    HADOOP_HDFS = "hadoop_hdfs"
    # Query engines / Data Warehouses
    TRINO = "trino"
    SPARK_SQL = "spark_sql"
    ATHENA = "athena"           # AWS serverless Trino
    BIGQUERY = "bigquery"       # GCP serverless data warehouse
    SYNAPSE = "synapse"         # Azure Synapse Analytics
    REDSHIFT = "redshift"       # AWS data warehouse
    SNOWFLAKE = "snowflake"     # Multi-cloud data warehouse (AWS/GCP/Azure)
    # Batch processing engines
    SPARK_BATCH = "spark_batch"
    SPARK_STREAMING = "spark_streaming"
    # Stream processing engines
    FLINK_BATCH = "flink_batch"
    FLINK_STREAMING = "flink_streaming"
    DATAFLOW = "dataflow"       # GCP managed Flink/Beam
    # Wide-column stores (NoSQL databases)
    HBASE = "hbase"
    BIGTABLE = "bigtable"       # GCP managed wide-column
    COSMOS_TABLE = "cosmos_table"  # Azure Cosmos DB Table API
    DYNAMODB = "dynamodb"       # AWS managed wide-column
    # Table formats (metadata catalogs - storage managed by NEST)
    ICEBERG = "iceberg"
    DELTA_LAKE = "delta_lake"
    HUDI = "hudi"


class ClusterState(Enum):
    """Big data cluster lifecycle states"""
    PENDING = "pending"
    CREATING = "creating"
    RUNNING = "running"
    SCALING = "scaling"
    STOPPED = "stopped"
    TERMINATING = "terminating"
    TERMINATED = "terminated"
    ERROR = "error"


class ClusterMode(Enum):
    """Spark cluster deployment modes"""
    STANDALONE = "standalone"
    YARN = "yarn"
    KUBERNETES = "kubernetes"
    MANAGED = "managed"  # Cloud-managed (EMR, Dataproc, etc.)


class JobState(Enum):
    """Spark/Flink job execution states"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobType(Enum):
    """Processing job types"""
    BATCH = "batch"
    STREAMING = "streaming"


class CatalogType(Enum):
    """Iceberg/table catalog types"""
    HIVE = "hive"
    GLUE = "glue"
    REST = "rest"
    JDBC = "jdbc"
    NESSIE = "nessie"


class TrinoCatalogConnector(Enum):
    """Trino catalog connector types"""
    HIVE = "hive"
    ICEBERG = "iceberg"
    DELTA_LAKE = "delta_lake"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MONGODB = "mongodb"
    ELASTICSEARCH = "elasticsearch"
    REDIS = "redis"
    KAFKA = "kafka"
    S3 = "s3"
    GCS = "gcs"


class StorageReferenceType(Enum):
    """Storage reference types for Iceberg catalogs (storage managed by NEST)"""
    S3 = "s3"
    GCS = "gcs"
    AZURE_BLOB = "azure_blob"
    HDFS = "hdfs"
