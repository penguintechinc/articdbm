"""
Base big data provisioner abstract class for distributed computing platforms.

This module defines the core interface that all big data provisioner
implementations must adhere to, ensuring consistent behavior across different
cloud providers and platforms for HDFS, Trino, Spark, Flink, and HBase.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class ClusterType(Enum):
    """Supported big data cluster types."""
    HDFS = "hdfs"
    TRINO = "trino"
    SPARK = "spark"
    FLINK = "flink"
    HBASE = "hbase"


class JobStatus(Enum):
    """Job execution status."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


class StorageBackendType(Enum):
    """Supported storage backend types."""
    S3 = "s3"
    GCS = "gcs"
    AZURE_BLOB = "azure_blob"
    HDFS = "hdfs"
    MINIO = "minio"


@dataclass
class BigDataProvisionerConfig:
    """
    Common configuration for all big data provisioners.

    Attributes:
        provider_type: Type of provider (kubernetes, aws, azure, gcp)
        credentials: Provider-specific credential dictionary
        region: Cloud region or cluster region
        timeout: Default timeout for operations in seconds
        retry_attempts: Number of retry attempts for failed operations
        dry_run: If True, simulate operations without executing
        tags: Default tags to apply to all resources
        storage_backend: Default storage backend configuration
    """
    provider_type: str
    credentials: Dict[str, Any] = field(default_factory=dict)
    region: Optional[str] = None
    timeout: int = 600
    retry_attempts: int = 3
    dry_run: bool = False
    tags: Dict[str, str] = field(default_factory=dict)
    storage_backend: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClusterConfig:
    """
    Configuration for big data cluster creation.

    Attributes:
        name: Cluster name (must be unique within provider)
        cluster_type: Type of cluster (hdfs, trino, spark, flink, hbase)
        master_count: Number of master/coordinator nodes
        worker_count: Number of worker/executor nodes
        master_instance_size: Instance size for master nodes
        worker_instance_size: Instance size for worker nodes
        storage_size_gb: Storage allocation per node in GB
        version: Software version to deploy
        network_config: Network configuration (VPC, subnet, security groups)
        storage_backend: Storage backend configuration
        high_availability: Enable HA configuration
        auto_scaling: Auto-scaling configuration
        labels: Resource labels/tags
        annotations: Provider-specific annotations
        custom_config: Cluster-specific custom configuration
    """
    name: str
    cluster_type: ClusterType
    master_count: int = 1
    worker_count: int = 2
    master_instance_size: str = 'medium'
    worker_instance_size: str = 'large'
    storage_size_gb: int = 100
    version: Optional[str] = None
    network_config: Dict[str, Any] = field(default_factory=dict)
    storage_backend: Dict[str, Any] = field(default_factory=dict)
    high_availability: bool = False
    auto_scaling: Dict[str, Any] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)
    custom_config: Dict[str, Any] = field(default_factory=dict)


@dataclass
class JobConfig:
    """
    Configuration for job submission (Spark/Flink).

    Attributes:
        job_name: Job name (must be unique)
        job_type: Type of job (spark, flink)
        main_class: Main class for Java/Scala jobs
        application_file: Path to application JAR or Python file
        arguments: Job arguments
        executor_count: Number of executors (Spark) or task managers (Flink)
        executor_cores: CPU cores per executor
        executor_memory_gb: Memory per executor in GB
        driver_memory_gb: Driver/JobManager memory in GB
        parallelism: Job parallelism level
        environment_variables: Environment variables for job
        dependencies: Additional dependencies (JARs, files)
        savepoint_path: Path to savepoint for Flink job recovery
        labels: Job labels/tags
        custom_config: Job-specific custom configuration
    """
    job_name: str
    job_type: str
    main_class: Optional[str] = None
    application_file: str = ""
    arguments: List[str] = field(default_factory=list)
    executor_count: int = 2
    executor_cores: int = 2
    executor_memory_gb: int = 4
    driver_memory_gb: int = 2
    parallelism: int = 1
    environment_variables: Dict[str, str] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    savepoint_path: Optional[str] = None
    labels: Dict[str, str] = field(default_factory=dict)
    custom_config: Dict[str, Any] = field(default_factory=dict)


class BigDataProvisionerException(Exception):
    """
    Base exception for big data provisioner errors.

    Attributes:
        message: Error message
        provider: Provider type where error occurred
        cluster_id: Cluster ID if applicable
        job_id: Job ID if applicable
        original_error: Original exception if wrapped
    """

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        cluster_id: Optional[str] = None,
        job_id: Optional[str] = None,
        original_error: Optional[Exception] = None
    ):
        self.message = message
        self.provider = provider
        self.cluster_id = cluster_id
        self.job_id = job_id
        self.original_error = original_error
        super().__init__(self.message)

    def __str__(self) -> str:
        parts = [self.message]
        if self.provider:
            parts.append(f"Provider: {self.provider}")
        if self.cluster_id:
            parts.append(f"Cluster: {self.cluster_id}")
        if self.job_id:
            parts.append(f"Job: {self.job_id}")
        if self.original_error:
            parts.append(f"Original error: {str(self.original_error)}")
        return " | ".join(parts)


class BaseBigDataProvisioner(ABC):
    """
    Abstract base class for big data platform provisioners.

    All big data provisioner implementations must inherit from this class and
    implement all abstract methods to ensure consistent behavior across
    HDFS, Trino, Spark, Flink, and HBase deployments.
    """

    def __init__(self, config: BigDataProvisionerConfig):
        """
        Initialize big data provisioner with configuration.

        Args:
            config: Big data provisioner configuration
        """
        self.config = config
        self._initialized = False

    # HDFS Cluster Management
    @abstractmethod
    async def create_hdfs_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """
        Create a new HDFS cluster.

        Args:
            cluster_config: Configuration for the HDFS cluster

        Returns:
            Dictionary containing:
                - cluster_id: Provider-specific cluster identifier
                - namenode_endpoint: NameNode endpoint
                - namenode_port: NameNode port
                - webhdfs_endpoint: WebHDFS endpoint
                - status: Current cluster status
                - created_at: Creation timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            BigDataProvisionerException: If cluster creation fails
        """
        pass

    @abstractmethod
    async def delete_hdfs_cluster(self, cluster_id: str) -> bool:
        """
        Delete an HDFS cluster.

        Args:
            cluster_id: Provider-specific cluster identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            BigDataProvisionerException: If cluster deletion fails
        """
        pass

    @abstractmethod
    async def scale_hdfs_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale an HDFS cluster (adjust DataNode count or storage).

        Args:
            cluster_id: Provider-specific cluster identifier
            scale_config: Scaling configuration containing:
                - worker_count: New DataNode count (optional)
                - storage_size_gb: New storage size per node (optional)

        Returns:
            Dictionary containing updated cluster state

        Raises:
            BigDataProvisionerException: If scaling operation fails
        """
        pass

    # Trino Cluster Management
    @abstractmethod
    async def create_trino_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """
        Create a new Trino cluster.

        Args:
            cluster_config: Configuration for the Trino cluster

        Returns:
            Dictionary containing:
                - cluster_id: Provider-specific cluster identifier
                - coordinator_endpoint: Coordinator endpoint
                - coordinator_port: Coordinator port
                - web_ui_endpoint: Web UI endpoint
                - status: Current cluster status
                - created_at: Creation timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            BigDataProvisionerException: If cluster creation fails
        """
        pass

    @abstractmethod
    async def delete_trino_cluster(self, cluster_id: str) -> bool:
        """
        Delete a Trino cluster.

        Args:
            cluster_id: Provider-specific cluster identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            BigDataProvisionerException: If cluster deletion fails
        """
        pass

    @abstractmethod
    async def scale_trino_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale a Trino cluster (adjust worker count or instance size).

        Args:
            cluster_id: Provider-specific cluster identifier
            scale_config: Scaling configuration containing:
                - worker_count: New worker count (optional)
                - worker_instance_size: New worker instance size (optional)

        Returns:
            Dictionary containing updated cluster state

        Raises:
            BigDataProvisionerException: If scaling operation fails
        """
        pass

    # Spark Cluster Management
    @abstractmethod
    async def create_spark_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """
        Create a new Spark cluster.

        Args:
            cluster_config: Configuration for the Spark cluster

        Returns:
            Dictionary containing:
                - cluster_id: Provider-specific cluster identifier
                - master_endpoint: Spark master endpoint
                - master_port: Spark master port
                - web_ui_endpoint: Web UI endpoint
                - status: Current cluster status
                - created_at: Creation timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            BigDataProvisionerException: If cluster creation fails
        """
        pass

    @abstractmethod
    async def delete_spark_cluster(self, cluster_id: str) -> bool:
        """
        Delete a Spark cluster.

        Args:
            cluster_id: Provider-specific cluster identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            BigDataProvisionerException: If cluster deletion fails
        """
        pass

    @abstractmethod
    async def scale_spark_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale a Spark cluster (adjust worker count or instance size).

        Args:
            cluster_id: Provider-specific cluster identifier
            scale_config: Scaling configuration containing:
                - worker_count: New worker count (optional)
                - worker_instance_size: New worker instance size (optional)

        Returns:
            Dictionary containing updated cluster state

        Raises:
            BigDataProvisionerException: If scaling operation fails
        """
        pass

    # Flink Cluster Management
    @abstractmethod
    async def create_flink_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """
        Create a new Flink cluster.

        Args:
            cluster_config: Configuration for the Flink cluster

        Returns:
            Dictionary containing:
                - cluster_id: Provider-specific cluster identifier
                - jobmanager_endpoint: JobManager endpoint
                - jobmanager_port: JobManager port
                - web_ui_endpoint: Web UI endpoint
                - status: Current cluster status
                - created_at: Creation timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            BigDataProvisionerException: If cluster creation fails
        """
        pass

    @abstractmethod
    async def delete_flink_cluster(self, cluster_id: str) -> bool:
        """
        Delete a Flink cluster.

        Args:
            cluster_id: Provider-specific cluster identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            BigDataProvisionerException: If cluster deletion fails
        """
        pass

    @abstractmethod
    async def scale_flink_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale a Flink cluster (adjust TaskManager count or slots).

        Args:
            cluster_id: Provider-specific cluster identifier
            scale_config: Scaling configuration containing:
                - worker_count: New TaskManager count (optional)
                - task_slots: New task slots per TaskManager (optional)

        Returns:
            Dictionary containing updated cluster state

        Raises:
            BigDataProvisionerException: If scaling operation fails
        """
        pass

    # HBase Cluster Management
    @abstractmethod
    async def create_hbase_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """
        Create a new HBase cluster.

        Args:
            cluster_config: Configuration for the HBase cluster

        Returns:
            Dictionary containing:
                - cluster_id: Provider-specific cluster identifier
                - master_endpoint: HMaster endpoint
                - master_port: HMaster port
                - zookeeper_quorum: ZooKeeper quorum endpoints
                - status: Current cluster status
                - created_at: Creation timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            BigDataProvisionerException: If cluster creation fails
        """
        pass

    @abstractmethod
    async def delete_hbase_cluster(self, cluster_id: str) -> bool:
        """
        Delete an HBase cluster.

        Args:
            cluster_id: Provider-specific cluster identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            BigDataProvisionerException: If cluster deletion fails
        """
        pass

    @abstractmethod
    async def scale_hbase_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale an HBase cluster (adjust RegionServer count).

        Args:
            cluster_id: Provider-specific cluster identifier
            scale_config: Scaling configuration containing:
                - worker_count: New RegionServer count (optional)

        Returns:
            Dictionary containing updated cluster state

        Raises:
            BigDataProvisionerException: If scaling operation fails
        """
        pass

    # Storage Backend Management
    @abstractmethod
    async def create_storage_backend(
        self,
        backend_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Create or configure a storage backend (S3, GCS, Azure Blob, MinIO).

        Args:
            backend_config: Storage backend configuration containing:
                - backend_type: Type of storage backend
                - bucket_name: Bucket/container name
                - region: Storage region
                - access_config: Access credentials configuration
                - lifecycle_policies: Data lifecycle policies (optional)

        Returns:
            Dictionary containing:
                - backend_id: Storage backend identifier
                - endpoint: Storage endpoint
                - bucket_name: Bucket/container name
                - access_key_id: Access key (if applicable)
                - created_at: Creation timestamp

        Raises:
            BigDataProvisionerException: If storage backend creation fails
        """
        pass

    @abstractmethod
    async def delete_storage_backend(self, backend_id: str) -> bool:
        """
        Delete a storage backend.

        Args:
            backend_id: Storage backend identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            BigDataProvisionerException: If storage backend deletion fails
        """
        pass

    # Spark Job Management
    @abstractmethod
    async def submit_spark_job(
        self,
        cluster_id: str,
        job_config: JobConfig
    ) -> Dict[str, Any]:
        """
        Submit a Spark job to a cluster.

        Args:
            cluster_id: Provider-specific cluster identifier
            job_config: Job configuration

        Returns:
            Dictionary containing:
                - job_id: Job identifier
                - cluster_id: Cluster identifier
                - status: Job status
                - submitted_at: Submission timestamp
                - metadata: Additional job metadata

        Raises:
            BigDataProvisionerException: If job submission fails
        """
        pass

    @abstractmethod
    async def get_spark_job_status(
        self,
        cluster_id: str,
        job_id: str
    ) -> Dict[str, Any]:
        """
        Get status of a Spark job.

        Args:
            cluster_id: Provider-specific cluster identifier
            job_id: Job identifier

        Returns:
            Dictionary containing:
                - job_id: Job identifier
                - status: Current job status
                - progress: Job progress percentage
                - started_at: Job start timestamp
                - completed_at: Job completion timestamp (if finished)
                - error_message: Error message (if failed)
                - metadata: Additional job metadata

        Raises:
            BigDataProvisionerException: If status retrieval fails
        """
        pass

    @abstractmethod
    async def kill_spark_job(
        self,
        cluster_id: str,
        job_id: str
    ) -> bool:
        """
        Kill a running Spark job.

        Args:
            cluster_id: Provider-specific cluster identifier
            job_id: Job identifier

        Returns:
            True if job killed successfully, False otherwise

        Raises:
            BigDataProvisionerException: If job termination fails
        """
        pass

    # Flink Job Management
    @abstractmethod
    async def submit_flink_job(
        self,
        cluster_id: str,
        job_config: JobConfig
    ) -> Dict[str, Any]:
        """
        Submit a Flink job to a cluster.

        Args:
            cluster_id: Provider-specific cluster identifier
            job_config: Job configuration

        Returns:
            Dictionary containing:
                - job_id: Job identifier
                - cluster_id: Cluster identifier
                - status: Job status
                - submitted_at: Submission timestamp
                - metadata: Additional job metadata

        Raises:
            BigDataProvisionerException: If job submission fails
        """
        pass

    @abstractmethod
    async def get_flink_job_status(
        self,
        cluster_id: str,
        job_id: str
    ) -> Dict[str, Any]:
        """
        Get status of a Flink job.

        Args:
            cluster_id: Provider-specific cluster identifier
            job_id: Job identifier

        Returns:
            Dictionary containing:
                - job_id: Job identifier
                - status: Current job status
                - started_at: Job start timestamp
                - completed_at: Job completion timestamp (if finished)
                - checkpoints: Checkpoint information
                - error_message: Error message (if failed)
                - metadata: Additional job metadata

        Raises:
            BigDataProvisionerException: If status retrieval fails
        """
        pass

    @abstractmethod
    async def cancel_flink_job(
        self,
        cluster_id: str,
        job_id: str,
        with_savepoint: bool = True
    ) -> Dict[str, Any]:
        """
        Cancel a running Flink job with optional savepoint.

        Args:
            cluster_id: Provider-specific cluster identifier
            job_id: Job identifier
            with_savepoint: Create savepoint before cancellation

        Returns:
            Dictionary containing:
                - job_id: Job identifier
                - cancelled_at: Cancellation timestamp
                - savepoint_path: Savepoint path (if created)

        Raises:
            BigDataProvisionerException: If job cancellation fails
        """
        pass

    @abstractmethod
    async def create_savepoint(
        self,
        cluster_id: str,
        job_id: str,
        savepoint_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Create a savepoint for a running Flink job.

        Args:
            cluster_id: Provider-specific cluster identifier
            job_id: Job identifier
            savepoint_path: Custom savepoint path (optional)

        Returns:
            Dictionary containing:
                - job_id: Job identifier
                - savepoint_path: Path to created savepoint
                - created_at: Savepoint creation timestamp

        Raises:
            BigDataProvisionerException: If savepoint creation fails
        """
        pass

    # Monitoring and Health
    @abstractmethod
    async def get_cluster_metrics(
        self,
        cluster_id: str,
        metric_names: List[str],
        start: datetime,
        end: datetime
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Retrieve metrics for a cluster over a time period.

        Args:
            cluster_id: Provider-specific cluster identifier
            metric_names: List of metric names to retrieve
            start: Start timestamp for metric data
            end: End timestamp for metric data

        Returns:
            Dictionary mapping metric names to lists of data points:
                {
                    "cpu_usage": [
                        {"timestamp": ..., "value": ..., "unit": "percent"},
                        ...
                    ],
                    ...
                }

        Raises:
            BigDataProvisionerException: If metric retrieval fails
        """
        pass

    @abstractmethod
    async def get_cluster_health(
        self,
        cluster_id: str
    ) -> Dict[str, Any]:
        """
        Get health status of a cluster.

        Args:
            cluster_id: Provider-specific cluster identifier

        Returns:
            Dictionary containing:
                - cluster_id: Cluster identifier
                - cluster_type: Type of cluster
                - status: Current status
                - health: Health status (healthy, degraded, unhealthy)
                - master_nodes: Master node health details
                - worker_nodes: Worker node health details
                - last_updated: Last health check timestamp
                - issues: List of identified issues

        Raises:
            BigDataProvisionerException: If health check fails
        """
        pass


def get_bigdata_provisioner(
    provider_type: str,
    config: Dict[str, Any]
) -> BaseBigDataProvisioner:
    """
    Factory function to instantiate the appropriate big data provisioner.

    Args:
        provider_type: Type of provider (kubernetes, aws, azure, gcp)
        config: Configuration dictionary for the provisioner

    Returns:
        Instantiated big data provisioner implementation

    Raises:
        BigDataProvisionerException: If provider_type is unknown or fails

    Examples:
        >>> config = {'credentials': {...}, 'region': 'us-east-1'}
        >>> provisioner = get_bigdata_provisioner('kubernetes', config)
        >>> cluster = await provisioner.create_spark_cluster(cluster_config)
    """
    provider_type = provider_type.lower()

    # Convert config dict to BigDataProvisionerConfig
    provisioner_config = BigDataProvisionerConfig(
        provider_type=provider_type,
        **config
    )

    # Import providers lazily to avoid circular dependencies
    if provider_type == 'kubernetes':
        from .kubernetes import KubernetesBigDataProvisioner
        return KubernetesBigDataProvisioner(provisioner_config)
    elif provider_type == 'aws':
        from .aws import AWSBigDataProvisioner
        return AWSBigDataProvisioner(provisioner_config)
    elif provider_type == 'azure':
        from .azure import AzureBigDataProvisioner
        return AzureBigDataProvisioner(provisioner_config)
    elif provider_type == 'gcp':
        from .gcp import GCPBigDataProvisioner
        return GCPBigDataProvisioner(provisioner_config)
    else:
        raise BigDataProvisionerException(
            f"Unknown provider type: {provider_type}",
            provider=provider_type
        )
