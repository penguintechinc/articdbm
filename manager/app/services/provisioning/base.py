"""
Base provisioner abstract class for cloud and Kubernetes resource provisioning.

This module defines the core interface that all provisioner implementations
must adhere to, ensuring consistent behavior across different cloud providers
and Kubernetes clusters.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ProvisionerConfig:
    """
    Common configuration for all provisioners.

    Attributes:
        provider_type: Type of provider (kubernetes, aws, azure, gcp)
        credentials: Provider-specific credential dictionary
        region: Cloud region or cluster region
        timeout: Default timeout for operations in seconds
        retry_attempts: Number of retry attempts for failed operations
        dry_run: If True, simulate operations without executing
        tags: Default tags to apply to all resources
    """
    provider_type: str
    credentials: Dict[str, Any] = field(default_factory=dict)
    region: Optional[str] = None
    timeout: int = 300
    retry_attempts: int = 3
    dry_run: bool = False
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class ResourceConfig:
    """
    Configuration for resource creation.

    Attributes:
        name: Resource name (must be unique within provider)
        resource_type: Type of resource (proxy, database, loadbalancer)
        instance_size: Size/tier of the resource
        replicas: Number of replicas for high availability
        storage_size_gb: Storage allocation in GB
        backup_enabled: Enable automated backups
        backup_retention_days: Backup retention period
        network_config: Network configuration (VPC, subnet, security groups)
        database_config: Database-specific configuration
        proxy_config: Proxy-specific configuration
        labels: Resource labels/tags
        annotations: Provider-specific annotations
    """
    name: str
    resource_type: str
    instance_size: str = 'small'
    replicas: int = 1
    storage_size_gb: int = 20
    backup_enabled: bool = True
    backup_retention_days: int = 7
    network_config: Dict[str, Any] = field(default_factory=dict)
    database_config: Dict[str, Any] = field(default_factory=dict)
    proxy_config: Dict[str, Any] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)
    annotations: Dict[str, str] = field(default_factory=dict)


class ProvisionerException(Exception):
    """
    Base exception for provisioner errors.

    Attributes:
        message: Error message
        provider: Provider type where error occurred
        resource_id: Resource ID if applicable
        original_error: Original exception if wrapped
    """

    def __init__(
        self,
        message: str,
        provider: Optional[str] = None,
        resource_id: Optional[str] = None,
        original_error: Optional[Exception] = None
    ):
        self.message = message
        self.provider = provider
        self.resource_id = resource_id
        self.original_error = original_error
        super().__init__(self.message)

    def __str__(self) -> str:
        parts = [self.message]
        if self.provider:
            parts.append(f"Provider: {self.provider}")
        if self.resource_id:
            parts.append(f"Resource: {self.resource_id}")
        if self.original_error:
            parts.append(f"Original error: {str(self.original_error)}")
        return " | ".join(parts)


class BaseProvisioner(ABC):
    """
    Abstract base class for cloud and Kubernetes provisioners.

    All provisioner implementations must inherit from this class and
    implement all abstract methods to ensure consistent behavior.
    """

    def __init__(self, config: ProvisionerConfig):
        """
        Initialize provisioner with configuration.

        Args:
            config: Provisioner configuration
        """
        self.config = config
        self._initialized = False

    @abstractmethod
    async def create_resource(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """
        Create a new cloud or Kubernetes resource.

        Args:
            resource_config: Configuration for the resource to create

        Returns:
            Dictionary containing:
                - provider_resource_id: Provider-specific resource identifier
                - endpoint: Connection endpoint (hostname or IP)
                - port: Connection port
                - status: Current resource status
                - created_at: Creation timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            ProvisionerException: If resource creation fails
        """
        pass

    @abstractmethod
    async def update_resource(
        self,
        resource_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing resource configuration.

        Args:
            resource_id: Provider-specific resource identifier
            updates: Dictionary of fields to update

        Returns:
            Dictionary containing updated resource state:
                - provider_resource_id: Resource identifier
                - status: Current resource status
                - updated_at: Update timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            ProvisionerException: If resource update fails
        """
        pass

    @abstractmethod
    async def delete_resource(self, resource_id: str) -> bool:
        """
        Delete a cloud or Kubernetes resource.

        Args:
            resource_id: Provider-specific resource identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            ProvisionerException: If resource deletion fails
        """
        pass

    @abstractmethod
    async def get_resource_status(self, resource_id: str) -> Dict[str, Any]:
        """
        Get current status and details of a resource.

        Args:
            resource_id: Provider-specific resource identifier

        Returns:
            Dictionary containing:
                - provider_resource_id: Resource identifier
                - status: Current status (pending, running, error, terminated)
                - health: Health status (healthy, degraded, unhealthy)
                - endpoint: Connection endpoint
                - port: Connection port
                - replicas: Current replica count
                - last_updated: Last status update timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            ProvisionerException: If status retrieval fails
        """
        pass

    @abstractmethod
    async def scale_resource(
        self,
        resource_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale a resource (adjust replicas, instance size, storage).

        Args:
            resource_id: Provider-specific resource identifier
            scale_config: Scaling configuration containing:
                - replicas: New replica count (optional)
                - instance_size: New instance size (optional)
                - storage_size_gb: New storage size in GB (optional)

        Returns:
            Dictionary containing:
                - provider_resource_id: Resource identifier
                - status: Current status after scaling
                - replicas: New replica count
                - instance_size: Current instance size
                - storage_size_gb: Current storage size
                - scaled_at: Scaling timestamp

        Raises:
            ProvisionerException: If scaling operation fails
        """
        pass

    @abstractmethod
    async def get_metrics(
        self,
        resource_id: str,
        metric_name: str,
        start: datetime,
        end: datetime
    ) -> List[Dict[str, Any]]:
        """
        Retrieve metrics for a resource over a time period.

        Args:
            resource_id: Provider-specific resource identifier
            metric_name: Name of metric to retrieve (cpu, memory, connections, etc.)
            start: Start timestamp for metric data
            end: End timestamp for metric data

        Returns:
            List of metric data points, each containing:
                - timestamp: Data point timestamp
                - value: Metric value
                - unit: Metric unit (percent, bytes, count, etc.)

        Raises:
            ProvisionerException: If metric retrieval fails
        """
        pass

    @abstractmethod
    async def test_connection(self) -> Tuple[bool, str]:
        """
        Test connectivity to the cloud provider or Kubernetes cluster.

        Returns:
            Tuple of (success, message):
                - success: True if connection successful, False otherwise
                - message: Human-readable status message

        Raises:
            ProvisionerException: If connection test encounters critical error
        """
        pass

    @abstractmethod
    async def sync_tags(self, resource_id: str, tags: Dict[str, str]) -> bool:
        """
        Synchronize tags/labels on a resource.

        Args:
            resource_id: Provider-specific resource identifier
            tags: Dictionary of tags to apply (overwrites existing tags)

        Returns:
            True if tag synchronization successful, False otherwise

        Raises:
            ProvisionerException: If tag synchronization fails
        """
        pass


def get_provisioner(provider_type: str, config: Dict[str, Any]) -> BaseProvisioner:
    """
    Factory function to instantiate the appropriate provisioner.

    Args:
        provider_type: Type of provider (kubernetes, aws, azure, gcp)
        config: Configuration dictionary for the provisioner

    Returns:
        Instantiated provisioner implementation

    Raises:
        ProvisionerException: If provider_type is unknown or instantiation fails

    Examples:
        >>> config = {'credentials': {...}, 'region': 'us-east-1'}
        >>> provisioner = get_provisioner('kubernetes', config)
        >>> status = await provisioner.test_connection()
    """
    provider_type = provider_type.lower()

    # Convert config dict to ProvisionerConfig
    provisioner_config = ProvisionerConfig(
        provider_type=provider_type,
        **config
    )

    # Import providers lazily to avoid circular dependencies
    if provider_type == 'kubernetes':
        from .kubernetes import KubernetesProvisioner
        return KubernetesProvisioner(provisioner_config)
    elif provider_type == 'aws':
        from .aws import AWSProvisioner
        return AWSProvisioner(provisioner_config)
    elif provider_type == 'azure':
        from .azure import AzureProvisioner
        return AzureProvisioner(provisioner_config)
    elif provider_type == 'gcp':
        from .gcp import GCPProvisioner
        return GCPProvisioner(provisioner_config)
    else:
        raise ProvisionerException(
            f"Unknown provider type: {provider_type}",
            provider=provider_type
        )
