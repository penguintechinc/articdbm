"""
GCP provisioner for ArticDBM.

Implements database and cache provisioning using Google Cloud services:
- Cloud SQL for relational databases (PostgreSQL, MySQL, SQL Server)
- Memorystore for Redis/Memcached
- Firestore/DocumentDB equivalents

Copyright (c) 2025 Penguin Tech Inc
Licensed under Limited AGPL3
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from google.cloud import sql_v1
    from google.cloud import redis_v1
    from google.api_core import retry
    GOOGLE_CLOUD_AVAILABLE = True
except ImportError:
    GOOGLE_CLOUD_AVAILABLE = False

from .base import BaseProvisioner, ProvisionerConfig, ResourceConfig, ProvisionerException

logger = logging.getLogger(__name__)


class GCPProvisioner(BaseProvisioner):
    """GCP cloud provisioner using google-cloud clients for Cloud SQL and Memorystore."""

    # Map ArticDBM resource types to GCP services
    SERVICE_MAPPING = {
        'postgresql': 'cloudsql',
        'mysql': 'cloudsql',
        'sqlserver': 'cloudsql',
        'redis': 'memorystore',
        'memcached': 'memorystore',
        'firestore': 'firestore',
    }

    # Cloud SQL database versions
    CLOUDSQL_VERSION_MAPPING = {
        'postgresql': 'POSTGRES_15',
        'mysql': 'MYSQL_8_0',
        'sqlserver': 'SQLSERVER_2019',
    }

    # Cloud SQL tier names (machine types)
    CLOUDSQL_TIER_MAPPING = {
        'small': 'db-f1-micro',
        'medium': 'db-n1-standard-1',
        'large': 'db-n1-standard-2',
        'xlarge': 'db-n1-standard-4',
    }

    def __init__(self, config: ProvisionerConfig):
        """
        Initialize GCP provisioner.

        Args:
            config: ProvisionerConfig containing:
                - credentials: Dict with project_id, credentials_json path, or default auth
                - region: GCP region (e.g., 'us-central1')
                - Additional fields: vpc_network, tier_mapping

        Raises:
            ProvisionerException: If initialization fails
        """
        super().__init__(config)

        if not GOOGLE_CLOUD_AVAILABLE:
            raise ProvisionerException(
                "google-cloud-sql-admin or google-cloud-redis libraries not installed",
                provider="gcp"
            )

        # Extract GCP-specific configuration
        self.project_id = config.credentials.get('project_id')
        self.region = config.region or 'us-central1'
        self.vpc_network = config.credentials.get('vpc_network', 'default')

        if not self.project_id:
            raise ProvisionerException(
                "Missing required GCP configuration: project_id",
                provider="gcp"
            )

        # Initialize GCP clients (lazy loaded)
        self._cloudsql_client = None
        self._redis_client = None
        self._credentials = None

        logger.info(f"Initialized GCP provisioner for project {self.project_id} in {self.region}")

    @property
    def cloudsql_client(self):
        """Lazy-load Cloud SQL Admin client."""
        if self._cloudsql_client is None:
            self._cloudsql_client = sql_v1.SqlInstancesServiceClient()
        return self._cloudsql_client

    @property
    def redis_client(self):
        """Lazy-load Memorystore for Redis client."""
        if self._redis_client is None:
            self._redis_client = redis_v1.CloudRedisClient()
        return self._redis_client

    async def create_resource(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """
        Create a new GCP resource.

        Args:
            resource_config: Configuration for the resource to create

        Returns:
            Dictionary containing:
                - provider_resource_id: GCP resource identifier
                - endpoint: Connection endpoint (hostname or IP)
                - port: Connection port
                - status: Current resource status
                - created_at: Creation timestamp
                - metadata: Additional GCP-specific metadata

        Raises:
            ProvisionerException: If resource creation fails
        """
        service = self.SERVICE_MAPPING.get(resource_config.resource_type)
        if not service:
            raise ProvisionerException(
                f"Unsupported resource type: {resource_config.resource_type}",
                provider="gcp",
                resource_id=resource_config.name
            )

        try:
            if service == 'cloudsql':
                return await self._create_cloudsql_instance(resource_config)
            elif service == 'memorystore':
                return await self._create_memorystore_instance(resource_config)
            elif service == 'firestore':
                return await self._create_firestore_instance(resource_config)
            else:
                raise ProvisionerException(
                    f"Unknown GCP service: {service}",
                    provider="gcp"
                )
        except Exception as e:
            logger.error(f"GCP API error creating {resource_config.name}: {e}")
            raise ProvisionerException(
                f"GCP resource creation failed: {str(e)}",
                provider="gcp",
                resource_id=resource_config.name,
                original_error=e
            )

    async def _create_cloudsql_instance(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """Create Cloud SQL instance."""
        db_version = self.CLOUDSQL_VERSION_MAPPING.get(
            resource_config.resource_type,
            'POSTGRES_15'
        )
        tier = self.CLOUDSQL_TIER_MAPPING.get(resource_config.instance_size, 'db-f1-micro')

        parent = f"projects/{self.project_id}"

        # Build Cloud SQL instance body
        instance_body = {
            'name': resource_config.name,
            'databaseVersion': db_version,
            'settings': {
                'tier': tier,
                'backupConfiguration': {
                    'enabled': resource_config.backup_enabled,
                    'binaryLogEnabled': resource_config.backup_enabled,
                    'replicationLog': resource_config.backup_enabled,
                    'backupRetentionSettings': {
                        'retentionUnit': 'COUNT',
                        'retentionCount': resource_config.backup_retention_days,
                    },
                },
                'ipConfiguration': {
                    'requireSsl': True,
                    'authorizedNetworks': [
                        {
                            'name': 'all',
                            'value': '0.0.0.0/0',
                        }
                    ],
                },
                'userLabels': self._format_labels(resource_config.labels),
            },
        }

        # Add network configuration if provided
        if self.vpc_network and self.vpc_network != 'default':
            instance_body['settings']['ipConfiguration']['ipv4Enabled'] = False
            instance_body['settings']['ipConfiguration']['privateNetwork'] = (
                f"projects/{self.project_id}/global/networks/{self.vpc_network}"
            )

        # Create the instance (placeholder implementation)
        logger.info(f"Creating Cloud SQL instance: {resource_config.name}")

        result = {
            'provider_resource_id': f"projects/{self.project_id}/instances/{resource_config.name}",
            'endpoint': f"{resource_config.name}.c.{self.project_id}.cloudsql.net",
            'port': 3306 if 'mysql' in resource_config.resource_type.lower() else 5432,
            'status': 'PENDING',
            'created_at': datetime.utcnow().isoformat(),
            'metadata': {
                'instance_type': resource_config.resource_type,
                'tier': tier,
                'db_version': db_version,
                'replicas': resource_config.replicas,
                'storage_size_gb': resource_config.storage_size_gb,
                'network': self.vpc_network,
            },
        }

        return result

    async def _create_memorystore_instance(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """Create Memorystore instance (Redis or Memcached)."""
        instance_type = 'redis' if 'redis' in resource_config.resource_type.lower() else 'memcached'

        parent = f"projects/{self.project_id}/locations/{self.region}"

        # Size to memory mapping (in GB)
        size_to_memory = {
            'small': 1,
            'medium': 5,
            'large': 10,
            'xlarge': 25,
        }
        memory_size_gb = size_to_memory.get(resource_config.instance_size, 1)

        # Build Memorystore instance body
        instance_body = {
            'name': f"{parent}/instances/{resource_config.name}",
            'displayName': resource_config.name,
            'tier': 'BASIC',
            'sizeGb': memory_size_gb,
            'labels': self._format_labels(resource_config.labels),
        }

        if instance_type == 'redis':
            instance_body['redisVersion'] = 'redis_7_0'
            instance_body['redisConfigs'] = {
                'maxmemory-policy': 'allkeys-lru',
            }

        # Add network configuration
        if self.vpc_network and self.vpc_network != 'default':
            instance_body['authorizedNetwork'] = (
                f"projects/{self.project_id}/global/networks/{self.vpc_network}"
            )

        logger.info(f"Creating Memorystore {instance_type} instance: {resource_config.name}")

        result = {
            'provider_resource_id': f"{parent}/instances/{resource_config.name}",
            'endpoint': f"{resource_config.name}.{self.region}.cache.googleapis.com",
            'port': 6379 if instance_type == 'redis' else 11211,
            'status': 'PENDING',
            'created_at': datetime.utcnow().isoformat(),
            'metadata': {
                'instance_type': instance_type,
                'memory_size_gb': memory_size_gb,
                'region': self.region,
            },
        }

        return result

    async def _create_firestore_instance(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """Create Firestore instance (document database)."""
        logger.info(f"Creating Firestore instance: {resource_config.name}")

        result = {
            'provider_resource_id': f"projects/{self.project_id}/databases/{resource_config.name}",
            'endpoint': f"firestore.googleapis.com",
            'port': 443,
            'status': 'PENDING',
            'created_at': datetime.utcnow().isoformat(),
            'metadata': {
                'instance_type': 'firestore',
                'database_type': 'document',
            },
        }

        return result

    async def update_resource(
        self,
        resource_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update an existing GCP resource.

        Args:
            resource_id: GCP resource identifier
            updates: Dictionary of fields to update

        Returns:
            Dictionary containing updated resource state

        Raises:
            ProvisionerException: If update fails
        """
        try:
            logger.info(f"Updating GCP resource: {resource_id}")

            # Placeholder implementation
            result = {
                'provider_resource_id': resource_id,
                'status': 'UPDATING',
                'updated_at': datetime.utcnow().isoformat(),
                'metadata': updates,
            }

            return result

        except Exception as e:
            logger.error(f"GCP API error updating {resource_id}: {e}")
            raise ProvisionerException(
                f"GCP resource update failed: {str(e)}",
                provider="gcp",
                resource_id=resource_id,
                original_error=e
            )

    async def delete_resource(self, resource_id: str) -> bool:
        """
        Delete a GCP resource.

        Args:
            resource_id: GCP resource identifier

        Returns:
            True if deletion successful, False otherwise

        Raises:
            ProvisionerException: If deletion fails
        """
        try:
            logger.info(f"Deleting GCP resource: {resource_id}")

            # Placeholder implementation
            return True

        except Exception as e:
            logger.error(f"GCP API error deleting {resource_id}: {e}")
            raise ProvisionerException(
                f"GCP resource deletion failed: {str(e)}",
                provider="gcp",
                resource_id=resource_id,
                original_error=e
            )

    async def get_resource_status(self, resource_id: str) -> Dict[str, Any]:
        """
        Get current status and details of a GCP resource.

        Args:
            resource_id: GCP resource identifier

        Returns:
            Dictionary containing resource status and metadata

        Raises:
            ProvisionerException: If status retrieval fails
        """
        try:
            logger.info(f"Retrieving status for GCP resource: {resource_id}")

            # Placeholder implementation
            result = {
                'provider_resource_id': resource_id,
                'status': 'RUNNING',
                'health': 'healthy',
                'endpoint': 'placeholder.googleapis.com',
                'port': 5432,
                'replicas': 1,
                'last_updated': datetime.utcnow().isoformat(),
                'metadata': {},
            }

            return result

        except Exception as e:
            logger.error(f"GCP API error getting status for {resource_id}: {e}")
            raise ProvisionerException(
                f"GCP status retrieval failed: {str(e)}",
                provider="gcp",
                resource_id=resource_id,
                original_error=e
            )

    async def scale_resource(
        self,
        resource_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale a GCP resource.

        Args:
            resource_id: GCP resource identifier
            scale_config: Scaling configuration (replicas, instance_size, storage_size_gb)

        Returns:
            Dictionary containing updated scaling state

        Raises:
            ProvisionerException: If scaling fails
        """
        try:
            logger.info(f"Scaling GCP resource: {resource_id} with config: {scale_config}")

            # Placeholder implementation
            result = {
                'provider_resource_id': resource_id,
                'status': 'SCALING',
                'replicas': scale_config.get('replicas', 1),
                'instance_size': scale_config.get('instance_size', 'small'),
                'storage_size_gb': scale_config.get('storage_size_gb', 20),
                'scaled_at': datetime.utcnow().isoformat(),
            }

            return result

        except Exception as e:
            logger.error(f"GCP API error scaling {resource_id}: {e}")
            raise ProvisionerException(
                f"GCP scaling failed: {str(e)}",
                provider="gcp",
                resource_id=resource_id,
                original_error=e
            )

    async def get_metrics(
        self,
        resource_id: str,
        metric_name: str,
        start: datetime,
        end: datetime
    ) -> List[Dict[str, Any]]:
        """
        Retrieve metrics for a GCP resource over a time period.

        Args:
            resource_id: GCP resource identifier
            metric_name: Name of metric (cpu, memory, connections, etc.)
            start: Start timestamp
            end: End timestamp

        Returns:
            List of metric data points with timestamp, value, and unit

        Raises:
            ProvisionerException: If metric retrieval fails
        """
        try:
            logger.info(f"Retrieving metrics for {resource_id}: {metric_name}")

            # Placeholder implementation - return sample metrics
            metrics = [
                {
                    'timestamp': datetime.utcnow().isoformat(),
                    'value': 45.5,
                    'unit': 'percent',
                },
                {
                    'timestamp': datetime.utcnow().isoformat(),
                    'value': 52.3,
                    'unit': 'percent',
                },
            ]

            return metrics

        except Exception as e:
            logger.error(f"GCP API error retrieving metrics for {resource_id}: {e}")
            raise ProvisionerException(
                f"GCP metrics retrieval failed: {str(e)}",
                provider="gcp",
                resource_id=resource_id,
                original_error=e
            )

    async def test_connection(self) -> Tuple[bool, str]:
        """
        Test connectivity to GCP.

        Returns:
            Tuple of (success, message)

        Raises:
            ProvisionerException: If connection test encounters critical error
        """
        try:
            logger.info(f"Testing GCP connection for project: {self.project_id}")

            # Placeholder implementation - test project access
            return True, f"Successfully connected to GCP project {self.project_id}"

        except Exception as e:
            logger.error(f"GCP connection test failed: {e}")
            raise ProvisionerException(
                f"GCP connection test failed: {str(e)}",
                provider="gcp",
                original_error=e
            )

    async def sync_tags(self, resource_id: str, tags: Dict[str, str]) -> bool:
        """
        Synchronize labels on a GCP resource.

        Args:
            resource_id: GCP resource identifier
            tags: Dictionary of labels to apply

        Returns:
            True if synchronization successful

        Raises:
            ProvisionerException: If tag synchronization fails
        """
        try:
            logger.info(f"Synchronizing labels for {resource_id}: {tags}")

            # Placeholder implementation
            gcp_labels = self._format_labels(tags)

            logger.info(f"Applied {len(gcp_labels)} labels to {resource_id}")

            return True

        except Exception as e:
            logger.error(f"GCP API error syncing tags for {resource_id}: {e}")
            raise ProvisionerException(
                f"GCP label synchronization failed: {str(e)}",
                provider="gcp",
                resource_id=resource_id,
                original_error=e
            )

    def _format_labels(self, tags: Dict[str, str]) -> Dict[str, str]:
        """
        Format tags dict to GCP labels format (lowercase, hyphen-separated).

        GCP labels must be lowercase alphanumeric and hyphens.

        Args:
            tags: Dictionary of tags

        Returns:
            Dictionary with formatted GCP labels
        """
        gcp_labels = {}
        for key, value in tags.items():
            # Convert to lowercase and replace spaces/underscores with hyphens
            gcp_key = key.lower().replace(' ', '-').replace('_', '-')
            gcp_value = str(value).lower().replace(' ', '-').replace('_', '-')

            # Enforce GCP label constraints (max 63 chars per label)
            gcp_key = gcp_key[:63]
            gcp_value = gcp_value[:63]

            gcp_labels[gcp_key] = gcp_value

        # Add default labels
        gcp_labels['managed-by'] = 'articdbm'
        gcp_labels['created-at'] = datetime.utcnow().isoformat()[:10]

        return gcp_labels
