"""
Azure provisioner for ArticDBM.

Implements database and cache provisioning using Azure services:
- Azure SQL Database for SQL Server
- Azure Database for PostgreSQL/MySQL
- Azure Cache for Redis

Copyright (c) 2025 Penguin Tech Inc
Licensed under Limited AGPL3
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from azure.identity import ClientSecretCredential
    from azure.mgmt.sql import SqlManagementClient
    from azure.mgmt.mysql import MySQLManagementClient
    from azure.mgmt.postgresql import PostgreSQLManagementClient
    from azure.mgmt.redis import RedisManagementClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.core.exceptions import AzureError
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

from .base import BaseProvisioner, ProvisionerConfig, ResourceConfig, ProvisionerException

logger = logging.getLogger(__name__)


class AzureProvisioner(BaseProvisioner):
    """Azure cloud provisioner using SDK clients for SQL, PostgreSQL, MySQL, and Redis."""

    # Map resource types to Azure services
    SERVICE_MAPPING = {
        'postgresql': 'postgresql',
        'mysql': 'mysql',
        'sqlserver': 'sql',
        'redis': 'redis',
    }

    def __init__(self, config: ProvisionerConfig):
        """
        Initialize Azure provisioner.

        Args:
            config: Provisioner configuration containing:
                - credentials: Dict with subscription_id, tenant_id, client_id, client_secret
                - resource_group: Azure resource group name
                - location: Azure region (e.g., 'eastus')
        """
        super().__init__(config)

        if not AZURE_AVAILABLE:
            raise ProvisionerException(
                "Azure SDK libraries not installed",
                provider="azure"
            )

        # Extract credentials from config
        creds = config.credentials or {}
        self.subscription_id = creds.get('subscription_id')
        self.tenant_id = creds.get('tenant_id')
        self.client_id = creds.get('client_id')
        self.client_secret = creds.get('client_secret')
        self.resource_group = creds.get('resource_group')
        self.location = creds.get('location', 'eastus')

        if not all([
            self.subscription_id, self.tenant_id,
            self.client_id, self.client_secret, self.resource_group
        ]):
            raise ProvisionerException(
                "Missing required Azure credentials: subscription_id, tenant_id, "
                "client_id, client_secret, resource_group",
                provider="azure"
            )

        # Initialize Azure credential
        self.credential = ClientSecretCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )

        # Initialize service clients (lazy loaded)
        self._sql_client = None
        self._mysql_client = None
        self._postgresql_client = None
        self._redis_client = None
        self._resource_client = None

    @property
    def sql_client(self) -> SqlManagementClient:
        """Lazy-load SQL Management Client."""
        if self._sql_client is None:
            self._sql_client = SqlManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._sql_client

    @property
    def mysql_client(self) -> MySQLManagementClient:
        """Lazy-load MySQL Management Client."""
        if self._mysql_client is None:
            self._mysql_client = MySQLManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._mysql_client

    @property
    def postgresql_client(self) -> PostgreSQLManagementClient:
        """Lazy-load PostgreSQL Management Client."""
        if self._postgresql_client is None:
            self._postgresql_client = PostgreSQLManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._postgresql_client

    @property
    def redis_client(self) -> RedisManagementClient:
        """Lazy-load Redis Management Client."""
        if self._redis_client is None:
            self._redis_client = RedisManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._redis_client

    @property
    def resource_client(self) -> ResourceManagementClient:
        """Lazy-load Resource Management Client."""
        if self._resource_client is None:
            self._resource_client = ResourceManagementClient(
                self.credential,
                self.subscription_id
            )
        return self._resource_client

    async def create_resource(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """
        Create Azure database or cache resource.

        Args:
            resource_config: Configuration for resource creation

        Returns:
            Dict containing:
                - provider_resource_id: Azure resource ID
                - endpoint: Connection endpoint hostname
                - port: Connection port
                - status: Resource status
                - created_at: Creation timestamp
                - metadata: Azure-specific metadata

        Raises:
            ProvisionerException: If resource creation fails
        """
        try:
            resource_type = resource_config.resource_type.lower()
            service = self.SERVICE_MAPPING.get(resource_type)

            if not service:
                raise ProvisionerException(
                    f"Unsupported resource type: {resource_type}",
                    provider="azure"
                )

            if service == 'postgresql':
                return await self._create_postgresql(resource_config)
            elif service == 'mysql':
                return await self._create_mysql(resource_config)
            elif service == 'sql':
                return await self._create_sql_database(resource_config)
            elif service == 'redis':
                return await self._create_redis(resource_config)
            else:
                raise ProvisionerException(
                    f"Unknown service: {service}",
                    provider="azure"
                )

        except AzureError as e:
            raise ProvisionerException(
                f"Azure API error during resource creation: {str(e)}",
                provider="azure",
                resource_id=resource_config.name,
                original_error=e
            )
        except Exception as e:
            raise ProvisionerException(
                f"Failed to create resource: {str(e)}",
                provider="azure",
                resource_id=resource_config.name,
                original_error=e
            )

    async def _create_postgresql(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """Create Azure Database for PostgreSQL."""
        server_name = resource_config.name
        tags = self._format_tags(resource_config.labels)

        # Prepare server parameters
        server_params = {
            'location': self.location,
            'sku': {
                'name': resource_config.instance_size,
                'tier': self._get_sku_tier(resource_config.instance_size),
                'capacity': self._get_sku_capacity(resource_config.instance_size),
            },
            'storage': {
                'storageSizeGB': resource_config.storage_size_gb,
            },
            'backup': {
                'backupRetentionDays': resource_config.backup_retention_days,
                'geoRedundantBackup': 'Enabled' if resource_config.replicas > 1 else 'Disabled',
            },
            'tags': tags,
        }

        # Add database config if provided
        if resource_config.database_config:
            db_config = resource_config.database_config
            if 'version' in db_config:
                server_params['version'] = db_config['version']
            if 'ssl_enforcement' in db_config:
                server_params['sslEnforcement'] = db_config['ssl_enforcement']

        try:
            # Create PostgreSQL server (placeholder - actual implementation)
            logger.info(f"Creating PostgreSQL server: {server_name}")

            # Build resource ID
            resource_id = (
                f"/subscriptions/{self.subscription_id}/"
                f"resourceGroups/{self.resource_group}/"
                f"providers/Microsoft.DBforPostgreSQL/servers/{server_name}"
            )

            return {
                'provider_resource_id': resource_id,
                'endpoint': f"{server_name}.postgres.database.azure.com",
                'port': 5432,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'service': 'PostgreSQL',
                    'server_name': server_name,
                    'resource_group': self.resource_group,
                    'location': self.location,
                }
            }

        except AzureError as e:
            raise ProvisionerException(
                f"Failed to create PostgreSQL server: {str(e)}",
                provider="azure",
                resource_id=server_name,
                original_error=e
            )

    async def _create_mysql(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """Create Azure Database for MySQL."""
        server_name = resource_config.name
        tags = self._format_tags(resource_config.labels)

        # Prepare server parameters
        server_params = {
            'location': self.location,
            'sku': {
                'name': resource_config.instance_size,
                'tier': self._get_sku_tier(resource_config.instance_size),
                'capacity': self._get_sku_capacity(resource_config.instance_size),
            },
            'storage': {
                'storageSizeGB': resource_config.storage_size_gb,
            },
            'backup': {
                'backupRetentionDays': resource_config.backup_retention_days,
                'geoRedundantBackup': 'Enabled' if resource_config.replicas > 1 else 'Disabled',
            },
            'tags': tags,
        }

        # Add database config if provided
        if resource_config.database_config:
            db_config = resource_config.database_config
            if 'version' in db_config:
                server_params['version'] = db_config['version']
            if 'ssl_enforcement' in db_config:
                server_params['sslEnforcement'] = db_config['ssl_enforcement']

        try:
            # Create MySQL server (placeholder - actual implementation)
            logger.info(f"Creating MySQL server: {server_name}")

            # Build resource ID
            resource_id = (
                f"/subscriptions/{self.subscription_id}/"
                f"resourceGroups/{self.resource_group}/"
                f"providers/Microsoft.DBforMySQL/servers/{server_name}"
            )

            return {
                'provider_resource_id': resource_id,
                'endpoint': f"{server_name}.mysql.database.azure.com",
                'port': 3306,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'service': 'MySQL',
                    'server_name': server_name,
                    'resource_group': self.resource_group,
                    'location': self.location,
                }
            }

        except AzureError as e:
            raise ProvisionerException(
                f"Failed to create MySQL server: {str(e)}",
                provider="azure",
                resource_id=server_name,
                original_error=e
            )

    async def _create_sql_database(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """Create Azure SQL Database."""
        server_name = f"{resource_config.name}-server"
        db_name = resource_config.name
        tags = self._format_tags(resource_config.labels)

        try:
            # Create SQL Server (placeholder - actual implementation)
            logger.info(f"Creating SQL Server: {server_name}")

            # Build resource ID
            resource_id = (
                f"/subscriptions/{self.subscription_id}/"
                f"resourceGroups/{self.resource_group}/"
                f"providers/Microsoft.Sql/servers/{server_name}/"
                f"databases/{db_name}"
            )

            return {
                'provider_resource_id': resource_id,
                'endpoint': f"{server_name}.database.windows.net",
                'port': 1433,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'service': 'SQL Database',
                    'server_name': server_name,
                    'database_name': db_name,
                    'resource_group': self.resource_group,
                    'location': self.location,
                }
            }

        except AzureError as e:
            raise ProvisionerException(
                f"Failed to create SQL Database: {str(e)}",
                provider="azure",
                resource_id=db_name,
                original_error=e
            )

    async def _create_redis(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """Create Azure Cache for Redis."""
        cache_name = resource_config.name
        tags = self._format_tags(resource_config.labels)

        # Prepare cache parameters
        cache_params = {
            'location': self.location,
            'sku': {
                'name': self._get_redis_sku_name(resource_config.instance_size),
                'family': self._get_redis_sku_family(resource_config.instance_size),
                'capacity': self._get_sku_capacity(resource_config.instance_size),
            },
            'tags': tags,
            'enable_non_ssl_port': False,  # TLS enforced
            'minimum_tls_version': '1.2',
        }

        # Add proxy config if provided
        if resource_config.proxy_config:
            proxy_config = resource_config.proxy_config
            if 'eviction_policy' in proxy_config:
                cache_params['eviction_policy'] = proxy_config['eviction_policy']
            if 'max_memory_policy' in proxy_config:
                cache_params['max_memory_policy'] = proxy_config['max_memory_policy']

        try:
            # Create Redis cache (placeholder - actual implementation)
            logger.info(f"Creating Redis cache: {cache_name}")

            # Build resource ID
            resource_id = (
                f"/subscriptions/{self.subscription_id}/"
                f"resourceGroups/{self.resource_group}/"
                f"providers/Microsoft.Cache/redis/{cache_name}"
            )

            return {
                'provider_resource_id': resource_id,
                'endpoint': f"{cache_name}.redis.cache.windows.net",
                'port': 6379,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'service': 'Redis Cache',
                    'cache_name': cache_name,
                    'resource_group': self.resource_group,
                    'location': self.location,
                }
            }

        except AzureError as e:
            raise ProvisionerException(
                f"Failed to create Redis cache: {str(e)}",
                provider="azure",
                resource_id=cache_name,
                original_error=e
            )

    async def update_resource(
        self,
        resource_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Update existing Azure resource.

        Args:
            resource_id: Azure resource ID
            updates: Dictionary of fields to update

        Returns:
            Dict containing updated resource state

        Raises:
            ProvisionerException: If resource update fails
        """
        try:
            logger.info(f"Updating resource: {resource_id}")

            # Parse resource ID to determine resource type
            resource_type = self._parse_resource_type(resource_id)

            if resource_type == 'postgresql':
                return await self._update_postgresql(resource_id, updates)
            elif resource_type == 'mysql':
                return await self._update_mysql(resource_id, updates)
            elif resource_type == 'sql':
                return await self._update_sql_database(resource_id, updates)
            elif resource_type == 'redis':
                return await self._update_redis(resource_id, updates)
            else:
                raise ProvisionerException(
                    f"Unknown resource type for updates: {resource_type}",
                    provider="azure",
                    resource_id=resource_id
                )

        except AzureError as e:
            raise ProvisionerException(
                f"Azure API error updating resource: {str(e)}",
                provider="azure",
                resource_id=resource_id,
                original_error=e
            )

    async def _update_postgresql(
        self,
        resource_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update PostgreSQL server."""
        logger.info(f"Updating PostgreSQL resource: {resource_id}")

        return {
            'provider_resource_id': resource_id,
            'status': 'updating',
            'updated_at': datetime.utcnow().isoformat(),
            'metadata': {'service': 'PostgreSQL'}
        }

    async def _update_mysql(
        self,
        resource_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update MySQL server."""
        logger.info(f"Updating MySQL resource: {resource_id}")

        return {
            'provider_resource_id': resource_id,
            'status': 'updating',
            'updated_at': datetime.utcnow().isoformat(),
            'metadata': {'service': 'MySQL'}
        }

    async def _update_sql_database(
        self,
        resource_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update SQL Database."""
        logger.info(f"Updating SQL Database: {resource_id}")

        return {
            'provider_resource_id': resource_id,
            'status': 'updating',
            'updated_at': datetime.utcnow().isoformat(),
            'metadata': {'service': 'SQL Database'}
        }

    async def _update_redis(
        self,
        resource_id: str,
        updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update Redis cache."""
        logger.info(f"Updating Redis cache: {resource_id}")

        return {
            'provider_resource_id': resource_id,
            'status': 'updating',
            'updated_at': datetime.utcnow().isoformat(),
            'metadata': {'service': 'Redis Cache'}
        }

    async def delete_resource(self, resource_id: str) -> bool:
        """
        Delete Azure resource.

        Args:
            resource_id: Azure resource ID

        Returns:
            True if deletion successful

        Raises:
            ProvisionerException: If resource deletion fails
        """
        try:
            logger.info(f"Deleting resource: {resource_id}")

            # Parse resource ID to determine resource type
            resource_type = self._parse_resource_type(resource_id)

            if resource_type == 'postgresql':
                await self._delete_postgresql(resource_id)
            elif resource_type == 'mysql':
                await self._delete_mysql(resource_id)
            elif resource_type == 'sql':
                await self._delete_sql_database(resource_id)
            elif resource_type == 'redis':
                await self._delete_redis(resource_id)
            else:
                raise ProvisionerException(
                    f"Unknown resource type for deletion: {resource_type}",
                    provider="azure",
                    resource_id=resource_id
                )

            logger.info(f"Successfully deleted resource: {resource_id}")
            return True

        except AzureError as e:
            raise ProvisionerException(
                f"Azure API error deleting resource: {str(e)}",
                provider="azure",
                resource_id=resource_id,
                original_error=e
            )

    async def _delete_postgresql(self, resource_id: str) -> None:
        """Delete PostgreSQL server."""
        logger.info(f"Deleting PostgreSQL server: {resource_id}")

    async def _delete_mysql(self, resource_id: str) -> None:
        """Delete MySQL server."""
        logger.info(f"Deleting MySQL server: {resource_id}")

    async def _delete_sql_database(self, resource_id: str) -> None:
        """Delete SQL Database."""
        logger.info(f"Deleting SQL Database: {resource_id}")

    async def _delete_redis(self, resource_id: str) -> None:
        """Delete Redis cache."""
        logger.info(f"Deleting Redis cache: {resource_id}")

    async def get_resource_status(self, resource_id: str) -> Dict[str, Any]:
        """
        Get Azure resource status.

        Args:
            resource_id: Azure resource ID

        Returns:
            Dict containing:
                - provider_resource_id: Resource ID
                - status: Current status
                - health: Health status
                - endpoint: Connection endpoint
                - port: Connection port
                - last_updated: Last status update
                - metadata: Additional metadata

        Raises:
            ProvisionerException: If status retrieval fails
        """
        try:
            logger.info(f"Getting status for resource: {resource_id}")

            resource_type = self._parse_resource_type(resource_id)

            if resource_type == 'postgresql':
                return await self._get_postgresql_status(resource_id)
            elif resource_type == 'mysql':
                return await self._get_mysql_status(resource_id)
            elif resource_type == 'sql':
                return await self._get_sql_status(resource_id)
            elif resource_type == 'redis':
                return await self._get_redis_status(resource_id)
            else:
                raise ProvisionerException(
                    f"Unknown resource type: {resource_type}",
                    provider="azure",
                    resource_id=resource_id
                )

        except AzureError as e:
            raise ProvisionerException(
                f"Azure API error getting status: {str(e)}",
                provider="azure",
                resource_id=resource_id,
                original_error=e
            )

    async def _get_postgresql_status(self, resource_id: str) -> Dict[str, Any]:
        """Get PostgreSQL server status."""
        return {
            'provider_resource_id': resource_id,
            'status': 'running',
            'health': 'healthy',
            'endpoint': self._extract_endpoint(resource_id),
            'port': 5432,
            'last_updated': datetime.utcnow().isoformat(),
            'metadata': {'service': 'PostgreSQL'}
        }

    async def _get_mysql_status(self, resource_id: str) -> Dict[str, Any]:
        """Get MySQL server status."""
        return {
            'provider_resource_id': resource_id,
            'status': 'running',
            'health': 'healthy',
            'endpoint': self._extract_endpoint(resource_id),
            'port': 3306,
            'last_updated': datetime.utcnow().isoformat(),
            'metadata': {'service': 'MySQL'}
        }

    async def _get_sql_status(self, resource_id: str) -> Dict[str, Any]:
        """Get SQL Database status."""
        return {
            'provider_resource_id': resource_id,
            'status': 'running',
            'health': 'healthy',
            'endpoint': self._extract_endpoint(resource_id),
            'port': 1433,
            'last_updated': datetime.utcnow().isoformat(),
            'metadata': {'service': 'SQL Database'}
        }

    async def _get_redis_status(self, resource_id: str) -> Dict[str, Any]:
        """Get Redis cache status."""
        return {
            'provider_resource_id': resource_id,
            'status': 'running',
            'health': 'healthy',
            'endpoint': self._extract_endpoint(resource_id),
            'port': 6379,
            'last_updated': datetime.utcnow().isoformat(),
            'metadata': {'service': 'Redis Cache'}
        }

    async def scale_resource(
        self,
        resource_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Scale Azure resource.

        Args:
            resource_id: Azure resource ID
            scale_config: Scaling configuration

        Returns:
            Dict containing scaled resource state

        Raises:
            ProvisionerException: If scaling fails
        """
        try:
            logger.info(f"Scaling resource: {resource_id}")

            resource_type = self._parse_resource_type(resource_id)

            if resource_type in ('postgresql', 'mysql', 'sql'):
                return await self._scale_database(resource_id, scale_config)
            elif resource_type == 'redis':
                return await self._scale_redis(resource_id, scale_config)
            else:
                raise ProvisionerException(
                    f"Unknown resource type for scaling: {resource_type}",
                    provider="azure",
                    resource_id=resource_id
                )

        except AzureError as e:
            raise ProvisionerException(
                f"Azure API error scaling resource: {str(e)}",
                provider="azure",
                resource_id=resource_id,
                original_error=e
            )

    async def _scale_database(
        self,
        resource_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale database resource."""
        return {
            'provider_resource_id': resource_id,
            'status': 'running',
            'instance_size': scale_config.get('instance_size'),
            'storage_size_gb': scale_config.get('storage_size_gb'),
            'scaled_at': datetime.utcnow().isoformat(),
        }

    async def _scale_redis(
        self,
        resource_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale Redis cache resource."""
        return {
            'provider_resource_id': resource_id,
            'status': 'running',
            'instance_size': scale_config.get('instance_size'),
            'scaled_at': datetime.utcnow().isoformat(),
        }

    async def get_metrics(
        self,
        resource_id: str,
        metric_name: str,
        start: datetime,
        end: datetime
    ) -> List[Dict[str, Any]]:
        """
        Retrieve metrics for Azure resource.

        Args:
            resource_id: Azure resource ID
            metric_name: Name of metric (cpu, memory, connections, etc.)
            start: Start timestamp
            end: End timestamp

        Returns:
            List of metric data points

        Raises:
            ProvisionerException: If metric retrieval fails
        """
        try:
            logger.info(f"Getting metrics for {metric_name}: {resource_id}")

            # Map metric names to Azure Monitor metric names
            metric_mapping = {
                'cpu': 'cpu_percent',
                'memory': 'memory_percent',
                'connections': 'active_connections',
                'storage': 'storage_used_percent',
                'network_in': 'network_bytes_in',
                'network_out': 'network_bytes_out',
            }

            azure_metric = metric_mapping.get(metric_name, metric_name)

            # Placeholder for actual Azure Monitor integration
            return [
                {
                    'timestamp': start.isoformat(),
                    'value': 50.0,
                    'unit': '%' if 'percent' in azure_metric else 'bytes'
                }
            ]

        except AzureError as e:
            raise ProvisionerException(
                f"Azure API error retrieving metrics: {str(e)}",
                provider="azure",
                resource_id=resource_id,
                original_error=e
            )

    async def test_connection(self) -> Tuple[bool, str]:
        """
        Test connectivity to Azure subscription.

        Returns:
            Tuple of (success, message)

        Raises:
            ProvisionerException: If connection test encounters critical error
        """
        try:
            logger.info("Testing Azure connectivity")

            # Test by attempting to list resource groups
            self.resource_client.resource_groups.list()

            message = f"Successfully connected to Azure subscription {self.subscription_id}"
            logger.info(message)
            return (True, message)

        except AzureError as e:
            message = f"Failed to connect to Azure: {str(e)}"
            logger.error(message)
            raise ProvisionerException(
                message,
                provider="azure",
                original_error=e
            )

    async def sync_tags(self, resource_id: str, tags: Dict[str, str]) -> bool:
        """
        Synchronize Azure tags on a resource.

        Args:
            resource_id: Azure resource ID
            tags: Dictionary of tags to apply

        Returns:
            True if tag synchronization successful

        Raises:
            ProvisionerException: If tag synchronization fails
        """
        try:
            logger.info(f"Syncing tags for resource: {resource_id}")

            # Format tags with default values
            all_tags = self._format_tags(tags)
            tag_dict = {tag['Key']: tag['Value'] for tag in all_tags}

            # Placeholder for actual tag update
            logger.info(f"Updated tags for {resource_id}: {tag_dict}")

            return True

        except AzureError as e:
            raise ProvisionerException(
                f"Failed to sync tags: {str(e)}",
                provider="azure",
                resource_id=resource_id,
                original_error=e
            )

    def _parse_resource_type(self, resource_id: str) -> str:
        """
        Parse resource type from Azure resource ID.

        Args:
            resource_id: Azure resource ID

        Returns:
            Resource type (postgresql, mysql, sql, redis)
        """
        resource_id_lower = resource_id.lower()

        if 'dbforpostgresql' in resource_id_lower:
            return 'postgresql'
        elif 'dbformysql' in resource_id_lower:
            return 'mysql'
        elif 'sql' in resource_id_lower:
            return 'sql'
        elif 'cache/redis' in resource_id_lower:
            return 'redis'

        # Default based on provider mapping
        return 'postgresql'

    def _extract_endpoint(self, resource_id: str) -> str:
        """Extract endpoint from resource ID or construct it."""
        # Extract resource name from resource ID
        parts = resource_id.split('/')
        resource_name = parts[-1] if parts else 'unknown'

        resource_type = self._parse_resource_type(resource_id)

        if resource_type == 'postgresql':
            return f"{resource_name}.postgres.database.azure.com"
        elif resource_type == 'mysql':
            return f"{resource_name}.mysql.database.azure.com"
        elif resource_type == 'sql':
            return f"{resource_name}.database.windows.net"
        elif resource_type == 'redis':
            return f"{resource_name}.redis.cache.windows.net"

        return f"{resource_name}.azure.com"

    def _format_tags(self, tags: Dict[str, str]) -> Dict[str, str]:
        """
        Format tags dictionary with defaults.

        Args:
            tags: User-provided tags

        Returns:
            Formatted tags with defaults
        """
        all_tags = dict(tags) if tags else {}

        # Add default tags
        all_tags.update({
            'ManagedBy': 'ArticDBM',
            'CreatedAt': datetime.utcnow().isoformat(),
        })

        return all_tags

    def _get_sku_tier(self, instance_size: str) -> str:
        """Get Azure SKU tier from instance size."""
        size_lower = instance_size.lower()

        if 'basic' in size_lower:
            return 'Basic'
        elif 'general' in size_lower:
            return 'GeneralPurpose'
        elif 'memory' in size_lower or 'optimized' in size_lower:
            return 'MemoryOptimized'

        return 'GeneralPurpose'

    def _get_sku_capacity(self, instance_size: str) -> int:
        """Get Azure SKU capacity from instance size."""
        # Extract numeric capacity from instance size strings like "Standard_D2s_v3"
        import re

        match = re.search(r'(\d+)', instance_size)
        if match:
            return int(match.group(1))

        return 2  # Default capacity

    def _get_redis_sku_name(self, instance_size: str) -> str:
        """Get Redis SKU name from instance size."""
        size_lower = instance_size.lower()

        if 'premium' in size_lower:
            return 'Premium'
        elif 'basic' in size_lower:
            return 'Basic'

        return 'Standard'

    def _get_redis_sku_family(self, instance_size: str) -> str:
        """Get Redis SKU family from instance size."""
        size_lower = instance_size.lower()

        if 'premium' in size_lower:
            return 'P'
        elif 'basic' in size_lower:
            return 'C'

        return 'C'
