"""
Vultr provisioner for ArticDBM.

Implements managed database provisioning using Vultr Managed Databases:
- PostgreSQL
- MySQL
- Redis

Copyright (c) 2025 Penguin Tech Inc
Licensed under Limited AGPL3
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from .base import BaseProvisioner, ProvisionerConfig, ProvisionerException, ResourceConfig

logger = logging.getLogger(__name__)


class VultrProvisioner(BaseProvisioner):
    """Vultr cloud provisioner for Managed Databases."""

    BASE_URL = "https://api.vultr.com/v2"

    # Map ArticDBM resource types to Vultr engine types
    ENGINE_MAPPING = {
        "postgresql": "postgresql",
        "mysql": "mysql",
        "redis": "redis",
    }

    # Map instance sizes to Vultr plan IDs
    SIZE_MAPPING = {
        "small": "vultr.dbaas.starter",
        "medium": "vultr.dbaas.regular",
        "large": "vultr.dbaas.dedicated",
    }

    def __init__(self, config: ProvisionerConfig):
        """
        Initialize Vultr provisioner.

        Args:
            config: Provisioner configuration containing:
                - credentials: Dict with 'api_key'
                - region: Vultr region slug (e.g., 'ewr', 'sjc')
                - timeout: Request timeout in seconds (default: 300)
                - retry_attempts: Number of retries (default: 3)
        """
        super().__init__(config)

        if not HTTPX_AVAILABLE and not REQUESTS_AVAILABLE:
            raise ProvisionerException(
                "httpx or requests library not installed",
                provider="vultr"
            )

        self.api_key = config.credentials.get("api_key")
        self.region = config.region or "ewr"
        self.timeout = config.timeout or 300
        self.retry_attempts = config.retry_attempts or 3

        if not self.api_key:
            raise ProvisionerException(
                "Missing required Vultr configuration: api_key",
                provider="vultr"
            )

        self.session = None
        self._initialized = True

    def _get_session(self):
        """Get or create HTTP session."""
        if HTTPX_AVAILABLE:
            if self.session is None:
                self.session = httpx.Client(
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=self.timeout,
                )
            return self.session
        else:
            return None

    def _make_request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Make HTTP request to Vultr API.

        Args:
            method: HTTP method (GET, POST, DELETE, PATCH)
            endpoint: API endpoint path
            json_data: JSON body for POST/PATCH requests
            params: Query parameters

        Returns:
            JSON response as dictionary

        Raises:
            ProvisionerException: If request fails
        """
        url = f"{self.BASE_URL}{endpoint}"
        headers = {"Authorization": f"Bearer {self.api_key}"}

        try:
            if HTTPX_AVAILABLE:
                client = httpx.Client(headers=headers, timeout=self.timeout)
                response = client.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                )
                client.close()
            else:
                response = requests.request(
                    method=method,
                    url=url,
                    json=json_data,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )

            response.raise_for_status()
            return response.json() if response.text else {}

        except Exception as e:
            logger.error(f"Vultr API request failed: {str(e)}")
            raise ProvisionerException(
                f"Vultr API request failed: {str(e)}",
                provider="vultr",
                original_error=e,
            )

    async def create_resource(self, resource_config: ResourceConfig) -> Dict[str, Any]:
        """
        Create a Vultr Managed Database.

        Args:
            resource_config: Configuration for the database resource

        Returns:
            Dictionary containing:
                - provider_resource_id: Database cluster ID
                - endpoint: Database hostname
                - port: Database port
                - status: Current status
                - created_at: Creation timestamp
                - metadata: Additional database information

        Raises:
            ProvisionerException: If creation fails
        """
        try:
            # Validate resource type
            resource_type = resource_config.resource_type.lower()
            if resource_type not in self.ENGINE_MAPPING:
                raise ProvisionerException(
                    f"Unsupported resource type: {resource_type}",
                    provider="vultr",
                )

            engine = self.ENGINE_MAPPING[resource_type]
            plan = self.SIZE_MAPPING.get(resource_config.instance_size, "vultr.dbaas.starter")

            # Prepare database configuration
            payload = {
                "cluster_name": resource_config.name,
                "region": self.config.region or "ewr",
                "engine": engine,
                "plan": plan,
                "database_engine": f"{engine}:latest",
                "tag": resource_config.labels.get("environment", "production"),
            }

            # Add database-specific configuration
            if resource_config.database_config:
                if "db_name" in resource_config.database_config:
                    payload["database"] = resource_config.database_config["db_name"]
                if "admin_user" in resource_config.database_config:
                    payload["admin_user"] = resource_config.database_config["admin_user"]

            # Add backup configuration
            if resource_config.backup_enabled:
                payload["backup_retention"] = resource_config.backup_retention_days

            # Create the database cluster
            response = self._make_request("POST", "/databases", json_data=payload)

            if "database" not in response:
                raise ProvisionerException(
                    "Invalid Vultr API response: missing database object",
                    provider="vultr",
                )

            db = response["database"]

            result = {
                "provider_resource_id": db["id"],
                "endpoint": db.get("host", ""),
                "port": db.get("port", self._get_default_port(engine)),
                "status": db.get("status", "pending"),
                "created_at": datetime.utcnow().isoformat(),
                "metadata": {
                    "engine": engine,
                    "region": db.get("region", self.config.region),
                    "plan": plan,
                    "replicas": resource_config.replicas,
                    "storage_gb": resource_config.storage_size_gb,
                    "backup_enabled": resource_config.backup_enabled,
                },
            }

            logger.info(f"Created Vultr database: {db['id']}")
            return result

        except ProvisionerException:
            raise
        except Exception as e:
            logger.error(f"Failed to create Vultr database: {str(e)}")
            raise ProvisionerException(
                f"Failed to create Vultr database: {str(e)}",
                provider="vultr",
                original_error=e,
            )

    async def update_resource(
        self,
        resource_id: str,
        updates: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Update a Vultr Managed Database.

        Args:
            resource_id: Database cluster ID
            updates: Dictionary of fields to update (plan, storage, etc.)

        Returns:
            Dictionary containing updated resource state

        Raises:
            ProvisionerException: If update fails
        """
        try:
            payload = {}

            if "instance_size" in updates:
                payload["plan"] = self.SIZE_MAPPING.get(
                    updates["instance_size"],
                    "vultr.dbaas.starter",
                )

            if "storage_size_gb" in updates:
                payload["storage_gb"] = updates["storage_size_gb"]

            if "backup_retention_days" in updates:
                payload["backup_retention"] = updates["backup_retention_days"]

            if not payload:
                raise ProvisionerException(
                    "No valid update fields provided",
                    provider="vultr",
                    resource_id=resource_id,
                )

            response = self._make_request(
                "PATCH",
                f"/databases/{resource_id}",
                json_data=payload,
            )

            if "database" not in response:
                raise ProvisionerException(
                    "Invalid Vultr API response: missing database object",
                    provider="vultr",
                    resource_id=resource_id,
                )

            db = response["database"]

            result = {
                "provider_resource_id": db["id"],
                "status": db.get("status", "updating"),
                "updated_at": datetime.utcnow().isoformat(),
                "metadata": {
                    "plan": db.get("plan", ""),
                    "storage_gb": db.get("storage_gb", 0),
                },
            }

            logger.info(f"Updated Vultr database: {resource_id}")
            return result

        except ProvisionerException:
            raise
        except Exception as e:
            logger.error(f"Failed to update Vultr database {resource_id}: {str(e)}")
            raise ProvisionerException(
                f"Failed to update Vultr database: {str(e)}",
                provider="vultr",
                resource_id=resource_id,
                original_error=e,
            )

    async def delete_resource(self, resource_id: str) -> bool:
        """
        Delete a Vultr Managed Database.

        Args:
            resource_id: Database cluster ID

        Returns:
            True if deletion successful, False otherwise

        Raises:
            ProvisionerException: If deletion fails
        """
        try:
            self._make_request("DELETE", f"/databases/{resource_id}")
            logger.info(f"Deleted Vultr database: {resource_id}")
            return True

        except ProvisionerException as e:
            # 404 means already deleted
            if "404" in str(e):
                return True
            raise

        except Exception as e:
            logger.error(f"Failed to delete Vultr database {resource_id}: {str(e)}")
            raise ProvisionerException(
                f"Failed to delete Vultr database: {str(e)}",
                provider="vultr",
                resource_id=resource_id,
                original_error=e,
            )

    async def get_resource_status(self, resource_id: str) -> Dict[str, Any]:
        """
        Get status and details of a Vultr Managed Database.

        Args:
            resource_id: Database cluster ID

        Returns:
            Dictionary containing:
                - provider_resource_id: Database ID
                - status: Current status (pending, running, error, etc.)
                - health: Health status (healthy, degraded, unhealthy)
                - endpoint: Database hostname
                - port: Database port
                - replicas: Current replica count
                - last_updated: Last status update timestamp
                - metadata: Additional provider-specific metadata

        Raises:
            ProvisionerException: If status retrieval fails
        """
        try:
            response = self._make_request("GET", f"/databases/{resource_id}")

            if "database" not in response:
                raise ProvisionerException(
                    "Invalid Vultr API response: missing database object",
                    provider="vultr",
                    resource_id=resource_id,
                )

            db = response["database"]

            # Determine health status based on database status
            health = self._determine_health(db.get("status", "unknown"))

            result = {
                "provider_resource_id": db["id"],
                "status": db.get("status", "unknown"),
                "health": health,
                "endpoint": db.get("host", ""),
                "port": db.get("port", 5432),
                "replicas": len(db.get("read_replicas", [])),
                "last_updated": datetime.utcnow().isoformat(),
                "metadata": {
                    "engine": db.get("engine", ""),
                    "region": db.get("region", ""),
                    "plan": db.get("plan", ""),
                    "storage_gb": db.get("storage_gb", 0),
                    "read_replicas": db.get("read_replicas", []),
                },
            }

            return result

        except ProvisionerException:
            raise
        except Exception as e:
            logger.error(f"Failed to get status for Vultr database {resource_id}: {str(e)}")
            raise ProvisionerException(
                f"Failed to get database status: {str(e)}",
                provider="vultr",
                resource_id=resource_id,
                original_error=e,
            )

    async def scale_resource(
        self,
        resource_id: str,
        scale_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Scale a Vultr Managed Database.

        Args:
            resource_id: Database cluster ID
            scale_config: Scaling configuration containing:
                - instance_size: New instance size (optional)
                - storage_size_gb: New storage size (optional)

        Returns:
            Dictionary containing updated resource state

        Raises:
            ProvisionerException: If scaling fails
        """
        return await self.update_resource(resource_id, scale_config)

    async def get_metrics(
        self,
        resource_id: str,
        metric_name: str,
        start: datetime,
        end: datetime,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve metrics for a Vultr Managed Database.

        Args:
            resource_id: Database cluster ID
            metric_name: Name of metric (cpu, memory, connections, etc.)
            start: Start timestamp for metric data
            end: End timestamp for metric data

        Returns:
            List of metric data points containing:
                - timestamp: Data point timestamp
                - value: Metric value
                - unit: Metric unit

        Raises:
            ProvisionerException: If metric retrieval fails
        """
        try:
            # Vultr doesn't provide direct metrics API for databases
            # This is a placeholder for the interface requirement
            logger.info(
                f"Metrics for {resource_id} ({metric_name}) from {start} to {end}"
            )

            return [
                {
                    "timestamp": start.isoformat(),
                    "value": 0.0,
                    "unit": "percent",
                }
            ]

        except Exception as e:
            logger.error(f"Failed to get metrics for Vultr database {resource_id}: {str(e)}")
            raise ProvisionerException(
                f"Failed to retrieve metrics: {str(e)}",
                provider="vultr",
                resource_id=resource_id,
                original_error=e,
            )

    async def test_connection(self) -> Tuple[bool, str]:
        """
        Test connectivity to Vultr API.

        Returns:
            Tuple of (success, message):
                - success: True if connection successful
                - message: Human-readable status message

        Raises:
            ProvisionerException: If connection test encounters critical error
        """
        try:
            response = self._make_request("GET", "/account")

            if "account" in response:
                return (True, "Successfully connected to Vultr API")
            else:
                return (False, "Unexpected response from Vultr API")

        except Exception as e:
            logger.error(f"Vultr API connection test failed: {str(e)}")
            return (False, f"Connection test failed: {str(e)}")

    async def sync_tags(self, resource_id: str, tags: Dict[str, str]) -> bool:
        """
        Synchronize tags/labels on a Vultr Managed Database.

        Args:
            resource_id: Database cluster ID
            tags: Dictionary of tags to apply

        Returns:
            True if tag synchronization successful, False otherwise

        Raises:
            ProvisionerException: If tag synchronization fails
        """
        try:
            if not tags:
                return True

            # Vultr uses single 'tag' field, use first tag key-value pair
            tag_key = list(tags.keys())[0] if tags else ""
            tag_value = tags.get(tag_key, "") if tag_key else ""
            tag_str = f"{tag_key}:{tag_value}" if tag_key else ""

            payload = {"tag": tag_str}

            response = self._make_request(
                "PATCH",
                f"/databases/{resource_id}",
                json_data=payload,
            )

            if "database" in response:
                logger.info(f"Synced tags for Vultr database: {resource_id}")
                return True
            else:
                logger.warning(f"Unexpected response syncing tags for {resource_id}")
                return False

        except Exception as e:
            logger.error(f"Failed to sync tags for Vultr database {resource_id}: {str(e)}")
            raise ProvisionerException(
                f"Failed to sync tags: {str(e)}",
                provider="vultr",
                resource_id=resource_id,
                original_error=e,
            )

    @staticmethod
    def _get_default_port(engine: str) -> int:
        """Get default port for database engine."""
        port_map = {
            "postgresql": 5432,
            "mysql": 3306,
            "redis": 6379,
        }
        return port_map.get(engine, 5432)

    @staticmethod
    def _determine_health(status: str) -> str:
        """Determine health status from database status."""
        if status in ("running", "active"):
            return "healthy"
        elif status in ("updating", "pending", "provisioning"):
            return "degraded"
        else:
            return "unhealthy"
