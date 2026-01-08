"""
Elder API client for syncing with Elder infrastructure management system.

Provides async methods for creating and managing services/entities in Elder,
as well as bidirectional sync between ArticDBM and Elder.
"""

import asyncio
import logging
from typing import Any, Dict, Optional

import aiohttp

logger = logging.getLogger(__name__)


class ElderClient:
    """Client for interacting with Elder infrastructure management API."""

    def __init__(self, base_url: str, api_key: str):
        """Initialize ElderClient.

        Args:
            base_url: Base URL of Elder API (e.g., http://localhost:8000)
            api_key: API key for Elder authentication
        """
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

    async def create_service(self, service_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new service in Elder.

        Args:
            service_data: Service payload dictionary

        Returns:
            Created service data with ID

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/services"
                async with session.post(
                    url,
                    json=service_data,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 201:
                        data = await response.json()
                        logger.info(f"Created Elder service: {data.get('id')}")
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to create Elder service: {response.status} - {error_text}"
                        )
                        raise ValueError(
                            f"Service creation failed: {response.status}"
                        )

        except aiohttp.ClientError as e:
            logger.error(f"Network error creating Elder service: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Elder service creation timed out")
            raise aiohttp.ClientError("Request timeout") from e

    async def update_service(
        self, service_id: int, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update an existing service in Elder.

        Args:
            service_id: Elder service ID
            data: Updated service data

        Returns:
            Updated service data

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/services/{service_id}"
                async with session.put(
                    url,
                    json=data,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Updated Elder service: {service_id}")
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to update Elder service {service_id}: {response.status} - {error_text}"
                        )
                        raise ValueError(
                            f"Service update failed: {response.status}"
                        )

        except aiohttp.ClientError as e:
            logger.error(f"Network error updating Elder service: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Elder service update timed out")
            raise aiohttp.ClientError("Request timeout") from e

    async def delete_service(self, service_id: int) -> bool:
        """Delete a service from Elder.

        Args:
            service_id: Elder service ID to delete

        Returns:
            True if deletion was successful

        Raises:
            aiohttp.ClientError: On network errors
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/services/{service_id}"
                async with session.delete(
                    url,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status in (200, 204):
                        logger.info(f"Deleted Elder service: {service_id}")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to delete Elder service {service_id}: {response.status} - {error_text}"
                        )
                        return False

        except aiohttp.ClientError as e:
            logger.error(f"Network error deleting Elder service: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Elder service deletion timed out")
            raise aiohttp.ClientError("Request timeout") from e

    async def create_entity(self, entity_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new entity in Elder (STORAGE/DATABASE type).

        Args:
            entity_data: Entity payload dictionary

        Returns:
            Created entity data with ID

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/entities"
                async with session.post(
                    url,
                    json=entity_data,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 201:
                        data = await response.json()
                        logger.info(f"Created Elder entity: {data.get('id')}")
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to create Elder entity: {response.status} - {error_text}"
                        )
                        raise ValueError(
                            f"Entity creation failed: {response.status}"
                        )

        except aiohttp.ClientError as e:
            logger.error(f"Network error creating Elder entity: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Elder entity creation timed out")
            raise aiohttp.ClientError("Request timeout") from e

    async def update_entity(
        self, entity_id: int, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update an existing entity in Elder.

        Args:
            entity_id: Elder entity ID
            data: Updated entity data

        Returns:
            Updated entity data

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/entities/{entity_id}"
                async with session.put(
                    url,
                    json=data,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Updated Elder entity: {entity_id}")
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to update Elder entity {entity_id}: {response.status} - {error_text}"
                        )
                        raise ValueError(
                            f"Entity update failed: {response.status}"
                        )

        except aiohttp.ClientError as e:
            logger.error(f"Network error updating Elder entity: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Elder entity update timed out")
            raise aiohttp.ClientError("Request timeout") from e

    async def delete_entity(self, entity_id: int) -> bool:
        """Delete an entity from Elder.

        Args:
            entity_id: Elder entity ID to delete

        Returns:
            True if deletion was successful

        Raises:
            aiohttp.ClientError: On network errors
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/entities/{entity_id}"
                async with session.delete(
                    url,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status in (200, 204):
                        logger.info(f"Deleted Elder entity: {entity_id}")
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to delete Elder entity {entity_id}: {response.status} - {error_text}"
                        )
                        return False

        except aiohttp.ClientError as e:
            logger.error(f"Network error deleting Elder entity: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Elder entity deletion timed out")
            raise aiohttp.ClientError("Request timeout") from e

    async def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status from Elder.

        Returns:
            Dictionary with sync status information

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/sync/status"
                async with session.get(
                    url,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.debug("Retrieved Elder sync status")
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to get Elder sync status: {response.status} - {error_text}"
                        )
                        raise ValueError(
                            f"Sync status retrieval failed: {response.status}"
                        )

        except aiohttp.ClientError as e:
            logger.error(f"Network error getting Elder sync status: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Elder sync status request timed out")
            raise aiohttp.ClientError("Request timeout") from e

    async def sync_mapping(
        self,
        local_type: str,
        local_id: int,
        elder_type: str,
        elder_id: int,
    ) -> Dict[str, Any]:
        """Create or update sync mapping between local and Elder entities.

        Args:
            local_type: Type of local entity (application, resource, etc.)
            local_id: Local entity ID
            elder_type: Type of Elder entity (service, entity)
            elder_id: Elder entity ID

        Returns:
            Sync mapping data

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        try:
            payload = {
                "local_type": local_type,
                "local_id": local_id,
                "elder_type": elder_type,
                "elder_id": elder_id,
            }

            async with aiohttp.ClientSession() as session:
                url = f"{self.base_url}/api/v1/sync/mapping"
                async with session.post(
                    url,
                    json=payload,
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status in (200, 201):
                        data = await response.json()
                        logger.info(
                            f"Created sync mapping: {local_type}/{local_id} -> {elder_type}/{elder_id}"
                        )
                        return data
                    else:
                        error_text = await response.text()
                        logger.error(
                            f"Failed to create sync mapping: {response.status} - {error_text}"
                        )
                        raise ValueError(
                            f"Sync mapping failed: {response.status}"
                        )

        except aiohttp.ClientError as e:
            logger.error(f"Network error creating sync mapping: {e}")
            raise
        except asyncio.TimeoutError as e:
            logger.error("Sync mapping creation timed out")
            raise aiohttp.ClientError("Request timeout") from e

    def build_service_payload(self, application: Dict[str, Any]) -> Dict[str, Any]:
        """Convert ArticDBM Application to Elder Service format.

        Args:
            application: ArticDBM application record

        Returns:
            Elder service payload dictionary
        """
        return {
            "name": application.get("name"),
            "description": application.get("description", ""),
            "service_type": "database_proxy",
            "deployment_model": application.get("deployment_model", "shared"),
            "status": "active" if application.get("is_active") else "inactive",
            "tags": application.get("tags", {}),
            "metadata": {
                "articdbm_id": application.get("id"),
                "organization_id": application.get("organization_id"),
                "created_on": application.get("created_on"),
            },
        }

    def build_entity_payload(self, resource: Dict[str, Any]) -> Dict[str, Any]:
        """Convert ArticDBM Resource to Elder Entity format.

        Args:
            resource: ArticDBM resource record

        Returns:
            Elder entity payload dictionary with STORAGE type, DATABASE sub_type
        """
        return {
            "name": resource.get("name"),
            "entity_type": "STORAGE",
            "sub_type": "DATABASE",
            "provider": resource.get("provider_id"),
            "status": resource.get("status", "unknown"),
            "configuration": {
                "engine": resource.get("engine"),
                "engine_version": resource.get("engine_version"),
                "endpoint": resource.get("endpoint"),
                "port": resource.get("port"),
                "database_name": resource.get("database_name"),
                "instance_class": resource.get("instance_class"),
                "storage_size_gb": resource.get("storage_size_gb"),
                "multi_az": resource.get("multi_az", False),
                "replicas": resource.get("replicas", 0),
                "tls_mode": resource.get("tls_mode", "required"),
            },
            "tags": resource.get("tags", {}),
            "metadata": {
                "articdbm_id": resource.get("id"),
                "application_id": resource.get("application_id"),
                "cluster_id": resource.get("cluster_id"),
                "provider_resource_id": resource.get("provider_resource_id"),
                "created_on": resource.get("created_on"),
            },
        }
