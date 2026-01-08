"""
Resource tagging service that syncs to cloud providers.

This module provides comprehensive tag management for database resources,
including validation, storage, and synchronization with cloud provider
tag/label systems.
"""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from pydal import DAL

from .provisioning.base import BaseProvisioner, ProvisionerException


class TaggingServiceException(Exception):
    """Exception raised by TaggingService operations."""

    def __init__(
        self,
        message: str,
        resource_id: Optional[int] = None,
        original_error: Optional[Exception] = None
    ):
        """
        Initialize TaggingServiceException.

        Args:
            message: Error message
            resource_id: Resource ID if applicable
            original_error: Original exception if wrapped
        """
        self.message = message
        self.resource_id = resource_id
        self.original_error = original_error
        super().__init__(self.message)

    def __str__(self) -> str:
        """Return formatted exception string."""
        parts = [self.message]
        if self.resource_id:
            parts.append(f"Resource: {self.resource_id}")
        if self.original_error:
            parts.append(f"Original error: {str(self.original_error)}")
        return " | ".join(parts)


class TaggingService:
    """
    Service for managing resource tags and syncing to cloud providers.

    Handles tag creation, validation, storage, and synchronization with
    cloud provider tagging systems (AWS tags, GCP labels, Azure tags, etc.).

    Attributes:
        db: PyDAL database instance
        provisioner_registry: Dictionary mapping provider types to provisioner instances
    """

    # Tag key validation pattern: alphanumeric, dashes, underscores
    TAG_KEY_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]+$')

    # Maximum tag key length
    MAX_TAG_KEY_LENGTH = 128

    # Maximum tag value length
    MAX_TAG_VALUE_LENGTH = 256

    def __init__(self, db: DAL, provisioner_registry: Dict[str, BaseProvisioner]):
        """
        Initialize TaggingService.

        Args:
            db: PyDAL database instance
            provisioner_registry: Dictionary mapping provider types to provisioner instances

        Raises:
            ValueError: If db or provisioner_registry is invalid
        """
        if not db:
            raise ValueError("Database instance (db) is required")
        if not isinstance(provisioner_registry, dict):
            raise ValueError("provisioner_registry must be a dictionary")

        self.db = db
        self.provisioner_registry = provisioner_registry

    async def add_tags(self, resource_id: int, tags: Dict[str, str]) -> Dict[str, Any]:
        """
        Add tags to a resource and sync to provider.

        Args:
            resource_id: ID of the resource to tag
            tags: Dictionary of tag key-value pairs to add

        Returns:
            Dictionary containing:
                - resource_id: Resource ID
                - tags_added: Number of tags added
                - tags_synced: Number of tags synced to provider
                - synced_tags: Dictionary of synced tags

        Raises:
            TaggingServiceException: If operation fails
        """
        if not isinstance(resource_id, int) or resource_id <= 0:
            raise TaggingServiceException(
                "resource_id must be a positive integer",
                resource_id=resource_id
            )

        if not isinstance(tags, dict):
            raise TaggingServiceException(
                "tags must be a dictionary",
                resource_id=resource_id
            )

        # Validate all tag keys and values
        for key, value in tags.items():
            if not await self.validate_tag_key(key):
                raise TaggingServiceException(
                    f"Invalid tag key: {key}",
                    resource_id=resource_id
                )
            if not await self.validate_tag_value(str(value)):
                raise TaggingServiceException(
                    f"Invalid tag value for key {key}: {value}",
                    resource_id=resource_id
                )

        try:
            # Verify resource exists
            resource = self.db.resources[resource_id]
            if not resource:
                raise TaggingServiceException(
                    f"Resource not found: {resource_id}",
                    resource_id=resource_id
                )

            tags_added = 0
            synced_tags = {}

            # Add each tag
            for key, value in tags.items():
                # Check if tag already exists
                existing = self.db(
                    (self.db.resource_tags.resource_id == resource_id) &
                    (self.db.resource_tags.key == key)
                ).select().first()

                if existing:
                    # Update existing tag
                    existing.update_record(
                        value=str(value),
                        synced_to_provider=False,
                        modified_on=datetime.utcnow()
                    )
                else:
                    # Create new tag
                    self.db.resource_tags.insert(
                        resource_id=resource_id,
                        key=key,
                        value=str(value),
                        synced_to_provider=False
                    )
                    tags_added += 1

            self.db.commit()

            # Sync tags to provider
            sync_result = await self.sync_tags_to_provider(resource_id)

            if sync_result:
                # Fetch synced tags
                synced = self.db(
                    self.db.resource_tags.resource_id == resource_id
                ).select()
                synced_tags = {row.key: row.value for row in synced}

            return {
                'resource_id': resource_id,
                'tags_added': tags_added,
                'tags_synced': len(synced_tags),
                'synced_tags': synced_tags
            }

        except TaggingServiceException:
            raise
        except Exception as e:
            raise TaggingServiceException(
                f"Failed to add tags: {str(e)}",
                resource_id=resource_id,
                original_error=e
            )

    async def remove_tag(self, resource_id: int, key: str) -> bool:
        """
        Remove a tag from a resource and sync to provider.

        Args:
            resource_id: ID of the resource
            key: Tag key to remove

        Returns:
            True if tag was removed and synced, False otherwise

        Raises:
            TaggingServiceException: If operation fails
        """
        if not isinstance(resource_id, int) or resource_id <= 0:
            raise TaggingServiceException(
                "resource_id must be a positive integer",
                resource_id=resource_id
            )

        if not isinstance(key, str) or not key:
            raise TaggingServiceException(
                "key must be a non-empty string",
                resource_id=resource_id
            )

        try:
            # Find and delete the tag
            tag = self.db(
                (self.db.resource_tags.resource_id == resource_id) &
                (self.db.resource_tags.key == key)
            ).select().first()

            if not tag:
                return False

            tag_id = tag.id
            self.db.resource_tags[tag_id].delete_record()
            self.db.commit()

            # Sync remaining tags to provider
            await self.sync_tags_to_provider(resource_id)

            return True

        except Exception as e:
            raise TaggingServiceException(
                f"Failed to remove tag: {str(e)}",
                resource_id=resource_id,
                original_error=e
            )

    async def get_tags(self, resource_id: int) -> Dict[str, str]:
        """
        Get all tags for a resource.

        Args:
            resource_id: ID of the resource

        Returns:
            Dictionary of tag key-value pairs

        Raises:
            TaggingServiceException: If resource not found
        """
        if not isinstance(resource_id, int) or resource_id <= 0:
            raise TaggingServiceException(
                "resource_id must be a positive integer",
                resource_id=resource_id
            )

        try:
            # Verify resource exists
            resource = self.db.resources[resource_id]
            if not resource:
                raise TaggingServiceException(
                    f"Resource not found: {resource_id}",
                    resource_id=resource_id
                )

            tags = self.db(
                self.db.resource_tags.resource_id == resource_id
            ).select()

            return {row.key: row.value for row in tags}

        except TaggingServiceException:
            raise
        except Exception as e:
            raise TaggingServiceException(
                f"Failed to retrieve tags: {str(e)}",
                resource_id=resource_id,
                original_error=e
            )

    async def sync_tags_to_provider(self, resource_id: int) -> bool:
        """
        Sync a resource's tags to its cloud provider.

        Args:
            resource_id: ID of the resource to sync

        Returns:
            True if sync successful, False otherwise

        Raises:
            TaggingServiceException: If operation fails
        """
        if not isinstance(resource_id, int) or resource_id <= 0:
            raise TaggingServiceException(
                "resource_id must be a positive integer",
                resource_id=resource_id
            )

        try:
            # Get resource and its provider
            resource = self.db.resources[resource_id]
            if not resource:
                raise TaggingServiceException(
                    f"Resource not found: {resource_id}",
                    resource_id=resource_id
                )

            provider = self.db.providers[resource.provider_id]
            if not provider:
                raise TaggingServiceException(
                    f"Provider not found for resource: {resource_id}",
                    resource_id=resource_id
                )

            # Get provisioner for this provider type
            provisioner = self.provisioner_registry.get(provider.provider_type)
            if not provisioner:
                raise TaggingServiceException(
                    f"No provisioner available for type: {provider.provider_type}",
                    resource_id=resource_id
                )

            # Get resource's tags
            tags = await self.get_tags(resource_id)
            if not tags:
                # No tags to sync, mark all as synced anyway
                self.db(
                    self.db.resource_tags.resource_id == resource_id
                ).update(
                    synced_to_provider=True,
                    last_synced=datetime.utcnow()
                )
                self.db.commit()
                return True

            # Call provisioner to sync tags
            provider_resource_id = resource.provider_resource_id
            if not provider_resource_id:
                raise TaggingServiceException(
                    f"Resource has no provider_resource_id: {resource_id}",
                    resource_id=resource_id
                )

            sync_success = await provisioner.sync_tags(
                provider_resource_id,
                tags
            )

            if sync_success:
                # Update all tags as synced
                self.db(
                    self.db.resource_tags.resource_id == resource_id
                ).update(
                    synced_to_provider=True,
                    last_synced=datetime.utcnow()
                )
                self.db.commit()
                return True
            else:
                return False

        except TaggingServiceException:
            raise
        except ProvisionerException as e:
            raise TaggingServiceException(
                f"Provisioner error during tag sync: {str(e)}",
                resource_id=resource_id,
                original_error=e
            )
        except Exception as e:
            raise TaggingServiceException(
                f"Failed to sync tags to provider: {str(e)}",
                resource_id=resource_id,
                original_error=e
            )

    async def sync_all_pending(self) -> Dict[str, Any]:
        """
        Sync all pending tags across all resources.

        Finds tags where synced_to_provider=False and attempts to sync
        each to its respective cloud provider.

        Returns:
            Dictionary containing:
                - total_resources: Total resources with pending tags
                - synced_count: Number of resources successfully synced
                - failed_count: Number of resources that failed to sync
                - failed_resources: List of resource IDs that failed

        Raises:
            TaggingServiceException: If operation fails
        """
        try:
            # Find all resources with pending tags
            pending_tags = self.db(
                self.db.resource_tags.synced_to_provider == False
            ).select()

            if not pending_tags:
                return {
                    'total_resources': 0,
                    'synced_count': 0,
                    'failed_count': 0,
                    'failed_resources': []
                }

            # Get unique resource IDs
            resource_ids = set()
            for tag in pending_tags:
                resource_ids.add(tag.resource_id)

            synced_count = 0
            failed_count = 0
            failed_resources = []

            # Sync tags for each resource
            for resource_id in resource_ids:
                try:
                    success = await self.sync_tags_to_provider(resource_id)
                    if success:
                        synced_count += 1
                    else:
                        failed_count += 1
                        failed_resources.append(resource_id)
                except Exception as e:
                    failed_count += 1
                    failed_resources.append(resource_id)

            return {
                'total_resources': len(resource_ids),
                'synced_count': synced_count,
                'failed_count': failed_count,
                'failed_resources': failed_resources
            }

        except Exception as e:
            raise TaggingServiceException(
                f"Failed to sync pending tags: {str(e)}",
                original_error=e
            )

    async def validate_tag_key(self, key: str) -> bool:
        """
        Validate tag key format.

        Tag keys must:
        - Be non-empty
        - Be at most 128 characters
        - Contain only alphanumeric characters, dashes, and underscores

        Args:
            key: Tag key to validate

        Returns:
            True if key is valid, False otherwise
        """
        if not isinstance(key, str):
            return False

        if not key or len(key) == 0:
            return False

        if len(key) > self.MAX_TAG_KEY_LENGTH:
            return False

        return bool(self.TAG_KEY_PATTERN.match(key))

    async def validate_tag_value(self, value: str) -> bool:
        """
        Validate tag value format.

        Tag values must:
        - Be a string
        - Be at most 256 characters
        - Not be empty or None

        Args:
            value: Tag value to validate

        Returns:
            True if value is valid, False otherwise
        """
        if not isinstance(value, str):
            return False

        if len(value) == 0:
            return False

        if len(value) > self.MAX_TAG_VALUE_LENGTH:
            return False

        return True
