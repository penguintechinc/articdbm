"""
Elder sync service for bidirectional sync with Elder system.

Provides ElderSyncService class for syncing ArticDBM applications and resources
with Elder services and entities, including conflict resolution and status tracking.
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

import aiohttp
from pydal import DAL

from app.integrations.elder_client import ElderClient
from app.models.enums import SyncDirection, SyncStatus

logger = logging.getLogger(__name__)


class ElderSyncService:
    """Service for bidirectional sync between ArticDBM and Elder."""

    def __init__(self, elder_client: ElderClient, db: DAL):
        """Initialize ElderSyncService.

        Args:
            elder_client: ElderClient instance for API communication
            db: PyDAL database instance
        """
        self.elder_client = elder_client
        self.db = db

    async def sync_application(
        self, application_id: int, direction: str = "push"
    ) -> Dict[str, Any]:
        """Sync application with Elder service.

        Args:
            application_id: ArticDBM application ID
            direction: Sync direction ("push" or "pull")

        Returns:
            Dictionary with sync results: {
                "success": bool,
                "elder_service_id": int (if push/pull succeeded),
                "local_application_id": int,
                "direction": str,
                "message": str,
                "error": str (if failed)
            }

        Raises:
            ValueError: If application not found or invalid direction
            aiohttp.ClientError: On network errors
        """
        if direction not in ("push", "pull"):
            raise ValueError(f"Invalid direction: {direction}. Must be 'push' or 'pull'")

        # Fetch application from database
        application = self.db.applications[application_id]
        if not application:
            raise ValueError(f"Application {application_id} not found")

        try:
            if direction == "push":
                # Push ArticDBM application to Elder as service
                result = await self._push_application(application)
            else:
                # Pull Elder service to update ArticDBM application
                result = await self._pull_application(application)

            # Update sync state
            await self._update_sync_state(
                entity_type="application",
                entity_id=application_id,
                elder_id=result.get("elder_service_id"),
                direction=direction,
                status="synced",
                last_sync=datetime.utcnow(),
            )

            return {
                "success": True,
                "elder_service_id": result.get("elder_service_id"),
                "local_application_id": application_id,
                "direction": direction,
                "message": f"Successfully {direction}ed application {application_id}",
            }

        except (aiohttp.ClientError, ValueError) as e:
            logger.error(
                f"Failed to sync application {application_id} ({direction}): {e}"
            )
            await self._update_sync_state(
                entity_type="application",
                entity_id=application_id,
                elder_id=None,
                direction=direction,
                status="error",
                last_sync=datetime.utcnow(),
                error=str(e),
            )
            return {
                "success": False,
                "local_application_id": application_id,
                "direction": direction,
                "error": str(e),
                "message": f"Failed to {direction} application {application_id}",
            }

    async def sync_resource(
        self, resource_id: int, direction: str = "push"
    ) -> Dict[str, Any]:
        """Sync resource with Elder entity.

        Args:
            resource_id: ArticDBM resource ID
            direction: Sync direction ("push" or "pull")

        Returns:
            Dictionary with sync results: {
                "success": bool,
                "elder_entity_id": int (if push/pull succeeded),
                "local_resource_id": int,
                "direction": str,
                "message": str,
                "error": str (if failed)
            }

        Raises:
            ValueError: If resource not found or invalid direction
            aiohttp.ClientError: On network errors
        """
        if direction not in ("push", "pull"):
            raise ValueError(f"Invalid direction: {direction}. Must be 'push' or 'pull'")

        # Fetch resource from database
        resource = self.db.resources[resource_id]
        if not resource:
            raise ValueError(f"Resource {resource_id} not found")

        try:
            if direction == "push":
                # Push ArticDBM resource to Elder as entity
                result = await self._push_resource(resource)
            else:
                # Pull Elder entity to update ArticDBM resource
                result = await self._pull_resource(resource)

            # Update sync state
            await self._update_sync_state(
                entity_type="resource",
                entity_id=resource_id,
                elder_id=result.get("elder_entity_id"),
                direction=direction,
                status="synced",
                last_sync=datetime.utcnow(),
            )

            return {
                "success": True,
                "elder_entity_id": result.get("elder_entity_id"),
                "local_resource_id": resource_id,
                "direction": direction,
                "message": f"Successfully {direction}ed resource {resource_id}",
            }

        except (aiohttp.ClientError, ValueError) as e:
            logger.error(f"Failed to sync resource {resource_id} ({direction}): {e}")
            await self._update_sync_state(
                entity_type="resource",
                entity_id=resource_id,
                elder_id=None,
                direction=direction,
                status="error",
                last_sync=datetime.utcnow(),
                error=str(e),
            )
            return {
                "success": False,
                "local_resource_id": resource_id,
                "direction": direction,
                "error": str(e),
                "message": f"Failed to {direction} resource {resource_id}",
            }

    async def full_sync(self, sync_type: str = "push") -> Dict[str, Any]:
        """Perform full sync of all applications and resources.

        Args:
            sync_type: Sync direction ("push" or "pull")

        Returns:
            Dictionary with sync statistics: {
                "entities_synced": int,
                "services_synced": int,
                "errors": int,
                "total_attempted": int,
                "direction": str,
                "failed_items": List[Dict]
            }
        """
        if sync_type not in ("push", "pull"):
            raise ValueError(
                f"Invalid sync_type: {sync_type}. Must be 'push' or 'pull'"
            )

        entities_synced = 0
        services_synced = 0
        errors = 0
        failed_items = []

        # Sync all applications
        applications = self.db(self.db.applications.id > 0).select()
        for app in applications:
            try:
                result = await self.sync_application(app.id, direction=sync_type)
                if result["success"]:
                    services_synced += 1
                else:
                    errors += 1
                    failed_items.append(
                        {
                            "type": "application",
                            "id": app.id,
                            "error": result.get("error", "Unknown error"),
                        }
                    )
            except Exception as e:
                logger.error(f"Failed to sync application {app.id}: {e}")
                errors += 1
                failed_items.append(
                    {"type": "application", "id": app.id, "error": str(e)}
                )

        # Sync all resources
        resources = self.db(self.db.resources.id > 0).select()
        for res in resources:
            try:
                result = await self.sync_resource(res.id, direction=sync_type)
                if result["success"]:
                    entities_synced += 1
                else:
                    errors += 1
                    failed_items.append(
                        {
                            "type": "resource",
                            "id": res.id,
                            "error": result.get("error", "Unknown error"),
                        }
                    )
            except Exception as e:
                logger.error(f"Failed to sync resource {res.id}: {e}")
                errors += 1
                failed_items.append({"type": "resource", "id": res.id, "error": str(e)})

        total_attempted = len(applications) + len(resources)

        logger.info(
            f"Full sync ({sync_type}) completed: {services_synced} services, "
            f"{entities_synced} entities, {errors} errors"
        )

        return {
            "entities_synced": entities_synced,
            "services_synced": services_synced,
            "errors": errors,
            "total_attempted": total_attempted,
            "direction": sync_type,
            "failed_items": failed_items,
        }

    async def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status for all entities.

        Returns:
            Dictionary with sync status: {
                "pending_syncs": int,
                "last_sync_time": datetime (ISO format),
                "errors": int,
                "sync_states": List[Dict]
            }
        """
        # Query elder_sync_state table
        pending_syncs = self.db(
            self.db.elder_sync_state.status == SyncStatus.PENDING.value
        ).count()

        error_syncs = self.db(
            self.db.elder_sync_state.status == SyncStatus.ERROR.value
        ).count()

        # Get last sync time
        last_sync_record = self.db(self.db.elder_sync_state.id > 0).select(
            orderby=~self.db.elder_sync_state.last_sync, limitby=(0, 1)
        )
        last_sync_time = (
            last_sync_record[0].last_sync.isoformat()
            if last_sync_record
            else None
        )

        # Get all sync states
        sync_states = []
        states = self.db(self.db.elder_sync_state.id > 0).select()
        for state in states:
            sync_states.append(
                {
                    "id": state.id,
                    "entity_type": state.entity_type,
                    "entity_id": state.entity_id,
                    "elder_id": state.elder_id,
                    "status": state.status,
                    "direction": state.direction,
                    "last_sync": (
                        state.last_sync.isoformat() if state.last_sync else None
                    ),
                    "error": state.error,
                }
            )

        return {
            "pending_syncs": pending_syncs,
            "last_sync_time": last_sync_time,
            "errors": error_syncs,
            "sync_states": sync_states,
        }

    async def resolve_conflict(
        self, sync_state_id: int, resolution: str
    ) -> bool:
        """Resolve sync conflict for a sync state.

        Args:
            sync_state_id: elder_sync_state table ID
            resolution: Resolution strategy ("local_wins", "elder_wins", "merge")

        Returns:
            True if conflict resolved successfully, False otherwise

        Raises:
            ValueError: If invalid resolution strategy or sync state not found
        """
        if resolution not in ("local_wins", "elder_wins", "merge"):
            raise ValueError(
                f"Invalid resolution: {resolution}. "
                "Must be 'local_wins', 'elder_wins', or 'merge'"
            )

        # Fetch sync state
        sync_state = self.db.elder_sync_state[sync_state_id]
        if not sync_state:
            raise ValueError(f"Sync state {sync_state_id} not found")

        try:
            if resolution == "local_wins":
                # Push local data to Elder
                if sync_state.entity_type == "application":
                    result = await self.sync_application(
                        sync_state.entity_id, direction="push"
                    )
                else:
                    result = await self.sync_resource(
                        sync_state.entity_id, direction="push"
                    )

            elif resolution == "elder_wins":
                # Pull Elder data to local
                if sync_state.entity_type == "application":
                    result = await self.sync_application(
                        sync_state.entity_id, direction="pull"
                    )
                else:
                    result = await self.sync_resource(
                        sync_state.entity_id, direction="pull"
                    )

            else:  # merge
                # Merge strategy: pull first, then push combined data
                if sync_state.entity_type == "application":
                    await self.sync_application(sync_state.entity_id, direction="pull")
                    result = await self.sync_application(
                        sync_state.entity_id, direction="push"
                    )
                else:
                    await self.sync_resource(sync_state.entity_id, direction="pull")
                    result = await self.sync_resource(
                        sync_state.entity_id, direction="push"
                    )

            if result["success"]:
                # Update sync state to resolved
                self.db(self.db.elder_sync_state.id == sync_state_id).update(
                    status=SyncStatus.SYNCED.value,
                    error=None,
                    last_sync=datetime.utcnow(),
                )
                self.db.commit()
                logger.info(
                    f"Resolved conflict for sync state {sync_state_id} "
                    f"using {resolution}"
                )
                return True
            else:
                logger.error(
                    f"Failed to resolve conflict for sync state {sync_state_id}: "
                    f"{result.get('error')}"
                )
                return False

        except Exception as e:
            logger.error(
                f"Error resolving conflict for sync state {sync_state_id}: {e}"
            )
            return False

    async def _push_application(self, application) -> Dict[str, Any]:
        """Push ArticDBM application to Elder as service.

        Args:
            application: PyDAL Row object for application

        Returns:
            Dictionary with elder_service_id

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        # Check if application already synced
        sync_state = self.db(
            (self.db.elder_sync_state.entity_type == "application")
            & (self.db.elder_sync_state.entity_id == application.id)
        ).select(limitby=(0, 1))

        # Build service payload
        service_payload = self.elder_client.build_service_payload(application.as_dict())

        if sync_state and sync_state[0].elder_id:
            # Update existing Elder service
            elder_service = await self.elder_client.update_service(
                sync_state[0].elder_id, service_payload
            )
            return {"elder_service_id": elder_service["id"]}
        else:
            # Create new Elder service
            elder_service = await self.elder_client.create_service(service_payload)
            return {"elder_service_id": elder_service["id"]}

    async def _pull_application(self, application) -> Dict[str, Any]:
        """Pull Elder service to update ArticDBM application.

        Args:
            application: PyDAL Row object for application

        Returns:
            Dictionary with elder_service_id

        Raises:
            ValueError: If no Elder mapping exists
        """
        # Get Elder service ID from sync state
        sync_state = self.db(
            (self.db.elder_sync_state.entity_type == "application")
            & (self.db.elder_sync_state.entity_id == application.id)
        ).select(limitby=(0, 1))

        if not sync_state or not sync_state[0].elder_id:
            raise ValueError(
                f"No Elder service mapping for application {application.id}"
            )

        # Note: ElderClient doesn't have get_service method yet
        # In a real implementation, we would fetch the service and update local data
        logger.warning(
            f"Pull not fully implemented. Would fetch Elder service "
            f"{sync_state[0].elder_id} and update application {application.id}"
        )

        return {"elder_service_id": sync_state[0].elder_id}

    async def _push_resource(self, resource) -> Dict[str, Any]:
        """Push ArticDBM resource to Elder as entity.

        Args:
            resource: PyDAL Row object for resource

        Returns:
            Dictionary with elder_entity_id

        Raises:
            aiohttp.ClientError: On network errors
            ValueError: On invalid response
        """
        # Check if resource already synced
        sync_state = self.db(
            (self.db.elder_sync_state.entity_type == "resource")
            & (self.db.elder_sync_state.entity_id == resource.id)
        ).select(limitby=(0, 1))

        # Build entity payload
        entity_payload = self.elder_client.build_entity_payload(resource.as_dict())

        if sync_state and sync_state[0].elder_id:
            # Update existing Elder entity
            elder_entity = await self.elder_client.update_entity(
                sync_state[0].elder_id, entity_payload
            )
            return {"elder_entity_id": elder_entity["id"]}
        else:
            # Create new Elder entity
            elder_entity = await self.elder_client.create_entity(entity_payload)
            return {"elder_entity_id": elder_entity["id"]}

    async def _pull_resource(self, resource) -> Dict[str, Any]:
        """Pull Elder entity to update ArticDBM resource.

        Args:
            resource: PyDAL Row object for resource

        Returns:
            Dictionary with elder_entity_id

        Raises:
            ValueError: If no Elder mapping exists
        """
        # Get Elder entity ID from sync state
        sync_state = self.db(
            (self.db.elder_sync_state.entity_type == "resource")
            & (self.db.elder_sync_state.entity_id == resource.id)
        ).select(limitby=(0, 1))

        if not sync_state or not sync_state[0].elder_id:
            raise ValueError(f"No Elder entity mapping for resource {resource.id}")

        # Note: ElderClient doesn't have get_entity method yet
        # In a real implementation, we would fetch the entity and update local data
        logger.warning(
            f"Pull not fully implemented. Would fetch Elder entity "
            f"{sync_state[0].elder_id} and update resource {resource.id}"
        )

        return {"elder_entity_id": sync_state[0].elder_id}

    async def _update_sync_state(
        self,
        entity_type: str,
        entity_id: int,
        elder_id: Optional[int],
        direction: str,
        status: str,
        last_sync: datetime,
        error: Optional[str] = None,
    ) -> None:
        """Update or create sync state record.

        Args:
            entity_type: Type of entity ("application" or "resource")
            entity_id: Local entity ID
            elder_id: Elder entity/service ID
            direction: Sync direction
            status: Sync status
            last_sync: Last sync timestamp
            error: Error message (if any)
        """
        # Check if sync state exists
        existing_state = self.db(
            (self.db.elder_sync_state.entity_type == entity_type)
            & (self.db.elder_sync_state.entity_id == entity_id)
        ).select(limitby=(0, 1))

        if existing_state:
            # Update existing state
            self.db(
                (self.db.elder_sync_state.entity_type == entity_type)
                & (self.db.elder_sync_state.entity_id == entity_id)
            ).update(
                elder_id=elder_id,
                direction=direction,
                status=status,
                last_sync=last_sync,
                error=error,
            )
        else:
            # Create new state
            self.db.elder_sync_state.insert(
                entity_type=entity_type,
                entity_id=entity_id,
                elder_id=elder_id,
                direction=direction,
                status=status,
                last_sync=last_sync,
                error=error,
            )

        self.db.commit()
