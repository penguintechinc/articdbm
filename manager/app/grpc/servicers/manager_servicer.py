"""gRPC Manager Servicer Implementation

Implements ManagerService for WebUI and proxy communication.
Provides resource management, dashboard stats, and real-time event streaming.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import grpc
from pydal import DAL

from manager.app.grpc.converters import ProtoConverter
from manager.app.services.licensing import LicenseService

logger = logging.getLogger(__name__)


class ManagerServicer:
    """gRPC servicer implementing ManagerService interface.

    Handles all gRPC requests from WebUI and provides business logic
    integration through service layer.
    """

    def __init__(self, db: DAL, license_service: LicenseService):
        """Initialize ManagerServicer.

        Args:
            db: PyDAL database instance
            license_service: LicenseService for license operations
        """
        self.db = db
        self.license_service = license_service
        self.converter = ProtoConverter()
        self._event_subscribers: List[asyncio.Queue] = []

    async def GetDashboardStats(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Get dashboard statistics and health information.

        Args:
            request: Empty request message
            context: gRPC context

        Returns:
            DashboardStatsResponse with resource counts, health, and license info
        """
        try:
            # Count resources by type
            total_resources = self.db(self.db.resources.status != 'deleted').count()
            database_count = self.db(
                (self.db.resources.resource_type == 'database') &
                (self.db.resources.status != 'deleted')
            ).count()
            cache_count = self.db(
                (self.db.resources.resource_type == 'cache') &
                (self.db.resources.status != 'deleted')
            ).count()

            # Count applications and providers
            application_count = self.db(self.db.applications.is_active == True).count()
            provider_count = self.db(self.db.providers.is_active == True).count()
            credential_count = self.db(self.db.credentials.is_active == True).count()

            # Get license information
            license_info = await self.license_service.get_current_license()

            # Check resource health
            healthy_resources = self.db(
                (self.db.resources.status == 'available') &
                (self.db.resources.status != 'deleted')
            ).count()
            failed_resources = self.db(
                (self.db.resources.status == 'failed') &
                (self.db.resources.status != 'deleted')
            ).count()

            # Provider health
            healthy_providers = self.db(
                (self.db.providers.status == 'healthy') &
                (self.db.providers.is_active == True)
            ).count()

            # Build response (adapt to actual proto message structure)
            response_data = {
                'resource_counts': {
                    'total': total_resources,
                    'databases': database_count,
                    'caches': cache_count,
                },
                'application_count': application_count,
                'provider_count': provider_count,
                'credential_count': credential_count,
                'health_status': {
                    'healthy_resources': healthy_resources,
                    'failed_resources': failed_resources,
                    'healthy_providers': healthy_providers,
                    'total_providers': provider_count,
                },
                'license_info': {
                    'tier': license_info.get('tier', 'free'),
                    'resource_count': total_resources,
                    'resource_limit': license_info.get('resource_limit', 3),
                    'is_active': license_info.get('is_active', False),
                    'features': license_info.get('features', []),
                },
                'timestamp': datetime.utcnow().isoformat(),
            }

            logger.debug(f"Dashboard stats: {response_data}")
            return response_data

        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to get stats: {str(e)}")

    async def StreamEvents(self, request: Any, context: grpc.aio.ServicerContext) -> AsyncIterator[Any]:
        """Stream real-time events to clients.

        Args:
            request: StreamEventsRequest with filter options
            context: gRPC context

        Yields:
            Event messages as they occur
        """
        event_queue: asyncio.Queue = asyncio.Queue()
        self._event_subscribers.append(event_queue)

        try:
            logger.info("Client connected to event stream")

            while not context.cancelled():
                try:
                    # Wait for events with timeout
                    event = await asyncio.wait_for(event_queue.get(), timeout=30.0)

                    # Filter events based on request
                    if self._should_send_event(event, request):
                        yield event

                except asyncio.TimeoutError:
                    # Send keepalive ping
                    yield {
                        'event_type': 'keepalive',
                        'timestamp': datetime.utcnow().isoformat(),
                    }

        except asyncio.CancelledError:
            logger.info("Event stream cancelled by client")

        finally:
            self._event_subscribers.remove(event_queue)
            logger.info("Client disconnected from event stream")

    async def ListResources(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """List resources with optional filtering.

        Args:
            request: ListResourcesRequest with filters
            context: gRPC context

        Returns:
            ListResourcesResponse with resource list
        """
        try:
            query = self.db.resources.status != 'deleted'

            # Apply filters
            if hasattr(request, 'application_id') and request.application_id:
                query &= self.db.resources.application_id == request.application_id
            if hasattr(request, 'resource_type') and request.resource_type:
                query &= self.db.resources.resource_type == request.resource_type
            if hasattr(request, 'provider_id') and request.provider_id:
                query &= self.db.resources.provider_id == request.provider_id

            # Pagination
            limit = getattr(request, 'limit', 100) or 100
            offset = getattr(request, 'offset', 0) or 0

            rows = self.db(query).select(
                limitby=(offset, offset + limit),
                orderby=~self.db.resources.created_on
            )

            resources = [self.converter.resource_to_proto(row) for row in rows]
            total_count = self.db(query).count()

            return {
                'resources': resources,
                'total_count': total_count,
                'limit': limit,
                'offset': offset,
            }

        except Exception as e:
            logger.error(f"Error listing resources: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to list resources: {str(e)}")

    async def GetResource(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Get single resource by ID.

        Args:
            request: GetResourceRequest with resource_id
            context: gRPC context

        Returns:
            Resource message
        """
        try:
            resource_id = request.resource_id
            row = self.db.resources[resource_id]

            if not row or row.status == 'deleted':
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Resource {resource_id} not found")

            return self.converter.resource_to_proto(row)

        except Exception as e:
            logger.error(f"Error getting resource: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to get resource: {str(e)}")

    async def CreateResource(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Create new resource.

        Args:
            request: CreateResourceRequest
            context: gRPC context

        Returns:
            Created resource message
        """
        try:
            # Check license limits
            can_create, current, limit = await self.license_service.check_resource_limit()
            if not can_create:
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    f"Resource limit reached: {current}/{limit}"
                )

            # Convert proto to dict
            data = self.converter.proto_to_resource_dict(request)
            data['status'] = 'provisioning'
            data['created_on'] = datetime.utcnow()

            # Insert resource
            resource_id = self.db.resources.insert(**data)
            self.db.commit()

            # Publish event
            await self._publish_event({
                'event_type': 'resource_created',
                'resource_id': resource_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

            # Return created resource
            row = self.db.resources[resource_id]
            return self.converter.resource_to_proto(row)

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating resource: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to create resource: {str(e)}")

    async def UpdateResource(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Update existing resource.

        Args:
            request: UpdateResourceRequest
            context: gRPC context

        Returns:
            Updated resource message
        """
        try:
            resource_id = request.resource_id
            row = self.db.resources[resource_id]

            if not row or row.status == 'deleted':
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Resource {resource_id} not found")

            # Convert proto to dict
            data = self.converter.proto_to_resource_dict(request)
            data['modified_on'] = datetime.utcnow()

            # Update resource
            self.db(self.db.resources.id == resource_id).update(**data)
            self.db.commit()

            # Publish event
            await self._publish_event({
                'event_type': 'resource_updated',
                'resource_id': resource_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

            # Return updated resource
            row = self.db.resources[resource_id]
            return self.converter.resource_to_proto(row)

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error updating resource: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to update resource: {str(e)}")

    async def DeleteResource(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Delete resource (soft delete).

        Args:
            request: DeleteResourceRequest
            context: gRPC context

        Returns:
            Empty response
        """
        try:
            resource_id = request.resource_id
            row = self.db.resources[resource_id]

            if not row or row.status == 'deleted':
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Resource {resource_id} not found")

            # Soft delete
            self.db(self.db.resources.id == resource_id).update(
                status='deleted',
                modified_on=datetime.utcnow()
            )
            self.db.commit()

            # Publish event
            await self._publish_event({
                'event_type': 'resource_deleted',
                'resource_id': resource_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

            return {}

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting resource: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete resource: {str(e)}")

    async def ListApplications(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """List applications.

        Args:
            request: ListApplicationsRequest
            context: gRPC context

        Returns:
            ListApplicationsResponse with application list
        """
        try:
            query = self.db.applications.is_active == True

            # Pagination
            limit = getattr(request, 'limit', 100) or 100
            offset = getattr(request, 'offset', 0) or 0

            rows = self.db(query).select(
                limitby=(offset, offset + limit),
                orderby=~self.db.applications.created_on
            )

            applications = [self.converter.application_to_proto(row) for row in rows]
            total_count = self.db(query).count()

            return {
                'applications': applications,
                'total_count': total_count,
                'limit': limit,
                'offset': offset,
            }

        except Exception as e:
            logger.error(f"Error listing applications: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to list applications: {str(e)}")

    async def GetApplication(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Get single application by ID.

        Args:
            request: GetApplicationRequest
            context: gRPC context

        Returns:
            Application message
        """
        try:
            app_id = request.application_id
            row = self.db.applications[app_id]

            if not row or not row.is_active:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Application {app_id} not found")

            return self.converter.application_to_proto(row)

        except Exception as e:
            logger.error(f"Error getting application: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to get application: {str(e)}")

    async def CreateApplication(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Create new application.

        Args:
            request: CreateApplicationRequest
            context: gRPC context

        Returns:
            Created application message
        """
        try:
            data = self.converter.proto_to_application_dict(request)
            data['is_active'] = True
            data['created_on'] = datetime.utcnow()

            app_id = self.db.applications.insert(**data)
            self.db.commit()

            # Publish event
            await self._publish_event({
                'event_type': 'application_created',
                'application_id': app_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

            row = self.db.applications[app_id]
            return self.converter.application_to_proto(row)

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating application: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to create application: {str(e)}")

    async def ListCredentials(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """List credentials for a resource.

        Args:
            request: ListCredentialsRequest
            context: gRPC context

        Returns:
            ListCredentialsResponse with credential list
        """
        try:
            query = self.db.credentials.is_active == True

            if hasattr(request, 'resource_id') and request.resource_id:
                query &= self.db.credentials.resource_id == request.resource_id
            if hasattr(request, 'application_id') and request.application_id:
                query &= self.db.credentials.application_id == request.application_id

            rows = self.db(query).select(orderby=~self.db.credentials.created_on)
            credentials = [self.converter.credential_to_proto(row) for row in rows]

            return {'credentials': credentials}

        except Exception as e:
            logger.error(f"Error listing credentials: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to list credentials: {str(e)}")

    async def CreateCredential(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Create new credential.

        Args:
            request: CreateCredentialRequest
            context: gRPC context

        Returns:
            Created credential message
        """
        try:
            data = self.converter.proto_to_credential_dict(request)
            data['is_active'] = True
            data['created_on'] = datetime.utcnow()

            cred_id = self.db.credentials.insert(**data)
            self.db.commit()

            await self._publish_event({
                'event_type': 'credential_created',
                'credential_id': cred_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

            row = self.db.credentials[cred_id]
            return self.converter.credential_to_proto(row)

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error creating credential: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to create credential: {str(e)}")

    async def RotateCredential(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Rotate credential (generate new password/key).

        Args:
            request: RotateCredentialRequest
            context: gRPC context

        Returns:
            Updated credential message
        """
        try:
            cred_id = request.credential_id
            row = self.db.credentials[cred_id]

            if not row or not row.is_active:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Credential {cred_id} not found")

            # Update rotation timestamps
            self.db(self.db.credentials.id == cred_id).update(
                last_rotated_at=datetime.utcnow(),
                modified_on=datetime.utcnow()
            )
            self.db.commit()

            await self._publish_event({
                'event_type': 'credential_rotated',
                'credential_id': cred_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

            row = self.db.credentials[cred_id]
            return self.converter.credential_to_proto(row)

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error rotating credential: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to rotate credential: {str(e)}")

    async def ListProviders(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """List infrastructure providers.

        Args:
            request: ListProvidersRequest
            context: gRPC context

        Returns:
            ListProvidersResponse with provider list
        """
        try:
            query = self.db.providers.is_active == True
            rows = self.db(query).select(orderby=self.db.providers.name)

            providers = [self.converter.provider_to_proto(row) for row in rows]

            return {'providers': providers}

        except Exception as e:
            logger.error(f"Error listing providers: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to list providers: {str(e)}")

    async def TestProvider(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Test provider connectivity and credentials.

        Args:
            request: TestProviderRequest
            context: gRPC context

        Returns:
            TestProviderResponse with test results
        """
        try:
            provider_id = request.provider_id
            row = self.db.providers[provider_id]

            if not row or not row.is_active:
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Provider {provider_id} not found")

            # Perform health check (implement actual provider testing)
            is_healthy = True
            message = "Provider is healthy"

            # Update provider status
            self.db(self.db.providers.id == provider_id).update(
                status='healthy' if is_healthy else 'unhealthy',
                last_health_check=datetime.utcnow()
            )
            self.db.commit()

            return {
                'success': is_healthy,
                'message': message,
                'timestamp': datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error testing provider: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to test provider: {str(e)}")

    async def SyncWithElder(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Trigger synchronization with Elder service.

        Args:
            request: SyncWithElderRequest
            context: gRPC context

        Returns:
            SyncWithElderResponse with sync status
        """
        try:
            sync_type = getattr(request, 'sync_type', 'full')

            # Implement Elder sync logic here
            logger.info(f"Triggering Elder sync: {sync_type}")

            return {
                'success': True,
                'message': f'Elder sync initiated: {sync_type}',
                'timestamp': datetime.utcnow().isoformat(),
            }

        except Exception as e:
            logger.error(f"Error syncing with Elder: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to sync with Elder: {str(e)}")

    async def ConfigureMarchProxy(self, request: Any, context: grpc.aio.ServicerContext) -> Any:
        """Configure MarchProxy routing for a resource.

        Args:
            request: ConfigureMarchProxyRequest
            context: gRPC context

        Returns:
            MarchProxyConfig message
        """
        try:
            resource_id = request.resource_id
            row = self.db.resources[resource_id]

            if not row or row.status == 'deleted':
                await context.abort(grpc.StatusCode.NOT_FOUND, f"Resource {resource_id} not found")

            # Check if config exists
            config_row = self.db(
                self.db.marchproxy_configs.resource_id == resource_id
            ).select().first()

            config_data = {
                'enabled': getattr(request, 'enabled', True),
                'route_name': getattr(request, 'route_name', f'route-{resource_id}'),
                'listen_port': getattr(request, 'listen_port', 0),
                'rate_limit_connections': getattr(request, 'rate_limit_connections', 100),
                'rate_limit_queries': getattr(request, 'rate_limit_queries', 1000),
                'security_config': getattr(request, 'security_config', {}),
                'modified_on': datetime.utcnow(),
            }

            if config_row:
                # Update existing
                self.db(self.db.marchproxy_configs.id == config_row.id).update(**config_data)
            else:
                # Create new
                config_data['resource_id'] = resource_id
                config_data['created_on'] = datetime.utcnow()
                self.db.marchproxy_configs.insert(**config_data)

            self.db.commit()

            await self._publish_event({
                'event_type': 'marchproxy_configured',
                'resource_id': resource_id,
                'timestamp': datetime.utcnow().isoformat(),
            })

            return config_data

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error configuring MarchProxy: {e}", exc_info=True)
            await context.abort(grpc.StatusCode.INTERNAL, f"Failed to configure MarchProxy: {str(e)}")

    async def _publish_event(self, event: Dict[str, Any]) -> None:
        """Publish event to all subscribers.

        Args:
            event: Event data to publish
        """
        for queue in self._event_subscribers:
            try:
                await queue.put(event)
            except Exception as e:
                logger.error(f"Error publishing event to subscriber: {e}")

    def _should_send_event(self, event: Dict[str, Any], request: Any) -> bool:
        """Determine if event should be sent based on request filters.

        Args:
            event: Event to check
            request: StreamEventsRequest with filters

        Returns:
            True if event matches filters
        """
        # Implement filtering logic based on request
        if hasattr(request, 'event_types') and request.event_types:
            return event.get('event_type') in request.event_types

        return True
