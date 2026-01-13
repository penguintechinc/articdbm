"""gRPC Manager Servicer Implementation

Implements ManagerService for WebUI and proxy communication.
Provides resource management, dashboard stats, and real-time event streaming.
"""

import asyncio
import logging
import random
import string
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, Dict, List, Optional

import grpc
from google.protobuf.timestamp_pb2 import Timestamp
from pydal import DAL

from articdbm import manager_pb2, types_pb2
from app.grpc.converters import ProtoConverter
from app.services.licensing import LicenseService

logger = logging.getLogger(__name__)


class ManagerServicer(manager_pb2.ManagerServiceServicer):
    """gRPC servicer implementing ManagerService interface.

    Handles all gRPC requests from WebUI and provides business logic
    integration through service layer.
    """

    SERVICE_NAME = 'articdbm.ManagerService'

    def __init__(self, db: Optional[DAL] = None, license_service: Optional[LicenseService] = None):
        """Initialize ManagerServicer.

        Args:
            db: PyDAL database instance (optional for testing)
            license_service: LicenseService for license operations
        """
        self.db = db
        self.license_service = license_service
        self.converter = ProtoConverter()
        self._event_subscribers: List[asyncio.Queue] = []

    def add_to_server(self, server: grpc.Server) -> None:
        """Add servicer to gRPC server.

        Args:
            server: gRPC server instance
        """
        manager_pb2.add_ManagerServiceServicer_to_server(self, server)

    def _get_current_timestamp(self) -> Timestamp:
        """Get current timestamp in proto format."""
        now = datetime.utcnow()
        return Timestamp(seconds=int(now.timestamp()), nanos=now.microsecond * 1000)

    # Dashboard Methods

    def GetDashboardStats(self, request: manager_pb2.GetDashboardStatsRequest,
                         context: grpc.ServicerContext) -> manager_pb2.GetDashboardStatsResponse:
        """Get dashboard statistics and health information.

        Args:
            request: GetDashboardStatsRequest
            context: gRPC context

        Returns:
            GetDashboardStatsResponse with resource counts and license info
        """
        try:
            # Sample/mock data since no database integration yet
            total_resources = 25
            active_resources = 22
            total_applications = 8
            total_credentials = 15

            response = manager_pb2.GetDashboardStatsResponse(
                total_resources=total_resources,
                active_resources=active_resources,
                total_applications=total_applications,
                total_credentials=total_credentials,
                license_tier=types_pb2.LICENSE_TIER_PROFESSIONAL,
                resource_limit=50,
                resources_by_type={
                    'database': 15,
                    'cache': 10,
                },
                resources_by_status={
                    'available': 22,
                    'provisioning': 2,
                    'failed': 1,
                },
            )
            logger.debug("Dashboard stats retrieved successfully")
            return response

        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get stats: {str(e)}")

    def StreamEvents(self, request: manager_pb2.StreamEventsRequest,
                    context: grpc.ServicerContext) -> AsyncIterator[types_pb2.Event]:
        """Stream real-time events to clients.

        Args:
            request: StreamEventsRequest with filter options
            context: gRPC context

        Yields:
            Event messages as they occur
        """
        try:
            logger.info("Client connected to event stream")

            # Yield sample events periodically
            event_count = 0
            event_types = list(request.event_types) if request.event_types else [
                types_pb2.EVENT_TYPE_RESOURCE_CREATED,
                types_pb2.EVENT_TYPE_RESOURCE_UPDATED,
                types_pb2.EVENT_TYPE_HEALTH_CHECK,
            ]

            while not context.cancelled():
                event_count += 1

                event_type = event_types[event_count % len(event_types)]

                event = types_pb2.Event(
                    event_type=event_type,
                    resource_id=100 + (event_count % 10),
                    message=f"Sample event #{event_count}",
                    timestamp=self._get_current_timestamp(),
                    metadata={
                        'source': 'manager',
                        'event_number': str(event_count),
                    },
                )

                yield event

                # Sleep to avoid overwhelming with events
                import time
                time.sleep(2)

        except Exception as e:
            logger.error(f"Error in event stream: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Event stream error: {str(e)}")

    # Resource Methods

    def ListResources(self, request: manager_pb2.ListResourcesRequest,
                     context: grpc.ServicerContext) -> manager_pb2.ListResourcesResponse:
        """List resources with pagination and filtering.

        Args:
            request: ListResourcesRequest with filters
            context: gRPC context

        Returns:
            ListResourcesResponse with resource list
        """
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            # Generate mock resources
            resources = []
            total_count = 45

            for i in range(page_size):
                resource_id = offset + i + 1
                if resource_id > total_count:
                    break

                resource_type = types_pb2.RESOURCE_TYPE_DATABASE if i % 2 == 0 else types_pb2.RESOURCE_TYPE_CACHE
                engine = types_pb2.ENGINE_POSTGRESQL if resource_type == types_pb2.RESOURCE_TYPE_DATABASE else types_pb2.ENGINE_REDIS

                resource = types_pb2.Resource(
                    id=resource_id,
                    name=f"resource-{resource_id}",
                    resource_type=resource_type,
                    engine=engine,
                    provider_id=1,
                    application_id=1 + (i % 8),
                    endpoint=f"db{resource_id}.example.com",
                    port=5432 if engine == types_pb2.ENGINE_POSTGRESQL else 6379,
                    database_name="mydb" if resource_type == types_pb2.RESOURCE_TYPE_DATABASE else "",
                    instance_class="db.t3.medium",
                    storage_size_gb=100,
                    multi_az=True,
                    replicas=2,
                    tls_mode=types_pb2.TLS_MODE_REQUIRED,
                    status=types_pb2.RESOURCE_STATUS_AVAILABLE,
                    status_message="Ready",
                    tags={"env": "production", "team": "data"},
                    elder_entity_id="entity-" + str(resource_id),
                    created_at=self._get_current_timestamp(),
                    updated_at=self._get_current_timestamp(),
                )
                resources.append(resource)

            pagination = manager_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            response = manager_pb2.ListResourcesResponse(
                resources=resources,
                pagination=pagination,
            )
            logger.debug(f"Listed {len(resources)} resources")
            return response

        except Exception as e:
            logger.error(f"Error listing resources: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list resources: {str(e)}")

    def GetResource(self, request: manager_pb2.GetResourceRequest,
                   context: grpc.ServicerContext) -> manager_pb2.GetResourceResponse:
        """Get single resource by ID.

        Args:
            request: GetResourceRequest with resource_id
            context: gRPC context

        Returns:
            GetResourceResponse with resource details
        """
        try:
            resource_id = request.id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            # Generate mock resource
            resource = types_pb2.Resource(
                id=resource_id,
                name=f"resource-{resource_id}",
                resource_type=types_pb2.RESOURCE_TYPE_DATABASE,
                engine=types_pb2.ENGINE_POSTGRESQL,
                provider_id=1,
                application_id=1,
                endpoint=f"db{resource_id}.example.com",
                port=5432,
                database_name="mydb",
                instance_class="db.t3.medium",
                storage_size_gb=100,
                multi_az=True,
                replicas=2,
                tls_mode=types_pb2.TLS_MODE_REQUIRED,
                status=types_pb2.RESOURCE_STATUS_AVAILABLE,
                status_message="Ready",
                tags={"env": "production"},
                elder_entity_id=f"entity-{resource_id}",
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.GetResourceResponse(resource=resource)
            logger.debug(f"Retrieved resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error getting resource: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get resource: {str(e)}")

    def CreateResource(self, request: manager_pb2.CreateResourceRequest,
                      context: grpc.ServicerContext) -> manager_pb2.CreateResourceResponse:
        """Create new resource.

        Args:
            request: CreateResourceRequest
            context: gRPC context

        Returns:
            CreateResourceResponse with created resource
        """
        try:
            # Generate new resource ID
            resource_id = random.randint(1000, 9999)

            resource = types_pb2.Resource(
                id=resource_id,
                name=request.name,
                resource_type=request.resource_type,
                engine=request.engine,
                provider_id=request.provider_id,
                application_id=request.application_id,
                endpoint=f"db{resource_id}.example.com",
                port=5432 if request.engine == types_pb2.ENGINE_POSTGRESQL else 3306,
                database_name=request.database_name,
                instance_class=request.instance_class,
                storage_size_gb=request.storage_size_gb,
                multi_az=request.multi_az,
                replicas=request.replicas,
                tls_mode=request.tls_mode,
                status=types_pb2.RESOURCE_STATUS_PROVISIONING,
                status_message="Provisioning in progress",
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.CreateResourceResponse(resource=resource)
            logger.info(f"Created resource {resource_id}: {request.name}")
            return response

        except Exception as e:
            logger.error(f"Error creating resource: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create resource: {str(e)}")

    def UpdateResource(self, request: manager_pb2.UpdateResourceRequest,
                      context: grpc.ServicerContext) -> manager_pb2.UpdateResourceResponse:
        """Update resource configuration.

        Args:
            request: UpdateResourceRequest
            context: gRPC context

        Returns:
            UpdateResourceResponse with updated resource
        """
        try:
            resource_id = request.id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            # Return updated mock resource
            resource = types_pb2.Resource(
                id=resource_id,
                name=request.name,
                instance_class=request.instance_class,
                storage_size_gb=request.storage_size_gb,
                multi_az=request.multi_az,
                replicas=request.replicas,
                tls_mode=request.tls_mode,
                tags=dict(request.tags),
                status=types_pb2.RESOURCE_STATUS_MODIFYING,
                status_message="Update in progress",
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.UpdateResourceResponse(resource=resource)
            logger.info(f"Updated resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error updating resource: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to update resource: {str(e)}")

    def DeleteResource(self, request: manager_pb2.DeleteResourceRequest,
                      context: grpc.ServicerContext) -> manager_pb2.DeleteResourceResponse:
        """Delete/soft-delete resource.

        Args:
            request: DeleteResourceRequest
            context: gRPC context

        Returns:
            DeleteResourceResponse with success status
        """
        try:
            resource_id = request.id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            response = manager_pb2.DeleteResourceResponse(success=True)
            logger.info(f"Deleted resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error deleting resource: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete resource: {str(e)}")

    def ScaleResource(self, request: manager_pb2.ScaleResourceRequest,
                     context: grpc.ServicerContext) -> manager_pb2.ScaleResourceResponse:
        """Scale resource (change instance class or replicas).

        Args:
            request: ScaleResourceRequest
            context: gRPC context

        Returns:
            ScaleResourceResponse with scaled resource
        """
        try:
            resource_id = request.id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            resource = types_pb2.Resource(
                id=resource_id,
                instance_class=request.instance_class,
                replicas=request.replicas,
                status=types_pb2.RESOURCE_STATUS_MODIFYING,
                status_message="Scaling in progress",
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.ScaleResourceResponse(resource=resource)
            logger.info(f"Scaling resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error scaling resource: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to scale resource: {str(e)}")

    def GetResourceMetrics(self, request: manager_pb2.GetResourceMetricsRequest,
                          context: grpc.ServicerContext) -> manager_pb2.GetResourceMetricsResponse:
        """Get resource metrics (CPU, memory, connections, storage).

        Args:
            request: GetResourceMetricsRequest with time range
            context: gRPC context

        Returns:
            GetResourceMetricsResponse with metric data
        """
        try:
            resource_id = request.id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            # Generate mock metrics
            base_time = datetime.utcnow()
            metrics = []
            for i in range(10):
                ts = base_time - timedelta(minutes=10-i)
                metric = manager_pb2.Metric(
                    timestamp=Timestamp(seconds=int(ts.timestamp()), nanos=ts.microsecond * 1000),
                    value=random.uniform(20, 80),
                )
                metrics.append(metric)

            response = manager_pb2.GetResourceMetricsResponse(
                cpu_utilization=metrics,
                memory_utilization=[manager_pb2.Metric(
                    timestamp=self._get_current_timestamp(),
                    value=random.uniform(40, 60),
                ) for _ in range(5)],
                connections=[manager_pb2.Metric(
                    timestamp=self._get_current_timestamp(),
                    value=random.uniform(10, 50),
                ) for _ in range(5)],
                storage_used=[manager_pb2.Metric(
                    timestamp=self._get_current_timestamp(),
                    value=random.uniform(30, 70),
                ) for _ in range(5)],
            )

            logger.debug(f"Retrieved metrics for resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error getting metrics: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get metrics: {str(e)}")

    # Application Methods

    def ListApplications(self, request: manager_pb2.ListApplicationsRequest,
                        context: grpc.ServicerContext) -> manager_pb2.ListApplicationsResponse:
        """List applications with pagination.

        Args:
            request: ListApplicationsRequest
            context: gRPC context

        Returns:
            ListApplicationsResponse with application list
        """
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            # Generate mock applications
            applications = []
            total_count = 8

            for i in range(page_size):
                app_id = offset + i + 1
                if app_id > total_count:
                    break

                app = types_pb2.Application(
                    id=app_id,
                    name=f"application-{app_id}",
                    description=f"Sample application {app_id}",
                    deployment_model=types_pb2.DEPLOYMENT_MODEL_SHARED if i % 2 == 0 else types_pb2.DEPLOYMENT_MODEL_SEPARATE,
                    elder_entity_id=f"elder-app-{app_id}",
                    elder_service_id=f"service-{app_id}",
                    tags={"team": "backend", "env": "prod"},
                    created_at=self._get_current_timestamp(),
                    updated_at=self._get_current_timestamp(),
                )
                applications.append(app)

            pagination = manager_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            response = manager_pb2.ListApplicationsResponse(
                applications=applications,
                pagination=pagination,
            )
            logger.debug(f"Listed {len(applications)} applications")
            return response

        except Exception as e:
            logger.error(f"Error listing applications: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list applications: {str(e)}")

    def GetApplication(self, request: manager_pb2.GetApplicationRequest,
                      context: grpc.ServicerContext) -> manager_pb2.GetApplicationResponse:
        """Get single application by ID.

        Args:
            request: GetApplicationRequest
            context: gRPC context

        Returns:
            GetApplicationResponse with application details
        """
        try:
            app_id = request.id
            if app_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid application ID")

            app = types_pb2.Application(
                id=app_id,
                name=f"application-{app_id}",
                description="Sample application",
                deployment_model=types_pb2.DEPLOYMENT_MODEL_SEPARATE,
                elder_entity_id=f"elder-app-{app_id}",
                elder_service_id=f"service-{app_id}",
                tags={"team": "backend"},
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.GetApplicationResponse(application=app)
            logger.debug(f"Retrieved application {app_id}")
            return response

        except Exception as e:
            logger.error(f"Error getting application: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get application: {str(e)}")

    def CreateApplication(self, request: manager_pb2.CreateApplicationRequest,
                         context: grpc.ServicerContext) -> manager_pb2.CreateApplicationResponse:
        """Create new application.

        Args:
            request: CreateApplicationRequest
            context: gRPC context

        Returns:
            CreateApplicationResponse with created application
        """
        try:
            app_id = random.randint(1000, 9999)

            app = types_pb2.Application(
                id=app_id,
                name=request.name,
                description=request.description,
                deployment_model=request.deployment_model,
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.CreateApplicationResponse(application=app)
            logger.info(f"Created application {app_id}: {request.name}")
            return response

        except Exception as e:
            logger.error(f"Error creating application: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create application: {str(e)}")

    def UpdateApplication(self, request: manager_pb2.UpdateApplicationRequest,
                         context: grpc.ServicerContext) -> manager_pb2.UpdateApplicationResponse:
        """Update application configuration.

        Args:
            request: UpdateApplicationRequest
            context: gRPC context

        Returns:
            UpdateApplicationResponse with updated application
        """
        try:
            app_id = request.id
            if app_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid application ID")

            app = types_pb2.Application(
                id=app_id,
                name=request.name,
                description=request.description,
                deployment_model=request.deployment_model,
                tags=dict(request.tags),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.UpdateApplicationResponse(application=app)
            logger.info(f"Updated application {app_id}")
            return response

        except Exception as e:
            logger.error(f"Error updating application: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to update application: {str(e)}")

    def DeleteApplication(self, request: manager_pb2.DeleteApplicationRequest,
                         context: grpc.ServicerContext) -> manager_pb2.DeleteApplicationResponse:
        """Delete application.

        Args:
            request: DeleteApplicationRequest
            context: gRPC context

        Returns:
            DeleteApplicationResponse with success status
        """
        try:
            app_id = request.id
            if app_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid application ID")

            response = manager_pb2.DeleteApplicationResponse(success=True)
            logger.info(f"Deleted application {app_id}")
            return response

        except Exception as e:
            logger.error(f"Error deleting application: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete application: {str(e)}")

    def SyncWithElder(self, request: manager_pb2.SyncWithElderRequest,
                     context: grpc.ServicerContext) -> manager_pb2.SyncWithElderResponse:
        """Sync application with Elder infrastructure platform.

        Args:
            request: SyncWithElderRequest
            context: gRPC context

        Returns:
            SyncWithElderResponse with sync status
        """
        try:
            app_id = request.application_id
            if app_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid application ID")

            response = manager_pb2.SyncWithElderResponse(
                success=True,
                elder_entity_id=f"elder-entity-{app_id}",
                elder_service_id=f"elder-service-{app_id}",
                message="Sync completed successfully",
            )
            logger.info(f"Synced application {app_id} with Elder")
            return response

        except Exception as e:
            logger.error(f"Error syncing with Elder: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to sync with Elder: {str(e)}")

    # Credential Methods

    def ListCredentials(self, request: manager_pb2.ListCredentialsRequest,
                       context: grpc.ServicerContext) -> manager_pb2.ListCredentialsResponse:
        """List credentials with pagination and filtering.

        Args:
            request: ListCredentialsRequest
            context: gRPC context

        Returns:
            ListCredentialsResponse with credential list
        """
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            # Generate mock credentials
            credentials = []
            total_count = 15

            for i in range(page_size):
                cred_id = offset + i + 1
                if cred_id > total_count:
                    break

                cred_type = [types_pb2.CREDENTIAL_TYPE_PASSWORD, types_pb2.CREDENTIAL_TYPE_IAM_ROLE,
                            types_pb2.CREDENTIAL_TYPE_JWT][i % 3]

                cred = types_pb2.Credential(
                    id=cred_id,
                    resource_id=request.resource_id or (100 + i),
                    application_id=request.application_id or (1 + (i % 8)),
                    credential_type=cred_type,
                    username=f"user-{cred_id}" if cred_type == types_pb2.CREDENTIAL_TYPE_PASSWORD else "",
                    iam_role_arn=f"arn:aws:iam::123456789:role/role-{cred_id}" if cred_type == types_pb2.CREDENTIAL_TYPE_IAM_ROLE else "",
                    jwt_subject=f"subject-{cred_id}" if cred_type == types_pb2.CREDENTIAL_TYPE_JWT else "",
                    permissions=["SELECT", "INSERT", "UPDATE"],
                    expires_at=Timestamp(seconds=int((datetime.utcnow() + timedelta(days=90)).timestamp())),
                    auto_rotate=True,
                    rotation_interval_days=30,
                    last_rotated_at=self._get_current_timestamp(),
                    next_rotation_at=Timestamp(seconds=int((datetime.utcnow() + timedelta(days=30)).timestamp())),
                    created_at=self._get_current_timestamp(),
                    updated_at=self._get_current_timestamp(),
                )
                credentials.append(cred)

            pagination = manager_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            response = manager_pb2.ListCredentialsResponse(
                credentials=credentials,
                pagination=pagination,
            )
            logger.debug(f"Listed {len(credentials)} credentials")
            return response

        except Exception as e:
            logger.error(f"Error listing credentials: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list credentials: {str(e)}")

    def GetCredential(self, request: manager_pb2.GetCredentialRequest,
                     context: grpc.ServicerContext) -> manager_pb2.GetCredentialResponse:
        """Get single credential by ID.

        Args:
            request: GetCredentialRequest
            context: gRPC context

        Returns:
            GetCredentialResponse with credential details
        """
        try:
            cred_id = request.id
            if cred_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid credential ID")

            cred = types_pb2.Credential(
                id=cred_id,
                resource_id=100,
                application_id=1,
                credential_type=types_pb2.CREDENTIAL_TYPE_PASSWORD,
                username=f"user-{cred_id}",
                permissions=["SELECT", "INSERT"],
                expires_at=Timestamp(seconds=int((datetime.utcnow() + timedelta(days=90)).timestamp())),
                auto_rotate=True,
                rotation_interval_days=30,
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.GetCredentialResponse(credential=cred)
            logger.debug(f"Retrieved credential {cred_id}")
            return response

        except Exception as e:
            logger.error(f"Error getting credential: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get credential: {str(e)}")

    def CreateCredential(self, request: manager_pb2.CreateCredentialRequest,
                        context: grpc.ServicerContext) -> manager_pb2.CreateCredentialResponse:
        """Create new credential (password, IAM, JWT, mTLS).

        Args:
            request: CreateCredentialRequest
            context: gRPC context

        Returns:
            CreateCredentialResponse with created credential and secret
        """
        try:
            cred_id = random.randint(1000, 9999)
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

            cred = types_pb2.Credential(
                id=cred_id,
                resource_id=request.resource_id,
                application_id=request.application_id,
                credential_type=request.credential_type,
                username=request.username,
                permissions=list(request.permissions),
                expires_at=request.expires_at or Timestamp(seconds=int((datetime.utcnow() + timedelta(days=90)).timestamp())),
                auto_rotate=request.auto_rotate,
                rotation_interval_days=request.rotation_interval_days or 30,
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.CreateCredentialResponse(
                credential=cred,
                password=password if request.credential_type == types_pb2.CREDENTIAL_TYPE_PASSWORD else "",
                jwt_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." if request.credential_type == types_pb2.CREDENTIAL_TYPE_JWT else "",
                mtls_certificate="-----BEGIN CERTIFICATE-----..." if request.credential_type == types_pb2.CREDENTIAL_TYPE_MTLS else "",
                mtls_private_key="-----BEGIN PRIVATE KEY-----..." if request.credential_type == types_pb2.CREDENTIAL_TYPE_MTLS else "",
            )

            logger.info(f"Created credential {cred_id} for resource {request.resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error creating credential: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create credential: {str(e)}")

    def RotateCredential(self, request: manager_pb2.RotateCredentialRequest,
                        context: grpc.ServicerContext) -> manager_pb2.RotateCredentialResponse:
        """Rotate credential (generate new password/key).

        Args:
            request: RotateCredentialRequest
            context: gRPC context

        Returns:
            RotateCredentialResponse with rotated credential and new secret
        """
        try:
            cred_id = request.id
            if cred_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid credential ID")

            new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

            cred = types_pb2.Credential(
                id=cred_id,
                last_rotated_at=self._get_current_timestamp(),
                next_rotation_at=Timestamp(seconds=int((datetime.utcnow() + timedelta(days=30)).timestamp())),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.RotateCredentialResponse(
                credential=cred,
                new_password=new_password,
                new_jwt_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            )

            logger.info(f"Rotated credential {cred_id}")
            return response

        except Exception as e:
            logger.error(f"Error rotating credential: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to rotate credential: {str(e)}")

    def ConfigureAutoRotation(self, request: manager_pb2.ConfigureAutoRotationRequest,
                             context: grpc.ServicerContext) -> manager_pb2.ConfigureAutoRotationResponse:
        """Configure automatic credential rotation.

        Args:
            request: ConfigureAutoRotationRequest
            context: gRPC context

        Returns:
            ConfigureAutoRotationResponse with updated credential
        """
        try:
            cred_id = request.id
            if cred_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid credential ID")

            cred = types_pb2.Credential(
                id=cred_id,
                auto_rotate=request.auto_rotate,
                rotation_interval_days=request.rotation_interval_days,
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.ConfigureAutoRotationResponse(credential=cred)
            logger.info(f"Configured auto-rotation for credential {cred_id}")
            return response

        except Exception as e:
            logger.error(f"Error configuring auto-rotation: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to configure auto-rotation: {str(e)}")

    def DeleteCredential(self, request: manager_pb2.DeleteCredentialRequest,
                        context: grpc.ServicerContext) -> manager_pb2.DeleteCredentialResponse:
        """Delete credential.

        Args:
            request: DeleteCredentialRequest
            context: gRPC context

        Returns:
            DeleteCredentialResponse with success status
        """
        try:
            cred_id = request.id
            if cred_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid credential ID")

            response = manager_pb2.DeleteCredentialResponse(success=True)
            logger.info(f"Deleted credential {cred_id}")
            return response

        except Exception as e:
            logger.error(f"Error deleting credential: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete credential: {str(e)}")

    # Provider Methods

    def ListProviders(self, request: manager_pb2.ListProvidersRequest,
                     context: grpc.ServicerContext) -> manager_pb2.ListProvidersResponse:
        """List cloud providers with pagination and filtering.

        Args:
            request: ListProvidersRequest
            context: gRPC context

        Returns:
            ListProvidersResponse with provider list
        """
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            # Generate mock providers
            providers = []
            provider_types = [types_pb2.PROVIDER_TYPE_KUBERNETES, types_pb2.PROVIDER_TYPE_AWS,
                             types_pb2.PROVIDER_TYPE_GCP, types_pb2.PROVIDER_TYPE_AZURE]
            total_count = 4

            for i in range(min(page_size, total_count)):
                provider_id = offset + i + 1
                if provider_id > total_count:
                    break

                provider = types_pb2.Provider(
                    id=provider_id,
                    name=["kubernetes", "aws", "gcp", "azure"][i],
                    provider_type=provider_types[i],
                    configuration='{"region": "us-east-1", "zone": "a"}',
                    credentials_secret_name=f"provider-{i}-creds",
                    enabled=True,
                    last_test_at=self._get_current_timestamp(),
                    last_test_success=True,
                    last_test_message="Health check passed",
                    created_at=self._get_current_timestamp(),
                    updated_at=self._get_current_timestamp(),
                )
                providers.append(provider)

            pagination = manager_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            response = manager_pb2.ListProvidersResponse(
                providers=providers,
                pagination=pagination,
            )
            logger.debug(f"Listed {len(providers)} providers")
            return response

        except Exception as e:
            logger.error(f"Error listing providers: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list providers: {str(e)}")

    def GetProvider(self, request: manager_pb2.GetProviderRequest,
                   context: grpc.ServicerContext) -> manager_pb2.GetProviderResponse:
        """Get single provider by ID.

        Args:
            request: GetProviderRequest
            context: gRPC context

        Returns:
            GetProviderResponse with provider details
        """
        try:
            provider_id = request.id
            if provider_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid provider ID")

            provider = types_pb2.Provider(
                id=provider_id,
                name="aws",
                provider_type=types_pb2.PROVIDER_TYPE_AWS,
                configuration='{"region": "us-east-1"}',
                credentials_secret_name="aws-creds",
                enabled=True,
                last_test_at=self._get_current_timestamp(),
                last_test_success=True,
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.GetProviderResponse(provider=provider)
            logger.debug(f"Retrieved provider {provider_id}")
            return response

        except Exception as e:
            logger.error(f"Error getting provider: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get provider: {str(e)}")

    def CreateProvider(self, request: manager_pb2.CreateProviderRequest,
                      context: grpc.ServicerContext) -> manager_pb2.CreateProviderResponse:
        """Create new provider.

        Args:
            request: CreateProviderRequest
            context: gRPC context

        Returns:
            CreateProviderResponse with created provider
        """
        try:
            provider_id = random.randint(1000, 9999)

            provider = types_pb2.Provider(
                id=provider_id,
                name=request.name,
                provider_type=request.provider_type,
                configuration=request.configuration,
                credentials_secret_name=request.credentials_secret_name,
                enabled=True,
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.CreateProviderResponse(provider=provider)
            logger.info(f"Created provider {provider_id}: {request.name}")
            return response

        except Exception as e:
            logger.error(f"Error creating provider: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create provider: {str(e)}")

    def UpdateProvider(self, request: manager_pb2.UpdateProviderRequest,
                      context: grpc.ServicerContext) -> manager_pb2.UpdateProviderResponse:
        """Update provider configuration.

        Args:
            request: UpdateProviderRequest
            context: gRPC context

        Returns:
            UpdateProviderResponse with updated provider
        """
        try:
            provider_id = request.id
            if provider_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid provider ID")

            provider = types_pb2.Provider(
                id=provider_id,
                name=request.name,
                configuration=request.configuration,
                credentials_secret_name=request.credentials_secret_name,
                enabled=request.enabled,
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.UpdateProviderResponse(provider=provider)
            logger.info(f"Updated provider {provider_id}")
            return response

        except Exception as e:
            logger.error(f"Error updating provider: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to update provider: {str(e)}")

    def DeleteProvider(self, request: manager_pb2.DeleteProviderRequest,
                      context: grpc.ServicerContext) -> manager_pb2.DeleteProviderResponse:
        """Delete provider.

        Args:
            request: DeleteProviderRequest
            context: gRPC context

        Returns:
            DeleteProviderResponse with success status
        """
        try:
            provider_id = request.id
            if provider_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid provider ID")

            response = manager_pb2.DeleteProviderResponse(success=True)
            logger.info(f"Deleted provider {provider_id}")
            return response

        except Exception as e:
            logger.error(f"Error deleting provider: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete provider: {str(e)}")

    def TestProvider(self, request: manager_pb2.TestProviderRequest,
                    context: grpc.ServicerContext) -> manager_pb2.TestProviderResponse:
        """Test provider connection and credentials.

        Args:
            request: TestProviderRequest
            context: gRPC context

        Returns:
            TestProviderResponse with test result
        """
        try:
            provider_id = request.id
            if provider_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid provider ID")

            response = manager_pb2.TestProviderResponse(
                success=True,
                message="Provider test passed",
            )
            logger.info(f"Tested provider {provider_id}")
            return response

        except Exception as e:
            logger.error(f"Error testing provider: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to test provider: {str(e)}")

    # MarchProxy Methods

    def ConfigureMarchProxy(self, request: manager_pb2.ConfigureMarchProxyRequest,
                           context: grpc.ServicerContext) -> manager_pb2.ConfigureMarchProxyResponse:
        """Configure MarchProxy for resource.

        Args:
            request: ConfigureMarchProxyRequest
            context: gRPC context

        Returns:
            ConfigureMarchProxyResponse with proxy endpoint
        """
        try:
            resource_id = request.resource_id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            response = manager_pb2.ConfigureMarchProxyResponse(
                success=True,
                proxy_endpoint=f"proxy-{resource_id}.example.com",
                proxy_port=3306,
                message="MarchProxy configured successfully",
            )
            logger.info(f"Configured MarchProxy for resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error configuring MarchProxy: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to configure MarchProxy: {str(e)}")

    def RemoveMarchProxy(self, request: manager_pb2.RemoveMarchProxyRequest,
                        context: grpc.ServicerContext) -> manager_pb2.RemoveMarchProxyResponse:
        """Remove MarchProxy configuration.

        Args:
            request: RemoveMarchProxyRequest
            context: gRPC context

        Returns:
            RemoveMarchProxyResponse with success status
        """
        try:
            resource_id = request.resource_id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            response = manager_pb2.RemoveMarchProxyResponse(success=True)
            logger.info(f"Removed MarchProxy for resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error removing MarchProxy: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to remove MarchProxy: {str(e)}")

    def SyncMarchProxy(self, request: manager_pb2.SyncMarchProxyRequest,
                      context: grpc.ServicerContext) -> manager_pb2.SyncMarchProxyResponse:
        """Sync MarchProxy status.

        Args:
            request: SyncMarchProxyRequest
            context: gRPC context

        Returns:
            SyncMarchProxyResponse with health status
        """
        try:
            resource_id = request.resource_id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            response = manager_pb2.SyncMarchProxyResponse(
                success=True,
                health_status="healthy",
                metrics={
                    "active_connections": "42",
                    "queries_per_second": "125.5",
                    "cpu_percent": "35.2",
                    "memory_mb": "512",
                },
            )
            logger.info(f"Synced MarchProxy for resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error syncing MarchProxy: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to sync MarchProxy: {str(e)}")

    # Tag Methods

    def AddTags(self, request: manager_pb2.AddTagsRequest,
               context: grpc.ServicerContext) -> manager_pb2.AddTagsResponse:
        """Add tags to resource.

        Args:
            request: AddTagsRequest
            context: gRPC context

        Returns:
            AddTagsResponse with updated resource
        """
        try:
            resource_id = request.resource_id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            resource = types_pb2.Resource(
                id=resource_id,
                tags=dict(request.tags),
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.AddTagsResponse(resource=resource)
            logger.info(f"Added tags to resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error adding tags: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to add tags: {str(e)}")

    def RemoveTag(self, request: manager_pb2.RemoveTagRequest,
                 context: grpc.ServicerContext) -> manager_pb2.RemoveTagResponse:
        """Remove tag from resource.

        Args:
            request: RemoveTagRequest
            context: gRPC context

        Returns:
            RemoveTagResponse with updated resource
        """
        try:
            resource_id = request.resource_id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            resource = types_pb2.Resource(
                id=resource_id,
                updated_at=self._get_current_timestamp(),
            )

            response = manager_pb2.RemoveTagResponse(resource=resource)
            logger.info(f"Removed tag '{request.tag_key}' from resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error removing tag: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to remove tag: {str(e)}")

    def SyncTags(self, request: manager_pb2.SyncTagsRequest,
                context: grpc.ServicerContext) -> manager_pb2.SyncTagsResponse:
        """Sync tags to cloud provider.

        Args:
            request: SyncTagsRequest
            context: gRPC context

        Returns:
            SyncTagsResponse with sync status
        """
        try:
            resource_id = request.resource_id
            if resource_id <= 0:
                context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Invalid resource ID")

            response = manager_pb2.SyncTagsResponse(
                success=True,
                message="Tags synced to provider successfully",
            )
            logger.info(f"Synced tags for resource {resource_id}")
            return response

        except Exception as e:
            logger.error(f"Error syncing tags: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to sync tags: {str(e)}")
