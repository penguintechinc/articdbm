"""gRPC BigData Servicer Implementation

Implements BigDataService for big data cluster management and operations.
Provides HDFS, Trino, Spark, Flink, HBase cluster lifecycle management,
job submission, catalog operations, and real-time event streaming.
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, AsyncIterator, Dict, List, Optional

import grpc
from google.protobuf.empty_pb2 import Empty
from google.protobuf.timestamp_pb2 import Timestamp
from pydal import DAL

from articdbm import bigdata_pb2, types_pb2
from app.services.provisioning.bigdata import (
    BaseBigDataProvisioner,
    ClusterConfig,
    ClusterType,
    JobConfig,
    get_bigdata_provisioner,
)

logger = logging.getLogger(__name__)


class BigDataServicer(bigdata_pb2.BigDataServiceServicer):
    """gRPC servicer implementing BigDataService interface.

    Handles all gRPC requests for big data cluster management including
    HDFS, Trino, Spark, Flink, HBase operations.
    """

    SERVICE_NAME = 'articdbm.BigDataService'

    def __init__(self, db: Optional[DAL] = None):
        """Initialize BigDataServicer.

        Args:
            db: PyDAL database instance (optional for testing)
        """
        self.db = db
        self._event_subscribers: List[asyncio.Queue] = []

    def add_to_server(self, server: grpc.Server) -> None:
        """Add servicer to gRPC server.

        Args:
            server: gRPC server instance
        """
        bigdata_pb2.add_BigDataServiceServicer_to_server(self, server)

    def _get_current_timestamp(self) -> Timestamp:
        """Get current timestamp in proto format."""
        now = datetime.utcnow()
        return Timestamp(seconds=int(now.timestamp()), nanos=now.microsecond * 1000)

    def _get_provisioner(self, provider_id: int) -> BaseBigDataProvisioner:
        """Get provisioner instance for provider.

        Args:
            provider_id: Provider ID

        Returns:
            Provisioner instance

        Raises:
            grpc.StatusCode.NOT_FOUND: Provider not found
            grpc.StatusCode.INTERNAL: Provisioner initialization failed
        """
        if not self.db:
            raise grpc.RpcError("Database not initialized")

        provider = self.db.providers[provider_id]
        if not provider:
            raise grpc.RpcError(f"Provider {provider_id} not found")

        config = json.loads(provider.configuration) if provider.configuration else {}
        provider_type = self._get_provider_type_string(provider.provider_type)

        try:
            return get_bigdata_provisioner(provider_type, config)
        except Exception as e:
            logger.error(f"Failed to initialize provisioner: {e}", exc_info=True)
            raise grpc.RpcError(f"Provisioner initialization failed: {str(e)}")

    def _get_provider_type_string(self, provider_type: int) -> str:
        """Convert provider type enum to string."""
        provider_map = {
            1: 'kubernetes',
            2: 'aws',
            3: 'gcp',
            4: 'azure',
            5: 'vultr',
        }
        return provider_map.get(provider_type, 'kubernetes')

    def _convert_cluster_status(self, state: str) -> bigdata_pb2.ClusterStatus:
        """Convert database state to proto ClusterStatus."""
        status_map = {
            'pending': bigdata_pb2.CLUSTER_STATUS_PROVISIONING,
            'creating': bigdata_pb2.CLUSTER_STATUS_PROVISIONING,
            'running': bigdata_pb2.CLUSTER_STATUS_RUNNING,
            'scaling': bigdata_pb2.CLUSTER_STATUS_SCALING,
            'stopped': bigdata_pb2.CLUSTER_STATUS_STOPPED,
            'terminating': bigdata_pb2.CLUSTER_STATUS_STOPPED,
            'terminated': bigdata_pb2.CLUSTER_STATUS_TERMINATED,
            'error': bigdata_pb2.CLUSTER_STATUS_FAILED,
        }
        return status_map.get(state, bigdata_pb2.CLUSTER_STATUS_UNSPECIFIED)

    def _convert_job_status(self, state: str) -> bigdata_pb2.JobStatus:
        """Convert database state to proto JobStatus."""
        status_map = {
            'pending': bigdata_pb2.JOB_STATUS_PENDING,
            'running': bigdata_pb2.JOB_STATUS_RUNNING,
            'completed': bigdata_pb2.JOB_STATUS_SUCCEEDED,
            'failed': bigdata_pb2.JOB_STATUS_FAILED,
            'cancelled': bigdata_pb2.JOB_STATUS_CANCELLED,
        }
        return status_map.get(state, bigdata_pb2.JOB_STATUS_UNSPECIFIED)

    # ===== HDFS Cluster Operations =====

    def ListHDFSClusters(self, request: bigdata_pb2.ListRequest,
                        context: grpc.ServicerContext) -> bigdata_pb2.HDFSClusterList:
        """List HDFS clusters with pagination."""
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            query = self.db.hdfs_clusters.is_active == True
            if request.filter:
                query &= self.db.hdfs_clusters.name.contains(request.filter)

            total_count = self.db(query).count()
            rows = self.db(query).select(
                limitby=(offset, offset + page_size),
                orderby=~self.db.hdfs_clusters.created_on
            )

            clusters = []
            for row in rows:
                cluster = bigdata_pb2.HDFSCluster(
                    id=row.id,
                    name=row.name,
                    description=row.description or '',
                    status=self._convert_cluster_status(row.state),
                    status_message=row.status_message or '',
                    namenode_host=row.namenode_endpoint.split(':')[0],
                    namenode_port=row.namenode_port,
                    replication_factor=row.replication_factor,
                    block_size_mb=row.block_size_mb,
                    hadoop_version=row.version or '',
                    datanode_count=row.datanode_count,
                    tags=json.loads(row.tags) if row.tags else {},
                    created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
                )
                clusters.append(cluster)

            pagination = types_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            return bigdata_pb2.HDFSClusterList(clusters=clusters, pagination=pagination)

        except Exception as e:
            logger.error(f"Error listing HDFS clusters: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list HDFS clusters: {str(e)}")

    def GetHDFSCluster(self, request: bigdata_pb2.GetByIdRequest,
                      context: grpc.ServicerContext) -> bigdata_pb2.HDFSCluster:
        """Get single HDFS cluster by ID."""
        try:
            row = self.db.hdfs_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"HDFS cluster {request.id} not found")

            return bigdata_pb2.HDFSCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                status_message=row.status_message or '',
                namenode_host=row.namenode_endpoint.split(':')[0],
                namenode_port=row.namenode_port,
                replication_factor=row.replication_factor,
                block_size_mb=row.block_size_mb,
                hadoop_version=row.version or '',
                datanode_count=row.datanode_count,
                tags=json.loads(row.tags) if row.tags else {},
                created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error getting HDFS cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get HDFS cluster: {str(e)}")

    def CreateHDFSCluster(self, request: bigdata_pb2.CreateHDFSClusterRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.HDFSCluster:
        """Create new HDFS cluster."""
        try:
            provisioner = self._get_provisioner(request.provider_id)

            cluster_id = self.db.hdfs_clusters.insert(
                name=request.name,
                description=request.description,
                provider_id=request.provider_id,
                application_id=1,  # Default application
                state='creating',
                cluster_mode='kubernetes',
                namenode_endpoint=f"{request.namenode_host}:{request.namenode_port}",
                namenode_port=request.namenode_port or 9000,
                http_port=50070,
                datanode_count=request.datanode_count or 3,
                replication_factor=request.replication_factor or 3,
                block_size_mb=request.block_size_mb or 256,
                tags=json.dumps(dict(request.tags)),
            )
            self.db.commit()

            # Async provisioning in background
            logger.info(f"Created HDFS cluster {cluster_id}: {request.name}")

            row = self.db.hdfs_clusters[cluster_id]
            return bigdata_pb2.HDFSCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                namenode_host=request.namenode_host,
                namenode_port=request.namenode_port or 9000,
                replication_factor=request.replication_factor or 3,
                block_size_mb=request.block_size_mb or 256,
                datanode_count=request.datanode_count or 3,
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating HDFS cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create HDFS cluster: {str(e)}")

    def UpdateHDFSCluster(self, request: bigdata_pb2.UpdateHDFSClusterRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.HDFSCluster:
        """Update HDFS cluster configuration."""
        try:
            row = self.db.hdfs_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"HDFS cluster {request.id} not found")

            update_fields = {}
            if request.description:
                update_fields['description'] = request.description
            if request.replication_factor > 0:
                update_fields['replication_factor'] = request.replication_factor
            if request.block_size_mb > 0:
                update_fields['block_size_mb'] = request.block_size_mb
            if request.tags:
                update_fields['tags'] = json.dumps(dict(request.tags))

            self.db(self.db.hdfs_clusters.id == request.id).update(**update_fields)
            self.db.commit()

            updated_row = self.db.hdfs_clusters[request.id]
            return self.GetHDFSCluster(bigdata_pb2.GetByIdRequest(id=request.id), context)

        except Exception as e:
            logger.error(f"Error updating HDFS cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to update HDFS cluster: {str(e)}")

    def DeleteHDFSCluster(self, request: bigdata_pb2.DeleteRequest,
                         context: grpc.ServicerContext) -> Empty:
        """Delete HDFS cluster."""
        try:
            row = self.db.hdfs_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"HDFS cluster {request.id} not found")

            self.db(self.db.hdfs_clusters.id == request.id).update(
                state='terminating',
                is_active=False
            )
            self.db.commit()

            logger.info(f"Deleted HDFS cluster {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error deleting HDFS cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete HDFS cluster: {str(e)}")

    def ScaleHDFSCluster(self, request: bigdata_pb2.ScaleHDFSRequest,
                        context: grpc.ServicerContext) -> bigdata_pb2.HDFSCluster:
        """Scale HDFS cluster (change datanode count)."""
        try:
            row = self.db.hdfs_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"HDFS cluster {request.id} not found")

            self.db(self.db.hdfs_clusters.id == request.id).update(
                state='scaling',
                datanode_count=request.datanode_count
            )
            self.db.commit()

            logger.info(f"Scaling HDFS cluster {request.id} to {request.datanode_count} datanodes")
            return self.GetHDFSCluster(bigdata_pb2.GetByIdRequest(id=request.id), context)

        except Exception as e:
            logger.error(f"Error scaling HDFS cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to scale HDFS cluster: {str(e)}")

    # ===== Trino Cluster Operations =====

    def ListTrinoClusters(self, request: bigdata_pb2.ListRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.TrinoClusterList:
        """List Trino clusters with pagination."""
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            query = self.db.trino_clusters.is_active == True
            if request.filter:
                query &= self.db.trino_clusters.name.contains(request.filter)

            total_count = self.db(query).count()
            rows = self.db(query).select(
                limitby=(offset, offset + page_size),
                orderby=~self.db.trino_clusters.created_on
            )

            clusters = []
            for row in rows:
                cluster = bigdata_pb2.TrinoCluster(
                    id=row.id,
                    name=row.name,
                    description=row.description or '',
                    status=self._convert_cluster_status(row.state),
                    status_message=row.status_message or '',
                    coordinator_host=row.coordinator_endpoint.split(':')[0],
                    coordinator_port=row.coordinator_port,
                    worker_count=row.worker_count,
                    trino_version=row.version or '',
                    tags=json.loads(row.tags) if row.tags else {},
                    created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
                )
                clusters.append(cluster)

            pagination = types_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            return bigdata_pb2.TrinoClusterList(clusters=clusters, pagination=pagination)

        except Exception as e:
            logger.error(f"Error listing Trino clusters: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list Trino clusters: {str(e)}")

    def GetTrinoCluster(self, request: bigdata_pb2.GetByIdRequest,
                       context: grpc.ServicerContext) -> bigdata_pb2.TrinoCluster:
        """Get single Trino cluster by ID."""
        try:
            row = self.db.trino_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Trino cluster {request.id} not found")

            # Get associated catalogs
            catalogs = []
            catalog_rows = self.db(
                self.db.trino_catalogs.trino_cluster_id == request.id
            ).select()
            for cat in catalog_rows:
                catalogs.append(bigdata_pb2.TrinoCatalog(
                    id=cat.id,
                    cluster_id=cat.trino_cluster_id,
                    name=cat.name,
                    connector_name=cat.connector_type,
                    configuration=json.dumps(json.loads(cat.configuration) if cat.configuration else {}),
                    created_at=Timestamp(seconds=int(cat.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(cat.modified_on.timestamp())),
                ))

            return bigdata_pb2.TrinoCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                status_message=row.status_message or '',
                coordinator_host=row.coordinator_endpoint.split(':')[0],
                coordinator_port=row.coordinator_port,
                worker_count=row.worker_count,
                trino_version=row.version or '',
                catalogs=catalogs,
                tags=json.loads(row.tags) if row.tags else {},
                created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error getting Trino cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get Trino cluster: {str(e)}")

    def CreateTrinoCluster(self, request: bigdata_pb2.CreateTrinoClusterRequest,
                          context: grpc.ServicerContext) -> bigdata_pb2.TrinoCluster:
        """Create new Trino cluster."""
        try:
            provisioner = self._get_provisioner(request.provider_id)

            cluster_id = self.db.trino_clusters.insert(
                name=request.name,
                description=request.description,
                provider_id=request.provider_id,
                application_id=1,
                state='creating',
                cluster_mode='kubernetes',
                coordinator_endpoint=f"{request.coordinator_host}:{request.coordinator_port}",
                coordinator_port=request.coordinator_port or 8080,
                worker_count=request.worker_count or 3,
                memory_gb=request.query_max_memory_mb // 1024 if request.query_max_memory_mb else 8,
                max_query_memory_gb=request.query_max_memory_mb // 1024 if request.query_max_memory_mb else 8,
                tags=json.dumps(dict(request.tags)),
            )
            self.db.commit()

            logger.info(f"Created Trino cluster {cluster_id}: {request.name}")

            row = self.db.trino_clusters[cluster_id]
            return bigdata_pb2.TrinoCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                coordinator_host=request.coordinator_host,
                coordinator_port=request.coordinator_port or 8080,
                worker_count=request.worker_count or 3,
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating Trino cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create Trino cluster: {str(e)}")

    def UpdateTrinoCluster(self, request: bigdata_pb2.UpdateTrinoClusterRequest,
                          context: grpc.ServicerContext) -> bigdata_pb2.TrinoCluster:
        """Update Trino cluster configuration."""
        try:
            row = self.db.trino_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Trino cluster {request.id} not found")

            update_fields = {}
            if request.description:
                update_fields['description'] = request.description
            if request.worker_count > 0:
                update_fields['worker_count'] = request.worker_count
            if request.query_max_memory_mb > 0:
                update_fields['max_query_memory_gb'] = request.query_max_memory_mb // 1024
            if request.tags:
                update_fields['tags'] = json.dumps(dict(request.tags))

            self.db(self.db.trino_clusters.id == request.id).update(**update_fields)
            self.db.commit()

            return self.GetTrinoCluster(bigdata_pb2.GetByIdRequest(id=request.id), context)

        except Exception as e:
            logger.error(f"Error updating Trino cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to update Trino cluster: {str(e)}")

    def DeleteTrinoCluster(self, request: bigdata_pb2.DeleteRequest,
                          context: grpc.ServicerContext) -> Empty:
        """Delete Trino cluster."""
        try:
            row = self.db.trino_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Trino cluster {request.id} not found")

            self.db(self.db.trino_clusters.id == request.id).update(
                state='terminating',
                is_active=False
            )
            self.db.commit()

            logger.info(f"Deleted Trino cluster {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error deleting Trino cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete Trino cluster: {str(e)}")

    def ScaleTrinoCluster(self, request: bigdata_pb2.ScaleTrinoRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.TrinoCluster:
        """Scale Trino cluster."""
        try:
            row = self.db.trino_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Trino cluster {request.id} not found")

            self.db(self.db.trino_clusters.id == request.id).update(
                state='scaling',
                worker_count=request.worker_count
            )
            self.db.commit()

            logger.info(f"Scaling Trino cluster {request.id} to {request.worker_count} workers")
            return self.GetTrinoCluster(bigdata_pb2.GetByIdRequest(id=request.id), context)

        except Exception as e:
            logger.error(f"Error scaling Trino cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to scale Trino cluster: {str(e)}")

    def AddTrinoCatalog(self, request: bigdata_pb2.AddTrinoCatalogRequest,
                       context: grpc.ServicerContext) -> bigdata_pb2.TrinoCatalog:
        """Add catalog to Trino cluster."""
        try:
            cluster = self.db.trino_clusters[request.cluster_id]
            if not cluster:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Trino cluster {request.cluster_id} not found")

            catalog_id = self.db.trino_catalogs.insert(
                name=request.name,
                trino_cluster_id=request.cluster_id,
                provider_id=cluster.provider_id,
                application_id=cluster.application_id,
                connector_type=request.connector_name,
                configuration=request.configuration or '{}',
                status='creating',
            )
            self.db.commit()

            row = self.db.trino_catalogs[catalog_id]
            return bigdata_pb2.TrinoCatalog(
                id=row.id,
                cluster_id=row.trino_cluster_id,
                name=row.name,
                connector_name=row.connector_type,
                configuration=row.configuration or '{}',
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error adding Trino catalog: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to add Trino catalog: {str(e)}")

    def RemoveTrinoCatalog(self, request: bigdata_pb2.RemoveTrinoCatalogRequest,
                          context: grpc.ServicerContext) -> Empty:
        """Remove catalog from Trino cluster."""
        try:
            row = self.db.trino_catalogs[request.catalog_id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Trino catalog {request.catalog_id} not found")

            self.db(self.db.trino_catalogs.id == request.catalog_id).delete()
            self.db.commit()

            logger.info(f"Removed Trino catalog {request.catalog_id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error removing Trino catalog: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to remove Trino catalog: {str(e)}")

    def ExecuteTrinoQuery(self, request: bigdata_pb2.TrinoQueryRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.TrinoQueryResult:
        """Execute query on Trino cluster."""
        try:
            cluster = self.db.trino_clusters[request.cluster_id]
            if not cluster:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Trino cluster {request.cluster_id} not found")

            # Mock query execution (actual implementation would call Trino REST API)
            import uuid
            query_id = str(uuid.uuid4())

            return bigdata_pb2.TrinoQueryResult(
                query_id=query_id,
                status=bigdata_pb2.JOB_STATUS_SUCCEEDED,
                columns=['col1', 'col2'],
                data=['row1_col1,row1_col2', 'row2_col1,row2_col2'],
                executed_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error executing Trino query: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to execute Trino query: {str(e)}")

    # ===== Spark Cluster Operations =====

    def ListSparkClusters(self, request: bigdata_pb2.ListRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.SparkClusterList:
        """List Spark clusters with pagination."""
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            query = self.db.spark_clusters.is_active == True
            if request.filter:
                query &= self.db.spark_clusters.name.contains(request.filter)

            total_count = self.db(query).count()
            rows = self.db(query).select(
                limitby=(offset, offset + page_size),
                orderby=~self.db.spark_clusters.created_on
            )

            clusters = []
            for row in rows:
                cluster = bigdata_pb2.SparkCluster(
                    id=row.id,
                    name=row.name,
                    description=row.description or '',
                    status=self._convert_cluster_status(row.state),
                    status_message=row.status_message or '',
                    master_host=row.master_endpoint.split(':')[0],
                    master_port=row.master_port,
                    worker_count=row.worker_count,
                    spark_version=row.version or '',
                    executor_cores=row.executor_cores,
                    executor_memory_gb=row.executor_memory_gb,
                    driver_memory_gb=row.driver_memory_gb,
                    tags=json.loads(row.tags) if row.tags else {},
                    created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
                )
                clusters.append(cluster)

            pagination = types_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            return bigdata_pb2.SparkClusterList(clusters=clusters, pagination=pagination)

        except Exception as e:
            logger.error(f"Error listing Spark clusters: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list Spark clusters: {str(e)}")

    def GetSparkCluster(self, request: bigdata_pb2.GetByIdRequest,
                       context: grpc.ServicerContext) -> bigdata_pb2.SparkCluster:
        """Get single Spark cluster by ID."""
        try:
            row = self.db.spark_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Spark cluster {request.id} not found")

            return bigdata_pb2.SparkCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                status_message=row.status_message or '',
                master_host=row.master_endpoint.split(':')[0],
                master_port=row.master_port,
                worker_count=row.worker_count,
                spark_version=row.version or '',
                executor_cores=row.executor_cores,
                executor_memory_gb=row.executor_memory_gb,
                driver_memory_gb=row.driver_memory_gb,
                tags=json.loads(row.tags) if row.tags else {},
                created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error getting Spark cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get Spark cluster: {str(e)}")

    def CreateSparkCluster(self, request: bigdata_pb2.CreateSparkClusterRequest,
                          context: grpc.ServicerContext) -> bigdata_pb2.SparkCluster:
        """Create new Spark cluster."""
        try:
            provisioner = self._get_provisioner(request.provider_id)

            cluster_id = self.db.spark_clusters.insert(
                name=request.name,
                description=request.description,
                provider_id=request.provider_id,
                application_id=1,
                state='creating',
                cluster_mode='kubernetes',
                master_endpoint=f"{request.master_host}:{request.master_port}",
                master_port=request.master_port or 7077,
                master_web_ui_port=8080,
                worker_count=request.worker_count or 3,
                executor_cores=request.executor_cores or 4,
                executor_memory_gb=request.executor_memory_gb or 8,
                driver_memory_gb=request.driver_memory_gb or 4,
                tags=json.dumps(dict(request.tags)),
            )
            self.db.commit()

            logger.info(f"Created Spark cluster {cluster_id}: {request.name}")

            row = self.db.spark_clusters[cluster_id]
            return bigdata_pb2.SparkCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                master_host=request.master_host,
                master_port=request.master_port or 7077,
                worker_count=request.worker_count or 3,
                executor_cores=request.executor_cores or 4,
                executor_memory_gb=request.executor_memory_gb or 8,
                driver_memory_gb=request.driver_memory_gb or 4,
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating Spark cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create Spark cluster: {str(e)}")

    def DeleteSparkCluster(self, request: bigdata_pb2.DeleteRequest,
                          context: grpc.ServicerContext) -> Empty:
        """Delete Spark cluster."""
        try:
            row = self.db.spark_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Spark cluster {request.id} not found")

            self.db(self.db.spark_clusters.id == request.id).update(
                state='terminating',
                is_active=False
            )
            self.db.commit()

            logger.info(f"Deleted Spark cluster {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error deleting Spark cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete Spark cluster: {str(e)}")

    def ScaleSparkCluster(self, request: bigdata_pb2.ScaleSparkRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.SparkCluster:
        """Scale Spark cluster."""
        try:
            row = self.db.spark_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Spark cluster {request.id} not found")

            update_fields = {'state': 'scaling', 'worker_count': request.worker_count}
            if request.executor_cores > 0:
                update_fields['executor_cores'] = request.executor_cores
            if request.executor_memory_gb > 0:
                update_fields['executor_memory_gb'] = request.executor_memory_gb

            self.db(self.db.spark_clusters.id == request.id).update(**update_fields)
            self.db.commit()

            logger.info(f"Scaling Spark cluster {request.id}")
            return self.GetSparkCluster(bigdata_pb2.GetByIdRequest(id=request.id), context)

        except Exception as e:
            logger.error(f"Error scaling Spark cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to scale Spark cluster: {str(e)}")

    def SubmitSparkJob(self, request: bigdata_pb2.SubmitSparkJobRequest,
                      context: grpc.ServicerContext) -> bigdata_pb2.SparkJob:
        """Submit Spark job to cluster."""
        try:
            cluster = self.db.spark_clusters[request.cluster_id]
            if not cluster:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Spark cluster {request.cluster_id} not found")

            job_id = self.db.spark_jobs.insert(
                name=request.job_name,
                spark_cluster_id=request.cluster_id,
                application_id=cluster.application_id,
                job_type='batch',
                state='pending',
                jar_file=request.jar_path,
                main_class=request.main_class,
                arguments=json.dumps(list(request.arguments)),
                spark_config=json.dumps(dict(request.spark_properties)),
                submitted_at=datetime.utcnow(),
            )
            self.db.commit()

            logger.info(f"Submitted Spark job {job_id} to cluster {request.cluster_id}")

            row = self.db.spark_jobs[job_id]
            return bigdata_pb2.SparkJob(
                id=row.id,
                cluster_id=row.spark_cluster_id,
                job_id=str(row.id),
                name=row.name,
                status=self._convert_job_status(row.state),
                submitted_at=Timestamp(seconds=int(row.submitted_at.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error submitting Spark job: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to submit Spark job: {str(e)}")

    def GetSparkJob(self, request: bigdata_pb2.GetByIdRequest,
                   context: grpc.ServicerContext) -> bigdata_pb2.SparkJob:
        """Get Spark job status."""
        try:
            row = self.db.spark_jobs[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Spark job {request.id} not found")

            return bigdata_pb2.SparkJob(
                id=row.id,
                cluster_id=row.spark_cluster_id,
                job_id=str(row.id),
                name=row.name,
                status=self._convert_job_status(row.state),
                status_message=row.error_message or '',
                submitted_at=Timestamp(seconds=int(row.submitted_at.timestamp())) if row.submitted_at else None,
                started_at=Timestamp(seconds=int(row.started_at.timestamp())) if row.started_at else None,
                completed_at=Timestamp(seconds=int(row.completed_at.timestamp())) if row.completed_at else None,
            )

        except Exception as e:
            logger.error(f"Error getting Spark job: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get Spark job: {str(e)}")

    def KillSparkJob(self, request: bigdata_pb2.DeleteRequest,
                    context: grpc.ServicerContext) -> Empty:
        """Kill running Spark job."""
        try:
            row = self.db.spark_jobs[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Spark job {request.id} not found")

            self.db(self.db.spark_jobs.id == request.id).update(state='cancelled')
            self.db.commit()

            logger.info(f"Killed Spark job {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error killing Spark job: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to kill Spark job: {str(e)}")

    # ===== Flink Cluster Operations =====

    def ListFlinkClusters(self, request: bigdata_pb2.ListRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.FlinkClusterList:
        """List Flink clusters with pagination."""
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            query = self.db.flink_clusters.is_active == True
            if request.filter:
                query &= self.db.flink_clusters.name.contains(request.filter)

            total_count = self.db(query).count()
            rows = self.db(query).select(
                limitby=(offset, offset + page_size),
                orderby=~self.db.flink_clusters.created_on
            )

            clusters = []
            for row in rows:
                cluster = bigdata_pb2.FlinkCluster(
                    id=row.id,
                    name=row.name,
                    description=row.description or '',
                    status=self._convert_cluster_status(row.state),
                    status_message=row.status_message or '',
                    jobmanager_host=row.jobmanager_endpoint.split(':')[0],
                    jobmanager_port=row.jobmanager_port,
                    taskmanager_count=row.taskmanager_count,
                    flink_version=row.version or '',
                    task_slots_per_taskmanager=row.taskmanager_slots,
                    taskmanager_memory_gb=row.taskmanager_memory_gb,
                    tags=json.loads(row.tags) if row.tags else {},
                    created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
                )
                clusters.append(cluster)

            pagination = types_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            return bigdata_pb2.FlinkClusterList(clusters=clusters, pagination=pagination)

        except Exception as e:
            logger.error(f"Error listing Flink clusters: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list Flink clusters: {str(e)}")

    def GetFlinkCluster(self, request: bigdata_pb2.GetByIdRequest,
                       context: grpc.ServicerContext) -> bigdata_pb2.FlinkCluster:
        """Get single Flink cluster by ID."""
        try:
            row = self.db.flink_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Flink cluster {request.id} not found")

            return bigdata_pb2.FlinkCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                status_message=row.status_message or '',
                jobmanager_host=row.jobmanager_endpoint.split(':')[0],
                jobmanager_port=row.jobmanager_port,
                taskmanager_count=row.taskmanager_count,
                flink_version=row.version or '',
                task_slots_per_taskmanager=row.taskmanager_slots,
                taskmanager_memory_gb=row.taskmanager_memory_gb,
                tags=json.loads(row.tags) if row.tags else {},
                created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error getting Flink cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get Flink cluster: {str(e)}")

    def CreateFlinkCluster(self, request: bigdata_pb2.CreateFlinkClusterRequest,
                          context: grpc.ServicerContext) -> bigdata_pb2.FlinkCluster:
        """Create new Flink cluster."""
        try:
            provisioner = self._get_provisioner(request.provider_id)

            cluster_id = self.db.flink_clusters.insert(
                name=request.name,
                description=request.description,
                provider_id=request.provider_id,
                application_id=1,
                state='creating',
                cluster_mode='kubernetes',
                jobmanager_endpoint=f"{request.jobmanager_host}:{request.jobmanager_port}",
                jobmanager_port=request.jobmanager_port or 6123,
                jobmanager_web_ui_port=8081,
                taskmanager_count=request.taskmanager_count or 3,
                taskmanager_slots=request.task_slots_per_taskmanager or 4,
                taskmanager_memory_gb=request.taskmanager_memory_gb or 8,
                tags=json.dumps(dict(request.tags)),
            )
            self.db.commit()

            logger.info(f"Created Flink cluster {cluster_id}: {request.name}")

            row = self.db.flink_clusters[cluster_id]
            return bigdata_pb2.FlinkCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                jobmanager_host=request.jobmanager_host,
                jobmanager_port=request.jobmanager_port or 6123,
                taskmanager_count=request.taskmanager_count or 3,
                task_slots_per_taskmanager=request.task_slots_per_taskmanager or 4,
                taskmanager_memory_gb=request.taskmanager_memory_gb or 8,
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating Flink cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create Flink cluster: {str(e)}")

    def DeleteFlinkCluster(self, request: bigdata_pb2.DeleteRequest,
                          context: grpc.ServicerContext) -> Empty:
        """Delete Flink cluster."""
        try:
            row = self.db.flink_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Flink cluster {request.id} not found")

            self.db(self.db.flink_clusters.id == request.id).update(
                state='terminating',
                is_active=False
            )
            self.db.commit()

            logger.info(f"Deleted Flink cluster {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error deleting Flink cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete Flink cluster: {str(e)}")

    def ScaleFlinkCluster(self, request: bigdata_pb2.ScaleFlinkRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.FlinkCluster:
        """Scale Flink cluster."""
        try:
            row = self.db.flink_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Flink cluster {request.id} not found")

            self.db(self.db.flink_clusters.id == request.id).update(
                state='scaling',
                taskmanager_count=request.taskmanager_count
            )
            self.db.commit()

            logger.info(f"Scaling Flink cluster {request.id}")
            return self.GetFlinkCluster(bigdata_pb2.GetByIdRequest(id=request.id), context)

        except Exception as e:
            logger.error(f"Error scaling Flink cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to scale Flink cluster: {str(e)}")

    def SubmitFlinkJob(self, request: bigdata_pb2.SubmitFlinkJobRequest,
                      context: grpc.ServicerContext) -> bigdata_pb2.FlinkJob:
        """Submit Flink job to cluster."""
        try:
            cluster = self.db.flink_clusters[request.cluster_id]
            if not cluster:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Flink cluster {request.cluster_id} not found")

            job_id = self.db.flink_jobs.insert(
                name=request.job_name,
                flink_cluster_id=request.cluster_id,
                application_id=cluster.application_id,
                job_type='batch',
                state='pending',
                jar_file=request.jar_path,
                main_class=request.main_class,
                arguments=json.dumps(list(request.arguments)),
                flink_config=json.dumps(dict(request.flink_properties)),
                parallelism=request.parallelism or 1,
                submitted_at=datetime.utcnow(),
            )
            self.db.commit()

            logger.info(f"Submitted Flink job {job_id} to cluster {request.cluster_id}")

            row = self.db.flink_jobs[job_id]
            return bigdata_pb2.FlinkJob(
                id=row.id,
                cluster_id=row.flink_cluster_id,
                job_id=str(row.id),
                name=row.name,
                status=self._convert_job_status(row.state),
                submitted_at=Timestamp(seconds=int(row.submitted_at.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error submitting Flink job: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to submit Flink job: {str(e)}")

    def GetFlinkJob(self, request: bigdata_pb2.GetByIdRequest,
                   context: grpc.ServicerContext) -> bigdata_pb2.FlinkJob:
        """Get Flink job status."""
        try:
            row = self.db.flink_jobs[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Flink job {request.id} not found")

            return bigdata_pb2.FlinkJob(
                id=row.id,
                cluster_id=row.flink_cluster_id,
                job_id=str(row.id),
                name=row.name,
                status=self._convert_job_status(row.state),
                status_message=row.error_message or '',
                submitted_at=Timestamp(seconds=int(row.submitted_at.timestamp())) if row.submitted_at else None,
                started_at=Timestamp(seconds=int(row.started_at.timestamp())) if row.started_at else None,
                completed_at=Timestamp(seconds=int(row.completed_at.timestamp())) if row.completed_at else None,
            )

        except Exception as e:
            logger.error(f"Error getting Flink job: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get Flink job: {str(e)}")

    def CancelFlinkJob(self, request: bigdata_pb2.DeleteRequest,
                      context: grpc.ServicerContext) -> Empty:
        """Cancel running Flink job."""
        try:
            row = self.db.flink_jobs[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Flink job {request.id} not found")

            self.db(self.db.flink_jobs.id == request.id).update(state='cancelled')
            self.db.commit()

            logger.info(f"Cancelled Flink job {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error cancelling Flink job: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to cancel Flink job: {str(e)}")

    def CreateSavepoint(self, request: bigdata_pb2.CreateSavepointRequest,
                       context: grpc.ServicerContext) -> bigdata_pb2.Savepoint:
        """Create savepoint for Flink job."""
        try:
            job = self.db.flink_jobs[request.job_id]
            if not job:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Flink job {request.job_id} not found")

            # Mock savepoint creation (actual implementation would call Flink API)
            import uuid
            savepoint_path = f"{request.savepoint_target_directory}/{uuid.uuid4()}"

            return bigdata_pb2.Savepoint(
                id=1,
                job_id=request.job_id,
                savepoint_path=savepoint_path,
                created_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating savepoint: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create savepoint: {str(e)}")

    # ===== HBase Cluster Operations =====

    def ListHBaseClusters(self, request: bigdata_pb2.ListRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.HBaseClusterList:
        """List HBase clusters with pagination."""
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            query = self.db.hbase_clusters.is_active == True
            if request.filter:
                query &= self.db.hbase_clusters.name.contains(request.filter)

            total_count = self.db(query).count()
            rows = self.db(query).select(
                limitby=(offset, offset + page_size),
                orderby=~self.db.hbase_clusters.created_on
            )

            clusters = []
            for row in rows:
                cluster = bigdata_pb2.HBaseCluster(
                    id=row.id,
                    name=row.name,
                    description=row.description or '',
                    status=self._convert_cluster_status(row.state),
                    status_message=row.status_message or '',
                    zookeeper_quorum=row.zookeeper_quorum,
                    zookeeper_client_port=2181,
                    regionserver_count=row.regionserver_count,
                    hbase_version=row.version or '',
                    tags=json.loads(row.tags) if row.tags else {},
                    created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
                )
                clusters.append(cluster)

            pagination = types_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            return bigdata_pb2.HBaseClusterList(clusters=clusters, pagination=pagination)

        except Exception as e:
            logger.error(f"Error listing HBase clusters: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list HBase clusters: {str(e)}")

    def GetHBaseCluster(self, request: bigdata_pb2.GetByIdRequest,
                       context: grpc.ServicerContext) -> bigdata_pb2.HBaseCluster:
        """Get single HBase cluster by ID."""
        try:
            row = self.db.hbase_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"HBase cluster {request.id} not found")

            return bigdata_pb2.HBaseCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                status_message=row.status_message or '',
                zookeeper_quorum=row.zookeeper_quorum,
                zookeeper_client_port=2181,
                regionserver_count=row.regionserver_count,
                hbase_version=row.version or '',
                tags=json.loads(row.tags) if row.tags else {},
                created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error getting HBase cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get HBase cluster: {str(e)}")

    def CreateHBaseCluster(self, request: bigdata_pb2.CreateHBaseClusterRequest,
                          context: grpc.ServicerContext) -> bigdata_pb2.HBaseCluster:
        """Create new HBase cluster."""
        try:
            provisioner = self._get_provisioner(request.provider_id)

            cluster_id = self.db.hbase_clusters.insert(
                name=request.name,
                description=request.description,
                provider_id=request.provider_id,
                application_id=1,
                state='creating',
                cluster_mode='kubernetes',
                zookeeper_quorum=request.zookeeper_quorum,
                hmaster_endpoint=f"hmaster-{request.name}:16010",
                hmaster_port=16010,
                regionserver_count=request.regionserver_count or 3,
                tags=json.dumps(dict(request.tags)),
            )
            self.db.commit()

            logger.info(f"Created HBase cluster {cluster_id}: {request.name}")

            row = self.db.hbase_clusters[cluster_id]
            return bigdata_pb2.HBaseCluster(
                id=row.id,
                name=row.name,
                description=row.description or '',
                status=self._convert_cluster_status(row.state),
                zookeeper_quorum=request.zookeeper_quorum,
                zookeeper_client_port=request.zookeeper_client_port or 2181,
                regionserver_count=request.regionserver_count or 3,
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating HBase cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create HBase cluster: {str(e)}")

    def DeleteHBaseCluster(self, request: bigdata_pb2.DeleteRequest,
                          context: grpc.ServicerContext) -> Empty:
        """Delete HBase cluster."""
        try:
            row = self.db.hbase_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"HBase cluster {request.id} not found")

            self.db(self.db.hbase_clusters.id == request.id).update(
                state='terminating',
                is_active=False
            )
            self.db.commit()

            logger.info(f"Deleted HBase cluster {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error deleting HBase cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete HBase cluster: {str(e)}")

    def ScaleHBaseCluster(self, request: bigdata_pb2.ScaleHBaseRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.HBaseCluster:
        """Scale HBase cluster."""
        try:
            row = self.db.hbase_clusters[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"HBase cluster {request.id} not found")

            self.db(self.db.hbase_clusters.id == request.id).update(
                state='scaling',
                regionserver_count=request.regionserver_count
            )
            self.db.commit()

            logger.info(f"Scaling HBase cluster {request.id}")
            return self.GetHBaseCluster(bigdata_pb2.GetByIdRequest(id=request.id), context)

        except Exception as e:
            logger.error(f"Error scaling HBase cluster: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to scale HBase cluster: {str(e)}")

    # ===== Storage Backend Operations =====

    def ListStorageBackends(self, request: bigdata_pb2.ListRequest,
                           context: grpc.ServicerContext) -> bigdata_pb2.StorageBackendList:
        """List storage backends with pagination."""
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            query = self.db.storage_backends.is_active == True
            if request.filter:
                query &= self.db.storage_backends.name.contains(request.filter)

            total_count = self.db(query).count()
            rows = self.db(query).select(
                limitby=(offset, offset + page_size),
                orderby=~self.db.storage_backends.created_on
            )

            backends = []
            for row in rows:
                storage_type_map = {
                    's3': bigdata_pb2.STORAGE_TYPE_S3,
                    'gcs': bigdata_pb2.STORAGE_TYPE_GCS,
                    'azure_blob': bigdata_pb2.STORAGE_TYPE_AZURE_BLOB,
                    'hdfs': bigdata_pb2.STORAGE_TYPE_HDFS,
                    'minio': bigdata_pb2.STORAGE_TYPE_S3,
                }

                backend = bigdata_pb2.StorageBackend(
                    id=row.id,
                    name=row.name,
                    description=row.description or '',
                    storage_type=storage_type_map.get(row.storage_type, bigdata_pb2.STORAGE_TYPE_UNSPECIFIED),
                    endpoint=row.endpoint,
                    enabled=row.is_active,
                    configuration=row.configuration or '{}',
                    tags=json.loads(row.tags) if row.tags else {},
                    created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
                )
                backends.append(backend)

            pagination = types_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            return bigdata_pb2.StorageBackendList(backends=backends, pagination=pagination)

        except Exception as e:
            logger.error(f"Error listing storage backends: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list storage backends: {str(e)}")

    def GetStorageBackend(self, request: bigdata_pb2.GetByIdRequest,
                         context: grpc.ServicerContext) -> bigdata_pb2.StorageBackend:
        """Get single storage backend by ID."""
        try:
            row = self.db.storage_backends[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Storage backend {request.id} not found")

            storage_type_map = {
                's3': bigdata_pb2.STORAGE_TYPE_S3,
                'gcs': bigdata_pb2.STORAGE_TYPE_GCS,
                'azure_blob': bigdata_pb2.STORAGE_TYPE_AZURE_BLOB,
                'hdfs': bigdata_pb2.STORAGE_TYPE_HDFS,
                'minio': bigdata_pb2.STORAGE_TYPE_S3,
            }

            return bigdata_pb2.StorageBackend(
                id=row.id,
                name=row.name,
                description=row.description or '',
                storage_type=storage_type_map.get(row.storage_type, bigdata_pb2.STORAGE_TYPE_UNSPECIFIED),
                endpoint=row.endpoint,
                enabled=row.is_active,
                configuration=row.configuration or '{}',
                tags=json.loads(row.tags) if row.tags else {},
                created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
            )

        except Exception as e:
            logger.error(f"Error getting storage backend: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to get storage backend: {str(e)}")

    def CreateStorageBackend(self, request: bigdata_pb2.CreateStorageBackendRequest,
                            context: grpc.ServicerContext) -> bigdata_pb2.StorageBackend:
        """Create new storage backend."""
        try:
            storage_type_map = {
                bigdata_pb2.STORAGE_TYPE_S3: 's3',
                bigdata_pb2.STORAGE_TYPE_GCS: 'gcs',
                bigdata_pb2.STORAGE_TYPE_AZURE_BLOB: 'azure_blob',
                bigdata_pb2.STORAGE_TYPE_HDFS: 'hdfs',
            }

            backend_id = self.db.storage_backends.insert(
                name=request.name,
                description=request.description,
                provider_id=1,
                application_id=1,
                storage_type=storage_type_map.get(request.storage_type, 's3'),
                endpoint=request.endpoint,
                bucket_name=request.name,
                configuration=request.configuration or '{}',
                status='creating',
                tags=json.dumps(dict(request.tags)),
            )
            self.db.commit()

            logger.info(f"Created storage backend {backend_id}: {request.name}")

            row = self.db.storage_backends[backend_id]
            return bigdata_pb2.StorageBackend(
                id=row.id,
                name=row.name,
                description=row.description or '',
                storage_type=request.storage_type,
                endpoint=row.endpoint,
                enabled=row.is_active,
                configuration=row.configuration or '{}',
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating storage backend: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create storage backend: {str(e)}")

    def DeleteStorageBackend(self, request: bigdata_pb2.DeleteRequest,
                            context: grpc.ServicerContext) -> Empty:
        """Delete storage backend."""
        try:
            row = self.db.storage_backends[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Storage backend {request.id} not found")

            self.db(self.db.storage_backends.id == request.id).update(
                status='deleting',
                is_active=False
            )
            self.db.commit()

            logger.info(f"Deleted storage backend {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error deleting storage backend: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete storage backend: {str(e)}")

    # ===== Iceberg Catalog Operations =====

    def ListIcebergCatalogs(self, request: bigdata_pb2.ListRequest,
                           context: grpc.ServicerContext) -> bigdata_pb2.IcebergCatalogList:
        """List Iceberg catalogs with pagination."""
        try:
            page = request.page or 1
            page_size = request.page_size or 20
            offset = (page - 1) * page_size

            query = self.db.iceberg_catalogs.is_active == True
            if request.filter:
                query &= self.db.iceberg_catalogs.name.contains(request.filter)

            total_count = self.db(query).count()
            rows = self.db(query).select(
                limitby=(offset, offset + page_size),
                orderby=~self.db.iceberg_catalogs.created_on
            )

            catalogs = []
            for row in rows:
                catalog = bigdata_pb2.IcebergCatalog(
                    id=row.id,
                    storage_backend_id=row.storage_backend_id,
                    name=row.name,
                    description=row.description or '',
                    warehouse_location=row.warehouse_location,
                    tags=json.loads(row.tags) if row.tags else {},
                    created_at=Timestamp(seconds=int(row.created_on.timestamp())),
                    updated_at=Timestamp(seconds=int(row.modified_on.timestamp())),
                )
                catalogs.append(catalog)

            pagination = types_pb2.Pagination(
                page=page,
                page_size=page_size,
                total=total_count,
                total_pages=(total_count + page_size - 1) // page_size,
            )

            return bigdata_pb2.IcebergCatalogList(catalogs=catalogs, pagination=pagination)

        except Exception as e:
            logger.error(f"Error listing Iceberg catalogs: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to list Iceberg catalogs: {str(e)}")

    def CreateIcebergCatalog(self, request: bigdata_pb2.CreateIcebergCatalogRequest,
                            context: grpc.ServicerContext) -> bigdata_pb2.IcebergCatalog:
        """Create new Iceberg catalog."""
        try:
            backend = self.db.storage_backends[request.storage_backend_id]
            if not backend:
                context.abort(grpc.StatusCode.NOT_FOUND,
                            f"Storage backend {request.storage_backend_id} not found")

            catalog_id = self.db.iceberg_catalogs.insert(
                name=request.name,
                description=request.description,
                provider_id=backend.provider_id,
                application_id=backend.application_id,
                catalog_type='rest',
                storage_backend_id=request.storage_backend_id,
                warehouse_location=request.warehouse_location,
                configuration=json.dumps(dict(request.catalog_properties)),
                status='creating',
                tags=json.dumps(dict(request.tags)),
            )
            self.db.commit()

            logger.info(f"Created Iceberg catalog {catalog_id}: {request.name}")

            row = self.db.iceberg_catalogs[catalog_id]
            return bigdata_pb2.IcebergCatalog(
                id=row.id,
                storage_backend_id=row.storage_backend_id,
                name=row.name,
                description=row.description or '',
                warehouse_location=row.warehouse_location,
                catalog_properties=dict(request.catalog_properties),
                tags=dict(request.tags),
                created_at=self._get_current_timestamp(),
                updated_at=self._get_current_timestamp(),
            )

        except Exception as e:
            logger.error(f"Error creating Iceberg catalog: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to create Iceberg catalog: {str(e)}")

    def DeleteIcebergCatalog(self, request: bigdata_pb2.DeleteRequest,
                            context: grpc.ServicerContext) -> Empty:
        """Delete Iceberg catalog."""
        try:
            row = self.db.iceberg_catalogs[request.id]
            if not row:
                context.abort(grpc.StatusCode.NOT_FOUND, f"Iceberg catalog {request.id} not found")

            self.db(self.db.iceberg_catalogs.id == request.id).update(
                status='deleting',
                is_active=False
            )
            self.db.commit()

            logger.info(f"Deleted Iceberg catalog {request.id}")
            return Empty()

        except Exception as e:
            logger.error(f"Error deleting Iceberg catalog: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Failed to delete Iceberg catalog: {str(e)}")

    # ===== Streaming Operations =====

    def StreamClusterEvents(self, request: bigdata_pb2.StreamRequest,
                           context: grpc.ServicerContext) -> AsyncIterator[bigdata_pb2.ClusterEvent]:
        """Stream real-time cluster events."""
        try:
            logger.info("Client connected to cluster event stream")

            event_count = 0
            engine_types = list(request.engine_types) if request.engine_types else [
                bigdata_pb2.BIG_DATA_ENGINE_HDFS,
                bigdata_pb2.BIG_DATA_ENGINE_TRINO,
                bigdata_pb2.BIG_DATA_ENGINE_SPARK,
                bigdata_pb2.BIG_DATA_ENGINE_FLINK,
                bigdata_pb2.BIG_DATA_ENGINE_HBASE,
            ]

            while not context.cancelled():
                event_count += 1
                engine_type = engine_types[event_count % len(engine_types)]

                event = bigdata_pb2.ClusterEvent(
                    event_id=f"evt-{event_count}",
                    engine_type=engine_type,
                    cluster_id=f"cluster-{event_count % 10}",
                    cluster_name=f"cluster-{event_count % 10}",
                    event_type="health_check",
                    message=f"Cluster health check #{event_count}",
                    cluster_status=bigdata_pb2.CLUSTER_STATUS_RUNNING,
                    timestamp=self._get_current_timestamp(),
                )

                yield event

                import time
                time.sleep(2)

        except Exception as e:
            logger.error(f"Error in cluster event stream: {e}", exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"Event stream error: {str(e)}")
