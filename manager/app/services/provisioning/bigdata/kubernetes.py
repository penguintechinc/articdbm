"""
Kubernetes big data provisioner using native operators for distributed computing.

This module implements big data cluster provisioning on Kubernetes using
specialized operators for Spark, Flink, Trino, HDFS, and HBase. It leverages
Custom Resource Definitions (CRDs) provided by each operator for declarative
cluster management.

Supported Operators:
    - Spark: GoogleCloudPlatform/spark-on-k8s-operator (SparkApplication CRD)
    - Flink: apache/flink-kubernetes-operator (FlinkDeployment CRD)
    - Trino: trinodb/charts or Starburst operator (TrinoCluster CRD)
    - HDFS: Stackable HDFS Operator (HdfsCluster CRD)
    - HBase: Stackable HBase Operator (HbaseCluster CRD)
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from kubernetes_asyncio import client, config as k8s_config
from kubernetes_asyncio.client.rest import ApiException

from .base import (
    BaseBigDataProvisioner,
    BigDataProvisionerConfig,
    BigDataProvisionerException,
    ClusterConfig,
    ClusterType,
    JobConfig,
    JobStatus,
)

logger = logging.getLogger(__name__)


class KubernetesBigDataProvisioner(BaseBigDataProvisioner):
    """
    Kubernetes-based big data provisioner using operators.

    This provisioner manages big data clusters on Kubernetes by creating and
    managing Custom Resources for various operators. Each cluster type maps
    to a specific CRD provided by the respective operator.
    """

    def __init__(self, config: BigDataProvisionerConfig):
        """
        Initialize Kubernetes big data provisioner.

        Args:
            config: Provisioner configuration
        """
        super().__init__(config)
        self.namespace = config.credentials.get('namespace', 'default')
        self.kubeconfig_path = config.credentials.get('kubeconfig_path')
        self._core_api: Optional[client.CoreV1Api] = None
        self._custom_api: Optional[client.CustomObjectsApi] = None
        self._apps_api: Optional[client.AppsV1Api] = None
        self._metrics_api: Optional[client.CustomObjectsApi] = None

    async def _ensure_initialized(self):
        """Ensure Kubernetes API clients are initialized."""
        if self._initialized:
            return

        try:
            if self.kubeconfig_path:
                await k8s_config.load_kube_config(config_file=self.kubeconfig_path)
            else:
                try:
                    k8s_config.load_incluster_config()
                except k8s_config.ConfigException:
                    await k8s_config.load_kube_config()

            self._core_api = client.CoreV1Api()
            self._custom_api = client.CustomObjectsApi()
            self._apps_api = client.AppsV1Api()
            self._metrics_api = client.CustomObjectsApi()
            self._initialized = True
            logger.info("Kubernetes API clients initialized successfully")
        except Exception as e:
            raise BigDataProvisionerException(
                f"Failed to initialize Kubernetes clients: {str(e)}",
                provider='kubernetes',
                original_error=e
            )

    def _map_instance_size_to_resources(
        self,
        instance_size: str
    ) -> Dict[str, str]:
        """
        Map instance size strings to Kubernetes resource requests/limits.

        Args:
            instance_size: Instance size (small, medium, large, xlarge, 2xlarge)

        Returns:
            Dictionary with cpu and memory resource specifications
        """
        size_map = {
            'small': {'cpu': '1', 'memory': '2Gi'},
            'medium': {'cpu': '2', 'memory': '4Gi'},
            'large': {'cpu': '4', 'memory': '8Gi'},
            'xlarge': {'cpu': '8', 'memory': '16Gi'},
            '2xlarge': {'cpu': '16', 'memory': '32Gi'},
            '4xlarge': {'cpu': '32', 'memory': '64Gi'},
        }
        return size_map.get(instance_size, size_map['medium'])

    # HDFS Cluster Management
    async def create_hdfs_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """
        Create an HDFS cluster using Stackable HDFS Operator.

        Args:
            cluster_config: HDFS cluster configuration

        Returns:
            Dictionary with cluster details including endpoints
        """
        await self._ensure_initialized()

        try:
            namenode_resources = self._map_instance_size_to_resources(
                cluster_config.master_instance_size
            )
            datanode_resources = self._map_instance_size_to_resources(
                cluster_config.worker_instance_size
            )

            hdfs_cluster = {
                'apiVersion': 'hdfs.stackable.tech/v1alpha1',
                'kind': 'HdfsCluster',
                'metadata': {
                    'name': cluster_config.name,
                    'namespace': self.namespace,
                    'labels': cluster_config.labels,
                    'annotations': cluster_config.annotations,
                },
                'spec': {
                    'image': {
                        'productVersion': cluster_config.version or '3.3.6',
                    },
                    'clusterConfig': {
                        'dfsReplication': 3 if cluster_config.high_availability else 1,
                        'vectorAggregatorConfigMapName': 'hdfs-vector-aggregator',
                    },
                    'nameNodes': {
                        'roleGroups': {
                            'default': {
                                'replicas': cluster_config.master_count,
                                'config': {
                                    'resources': {
                                        'cpu': {
                                            'min': namenode_resources['cpu'],
                                            'max': namenode_resources['cpu'],
                                        },
                                        'memory': {
                                            'limit': namenode_resources['memory'],
                                        },
                                        'storage': {
                                            'data': {
                                                'capacity': f"{cluster_config.storage_size_gb}Gi",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    'dataNodes': {
                        'roleGroups': {
                            'default': {
                                'replicas': cluster_config.worker_count,
                                'config': {
                                    'resources': {
                                        'cpu': {
                                            'min': datanode_resources['cpu'],
                                            'max': datanode_resources['cpu'],
                                        },
                                        'memory': {
                                            'limit': datanode_resources['memory'],
                                        },
                                        'storage': {
                                            'data': {
                                                'capacity': f"{cluster_config.storage_size_gb}Gi",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    'journalNodes': {
                        'roleGroups': {
                            'default': {
                                'replicas': 3 if cluster_config.high_availability else 1,
                            },
                        },
                    },
                },
            }

            await self._custom_api.create_namespaced_custom_object(
                group='hdfs.stackable.tech',
                version='v1alpha1',
                namespace=self.namespace,
                plural='hdfsclusters',
                body=hdfs_cluster,
            )

            # Wait for cluster to be ready
            await asyncio.sleep(5)

            namenode_endpoint = f"{cluster_config.name}-namenode-0.{cluster_config.name}-namenode.{self.namespace}.svc.cluster.local"
            webhdfs_endpoint = f"http://{namenode_endpoint}:9870"

            return {
                'cluster_id': f"{self.namespace}/{cluster_config.name}",
                'namenode_endpoint': namenode_endpoint,
                'namenode_port': 9000,
                'webhdfs_endpoint': webhdfs_endpoint,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'namespace': self.namespace,
                    'name': cluster_config.name,
                    'operator': 'stackable-hdfs-operator',
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to create HDFS cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_config.name,
                original_error=e
            )
        except Exception as e:
            raise BigDataProvisionerException(
                f"Unexpected error creating HDFS cluster: {str(e)}",
                provider='kubernetes',
                cluster_id=cluster_config.name,
                original_error=e
            )

    async def delete_hdfs_cluster(self, cluster_id: str) -> bool:
        """Delete an HDFS cluster."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')
            await self._custom_api.delete_namespaced_custom_object(
                group='hdfs.stackable.tech',
                version='v1alpha1',
                namespace=namespace,
                plural='hdfsclusters',
                name=name,
            )
            logger.info(f"HDFS cluster {cluster_id} deleted successfully")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"HDFS cluster {cluster_id} not found")
                return False
            raise BigDataProvisionerException(
                f"Failed to delete HDFS cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )
        except Exception as e:
            raise BigDataProvisionerException(
                f"Unexpected error deleting HDFS cluster: {str(e)}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_hdfs_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale an HDFS cluster by updating DataNode count."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')

            # Get current cluster
            cluster = await self._custom_api.get_namespaced_custom_object(
                group='hdfs.stackable.tech',
                version='v1alpha1',
                namespace=namespace,
                plural='hdfsclusters',
                name=name,
            )

            # Update worker count if specified
            if 'worker_count' in scale_config:
                cluster['spec']['dataNodes']['roleGroups']['default']['replicas'] = scale_config['worker_count']

            # Update storage size if specified
            if 'storage_size_gb' in scale_config:
                storage_capacity = f"{scale_config['storage_size_gb']}Gi"
                cluster['spec']['dataNodes']['roleGroups']['default']['config']['resources']['storage']['data']['capacity'] = storage_capacity

            # Apply the patch
            await self._custom_api.patch_namespaced_custom_object(
                group='hdfs.stackable.tech',
                version='v1alpha1',
                namespace=namespace,
                plural='hdfsclusters',
                name=name,
                body=cluster,
            )

            return {
                'cluster_id': cluster_id,
                'status': 'scaling',
                'updated_at': datetime.utcnow().isoformat(),
                'new_worker_count': scale_config.get('worker_count'),
                'new_storage_size_gb': scale_config.get('storage_size_gb'),
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to scale HDFS cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )
        except Exception as e:
            raise BigDataProvisionerException(
                f"Unexpected error scaling HDFS cluster: {str(e)}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    # Trino Cluster Management
    async def create_trino_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create a Trino cluster using TrinoCluster CRD."""
        await self._ensure_initialized()

        try:
            coordinator_resources = self._map_instance_size_to_resources(
                cluster_config.master_instance_size
            )
            worker_resources = self._map_instance_size_to_resources(
                cluster_config.worker_instance_size
            )

            trino_cluster = {
                'apiVersion': 'trino.io/v1alpha1',
                'kind': 'TrinoCluster',
                'metadata': {
                    'name': cluster_config.name,
                    'namespace': self.namespace,
                    'labels': cluster_config.labels,
                    'annotations': cluster_config.annotations,
                },
                'spec': {
                    'image': f"trinodb/trino:{cluster_config.version or '435'}",
                    'coordinator': {
                        'replicas': 1,
                        'resources': {
                            'requests': coordinator_resources,
                            'limits': coordinator_resources,
                        },
                        'config': {
                            'query.max-memory': '50GB',
                            'query.max-memory-per-node': '8GB',
                        },
                    },
                    'worker': {
                        'replicas': cluster_config.worker_count,
                        'resources': {
                            'requests': worker_resources,
                            'limits': worker_resources,
                        },
                        'autoscaling': {
                            'enabled': bool(cluster_config.auto_scaling),
                            'minReplicas': cluster_config.auto_scaling.get('min_workers', 2) if cluster_config.auto_scaling else 2,
                            'maxReplicas': cluster_config.auto_scaling.get('max_workers', 10) if cluster_config.auto_scaling else 10,
                            'targetCPUUtilizationPercentage': 80,
                        },
                    },
                    'catalogs': cluster_config.custom_config.get('catalogs', {}),
                    'service': {
                        'type': 'ClusterIP',
                        'port': 8080,
                    },
                    'security': {
                        'authentication': {
                            'type': 'PASSWORD',
                        },
                    },
                },
            }

            await self._custom_api.create_namespaced_custom_object(
                group='trino.io',
                version='v1alpha1',
                namespace=self.namespace,
                plural='trinoclusters',
                body=trino_cluster,
            )

            coordinator_endpoint = f"{cluster_config.name}-coordinator.{self.namespace}.svc.cluster.local"
            web_ui_endpoint = f"http://{coordinator_endpoint}:8080"

            return {
                'cluster_id': f"{self.namespace}/{cluster_config.name}",
                'coordinator_endpoint': coordinator_endpoint,
                'coordinator_port': 8080,
                'web_ui_endpoint': web_ui_endpoint,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'namespace': self.namespace,
                    'name': cluster_config.name,
                    'operator': 'trino-operator',
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to create Trino cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_config.name,
                original_error=e
            )
        except Exception as e:
            raise BigDataProvisionerException(
                f"Unexpected error creating Trino cluster: {str(e)}",
                provider='kubernetes',
                cluster_id=cluster_config.name,
                original_error=e
            )

    async def delete_trino_cluster(self, cluster_id: str) -> bool:
        """Delete a Trino cluster."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')
            await self._custom_api.delete_namespaced_custom_object(
                group='trino.io',
                version='v1alpha1',
                namespace=namespace,
                plural='trinoclusters',
                name=name,
            )
            logger.info(f"Trino cluster {cluster_id} deleted successfully")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Trino cluster {cluster_id} not found")
                return False
            raise BigDataProvisionerException(
                f"Failed to delete Trino cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_trino_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale a Trino cluster by updating worker count."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')

            cluster = await self._custom_api.get_namespaced_custom_object(
                group='trino.io',
                version='v1alpha1',
                namespace=namespace,
                plural='trinoclusters',
                name=name,
            )

            if 'worker_count' in scale_config:
                cluster['spec']['worker']['replicas'] = scale_config['worker_count']

            if 'worker_instance_size' in scale_config:
                new_resources = self._map_instance_size_to_resources(
                    scale_config['worker_instance_size']
                )
                cluster['spec']['worker']['resources']['requests'] = new_resources
                cluster['spec']['worker']['resources']['limits'] = new_resources

            await self._custom_api.patch_namespaced_custom_object(
                group='trino.io',
                version='v1alpha1',
                namespace=namespace,
                plural='trinoclusters',
                name=name,
                body=cluster,
            )

            return {
                'cluster_id': cluster_id,
                'status': 'scaling',
                'updated_at': datetime.utcnow().isoformat(),
                'new_worker_count': scale_config.get('worker_count'),
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to scale Trino cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    # Spark Cluster Management
    async def create_spark_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """
        Create a Spark cluster using spark-on-k8s-operator.

        Note: spark-on-k8s-operator typically runs jobs, not persistent clusters.
        This creates a SparkApplication template for job submissions.
        """
        await self._ensure_initialized()

        try:
            # For Spark on K8s, we create a ConfigMap with cluster configuration
            # that can be referenced by SparkApplications
            driver_resources = self._map_instance_size_to_resources(
                cluster_config.master_instance_size
            )
            executor_resources = self._map_instance_size_to_resources(
                cluster_config.worker_instance_size
            )

            config_map = {
                'apiVersion': 'v1',
                'kind': 'ConfigMap',
                'metadata': {
                    'name': f"{cluster_config.name}-config",
                    'namespace': self.namespace,
                    'labels': cluster_config.labels,
                },
                'data': {
                    'spark-version': cluster_config.version or '3.5.0',
                    'executor-count': str(cluster_config.worker_count),
                    'driver-cpu': driver_resources['cpu'],
                    'driver-memory': driver_resources['memory'],
                    'executor-cpu': executor_resources['cpu'],
                    'executor-memory': executor_resources['memory'],
                    'storage-size-gb': str(cluster_config.storage_size_gb),
                },
            }

            await self._core_api.create_namespaced_config_map(
                namespace=self.namespace,
                body=config_map,
            )

            master_endpoint = f"spark://{cluster_config.name}-master.{self.namespace}.svc.cluster.local:7077"
            web_ui_endpoint = f"http://{cluster_config.name}-master.{self.namespace}.svc.cluster.local:8080"

            return {
                'cluster_id': f"{self.namespace}/{cluster_config.name}",
                'master_endpoint': master_endpoint,
                'master_port': 7077,
                'web_ui_endpoint': web_ui_endpoint,
                'status': 'ready',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'namespace': self.namespace,
                    'name': cluster_config.name,
                    'operator': 'spark-on-k8s-operator',
                    'config_map': f"{cluster_config.name}-config",
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to create Spark cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_config.name,
                original_error=e
            )

    async def delete_spark_cluster(self, cluster_id: str) -> bool:
        """Delete Spark cluster configuration."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')
            await self._core_api.delete_namespaced_config_map(
                name=f"{name}-config",
                namespace=namespace,
            )
            logger.info(f"Spark cluster {cluster_id} deleted successfully")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Spark cluster {cluster_id} not found")
                return False
            raise BigDataProvisionerException(
                f"Failed to delete Spark cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_spark_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update Spark cluster configuration for future jobs."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')

            config_map = await self._core_api.read_namespaced_config_map(
                name=f"{name}-config",
                namespace=namespace,
            )

            if 'worker_count' in scale_config:
                config_map.data['executor-count'] = str(scale_config['worker_count'])

            if 'worker_instance_size' in scale_config:
                new_resources = self._map_instance_size_to_resources(
                    scale_config['worker_instance_size']
                )
                config_map.data['executor-cpu'] = new_resources['cpu']
                config_map.data['executor-memory'] = new_resources['memory']

            await self._core_api.patch_namespaced_config_map(
                name=f"{name}-config",
                namespace=namespace,
                body=config_map,
            )

            return {
                'cluster_id': cluster_id,
                'status': 'updated',
                'updated_at': datetime.utcnow().isoformat(),
                'new_worker_count': scale_config.get('worker_count'),
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to scale Spark cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    # Flink Cluster Management
    async def create_flink_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create a Flink cluster using flink-kubernetes-operator."""
        await self._ensure_initialized()

        try:
            jobmanager_resources = self._map_instance_size_to_resources(
                cluster_config.master_instance_size
            )
            taskmanager_resources = self._map_instance_size_to_resources(
                cluster_config.worker_instance_size
            )

            flink_deployment = {
                'apiVersion': 'flink.apache.org/v1beta1',
                'kind': 'FlinkDeployment',
                'metadata': {
                    'name': cluster_config.name,
                    'namespace': self.namespace,
                    'labels': cluster_config.labels,
                    'annotations': cluster_config.annotations,
                },
                'spec': {
                    'image': f"flink:{cluster_config.version or '1.18'}",
                    'flinkVersion': 'v1_18',
                    'flinkConfiguration': {
                        'taskmanager.numberOfTaskSlots': '4',
                        'state.backend': 'rocksdb',
                        'state.checkpoints.dir': cluster_config.storage_backend.get('checkpoint_dir', 's3://flink-checkpoints'),
                        'state.savepoints.dir': cluster_config.storage_backend.get('savepoint_dir', 's3://flink-savepoints'),
                        'execution.checkpointing.interval': '5min',
                        'execution.checkpointing.mode': 'EXACTLY_ONCE',
                        'high-availability': 'kubernetes' if cluster_config.high_availability else 'NONE',
                    },
                    'serviceAccount': 'flink',
                    'jobManager': {
                        'replicas': 1,
                        'resource': {
                            'memory': jobmanager_resources['memory'],
                            'cpu': float(jobmanager_resources['cpu']),
                        },
                    },
                    'taskManager': {
                        'replicas': cluster_config.worker_count,
                        'resource': {
                            'memory': taskmanager_resources['memory'],
                            'cpu': float(taskmanager_resources['cpu']),
                        },
                    },
                    'podTemplate': {
                        'spec': {
                            'containers': [{
                                'name': 'flink-main-container',
                                'volumeMounts': [{
                                    'name': 'flink-storage',
                                    'mountPath': '/opt/flink/data',
                                }],
                            }],
                            'volumes': [{
                                'name': 'flink-storage',
                                'emptyDir': {
                                    'sizeLimit': f"{cluster_config.storage_size_gb}Gi",
                                },
                            }],
                        },
                    },
                },
            }

            await self._custom_api.create_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=self.namespace,
                plural='flinkdeployments',
                body=flink_deployment,
            )

            jobmanager_endpoint = f"{cluster_config.name}-rest.{self.namespace}.svc.cluster.local"
            web_ui_endpoint = f"http://{jobmanager_endpoint}:8081"

            return {
                'cluster_id': f"{self.namespace}/{cluster_config.name}",
                'jobmanager_endpoint': jobmanager_endpoint,
                'jobmanager_port': 8081,
                'web_ui_endpoint': web_ui_endpoint,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'namespace': self.namespace,
                    'name': cluster_config.name,
                    'operator': 'flink-kubernetes-operator',
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to create Flink cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_config.name,
                original_error=e
            )

    async def delete_flink_cluster(self, cluster_id: str) -> bool:
        """Delete a Flink cluster."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')
            await self._custom_api.delete_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=name,
            )
            logger.info(f"Flink cluster {cluster_id} deleted successfully")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Flink cluster {cluster_id} not found")
                return False
            raise BigDataProvisionerException(
                f"Failed to delete Flink cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_flink_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale a Flink cluster by updating TaskManager count."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')

            deployment = await self._custom_api.get_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=name,
            )

            if 'worker_count' in scale_config:
                deployment['spec']['taskManager']['replicas'] = scale_config['worker_count']

            if 'task_slots' in scale_config:
                deployment['spec']['flinkConfiguration']['taskmanager.numberOfTaskSlots'] = str(scale_config['task_slots'])

            await self._custom_api.patch_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=name,
                body=deployment,
            )

            return {
                'cluster_id': cluster_id,
                'status': 'scaling',
                'updated_at': datetime.utcnow().isoformat(),
                'new_worker_count': scale_config.get('worker_count'),
                'new_task_slots': scale_config.get('task_slots'),
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to scale Flink cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    # HBase Cluster Management
    async def create_hbase_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create an HBase cluster using Stackable HBase Operator."""
        await self._ensure_initialized()

        try:
            master_resources = self._map_instance_size_to_resources(
                cluster_config.master_instance_size
            )
            regionserver_resources = self._map_instance_size_to_resources(
                cluster_config.worker_instance_size
            )

            hbase_cluster = {
                'apiVersion': 'hbase.stackable.tech/v1alpha1',
                'kind': 'HbaseCluster',
                'metadata': {
                    'name': cluster_config.name,
                    'namespace': self.namespace,
                    'labels': cluster_config.labels,
                    'annotations': cluster_config.annotations,
                },
                'spec': {
                    'image': {
                        'productVersion': cluster_config.version or '2.4.17',
                    },
                    'clusterConfig': {
                        'zookeeperConfigMapName': cluster_config.custom_config.get('zookeeper_config', 'hbase-zookeeper'),
                        'hdfsConfigMapName': cluster_config.custom_config.get('hdfs_config', 'hbase-hdfs'),
                    },
                    'masters': {
                        'roleGroups': {
                            'default': {
                                'replicas': cluster_config.master_count,
                                'config': {
                                    'resources': {
                                        'cpu': {
                                            'min': master_resources['cpu'],
                                            'max': master_resources['cpu'],
                                        },
                                        'memory': {
                                            'limit': master_resources['memory'],
                                        },
                                    },
                                },
                            },
                        },
                    },
                    'regionServers': {
                        'roleGroups': {
                            'default': {
                                'replicas': cluster_config.worker_count,
                                'config': {
                                    'resources': {
                                        'cpu': {
                                            'min': regionserver_resources['cpu'],
                                            'max': regionserver_resources['cpu'],
                                        },
                                        'memory': {
                                            'limit': regionserver_resources['memory'],
                                        },
                                        'storage': {
                                            'data': {
                                                'capacity': f"{cluster_config.storage_size_gb}Gi",
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                    'restServers': {
                        'roleGroups': {
                            'default': {
                                'replicas': 1,
                            },
                        },
                    },
                },
            }

            await self._custom_api.create_namespaced_custom_object(
                group='hbase.stackable.tech',
                version='v1alpha1',
                namespace=self.namespace,
                plural='hbaseclusters',
                body=hbase_cluster,
            )

            master_endpoint = f"{cluster_config.name}-master-0.{cluster_config.name}-master.{self.namespace}.svc.cluster.local"
            zookeeper_quorum = cluster_config.custom_config.get('zookeeper_quorum', 'zookeeper-0:2181')

            return {
                'cluster_id': f"{self.namespace}/{cluster_config.name}",
                'master_endpoint': master_endpoint,
                'master_port': 16000,
                'zookeeper_quorum': zookeeper_quorum,
                'status': 'creating',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'namespace': self.namespace,
                    'name': cluster_config.name,
                    'operator': 'stackable-hbase-operator',
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to create HBase cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_config.name,
                original_error=e
            )

    async def delete_hbase_cluster(self, cluster_id: str) -> bool:
        """Delete an HBase cluster."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')
            await self._custom_api.delete_namespaced_custom_object(
                group='hbase.stackable.tech',
                version='v1alpha1',
                namespace=namespace,
                plural='hbaseclusters',
                name=name,
            )
            logger.info(f"HBase cluster {cluster_id} deleted successfully")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"HBase cluster {cluster_id} not found")
                return False
            raise BigDataProvisionerException(
                f"Failed to delete HBase cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_hbase_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale an HBase cluster by updating RegionServer count."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')

            cluster = await self._custom_api.get_namespaced_custom_object(
                group='hbase.stackable.tech',
                version='v1alpha1',
                namespace=namespace,
                plural='hbaseclusters',
                name=name,
            )

            if 'worker_count' in scale_config:
                cluster['spec']['regionServers']['roleGroups']['default']['replicas'] = scale_config['worker_count']

            await self._custom_api.patch_namespaced_custom_object(
                group='hbase.stackable.tech',
                version='v1alpha1',
                namespace=namespace,
                plural='hbaseclusters',
                name=name,
                body=cluster,
            )

            return {
                'cluster_id': cluster_id,
                'status': 'scaling',
                'updated_at': datetime.utcnow().isoformat(),
                'new_worker_count': scale_config.get('worker_count'),
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to scale HBase cluster: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    # Storage Backend Management
    async def create_storage_backend(
        self,
        backend_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create or configure storage backend (creates Secret for credentials)."""
        await self._ensure_initialized()

        try:
            backend_type = backend_config.get('backend_type', 's3')
            bucket_name = backend_config['bucket_name']
            access_config = backend_config.get('access_config', {})

            # Create a Secret with storage credentials
            secret_name = f"{bucket_name}-credentials"
            secret = {
                'apiVersion': 'v1',
                'kind': 'Secret',
                'metadata': {
                    'name': secret_name,
                    'namespace': self.namespace,
                },
                'type': 'Opaque',
                'stringData': {
                    'backend-type': backend_type,
                    'bucket-name': bucket_name,
                    'access-key-id': access_config.get('access_key_id', ''),
                    'secret-access-key': access_config.get('secret_access_key', ''),
                    'endpoint': access_config.get('endpoint', ''),
                    'region': backend_config.get('region', ''),
                },
            }

            await self._core_api.create_namespaced_secret(
                namespace=self.namespace,
                body=secret,
            )

            return {
                'backend_id': f"{self.namespace}/{secret_name}",
                'endpoint': access_config.get('endpoint', f"https://s3.{backend_config.get('region', 'us-east-1')}.amazonaws.com"),
                'bucket_name': bucket_name,
                'access_key_id': access_config.get('access_key_id', ''),
                'created_at': datetime.utcnow().isoformat(),
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to create storage backend: {e.reason}",
                provider='kubernetes',
                original_error=e
            )

    async def delete_storage_backend(self, backend_id: str) -> bool:
        """Delete storage backend Secret."""
        await self._ensure_initialized()

        try:
            namespace, name = backend_id.split('/')
            await self._core_api.delete_namespaced_secret(
                name=name,
                namespace=namespace,
            )
            logger.info(f"Storage backend {backend_id} deleted successfully")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Storage backend {backend_id} not found")
                return False
            raise BigDataProvisionerException(
                f"Failed to delete storage backend: {e.reason}",
                provider='kubernetes',
                original_error=e
            )

    # Spark Job Management
    async def submit_spark_job(
        self,
        cluster_id: str,
        job_config: JobConfig
    ) -> Dict[str, Any]:
        """Submit a Spark job using SparkApplication CRD."""
        await self._ensure_initialized()

        try:
            namespace, cluster_name = cluster_id.split('/')

            # Read cluster configuration
            config_map = await self._core_api.read_namespaced_config_map(
                name=f"{cluster_name}-config",
                namespace=namespace,
            )

            spark_app = {
                'apiVersion': 'sparkoperator.k8s.io/v1beta2',
                'kind': 'SparkApplication',
                'metadata': {
                    'name': job_config.job_name,
                    'namespace': namespace,
                    'labels': job_config.labels,
                },
                'spec': {
                    'type': 'Python' if job_config.application_file.endswith('.py') else 'Scala',
                    'mode': 'cluster',
                    'image': f"spark:{config_map.data['spark-version']}",
                    'imagePullPolicy': 'IfNotPresent',
                    'mainClass': job_config.main_class,
                    'mainApplicationFile': job_config.application_file,
                    'arguments': job_config.arguments,
                    'sparkVersion': config_map.data['spark-version'],
                    'restartPolicy': {
                        'type': 'OnFailure',
                        'onFailureRetries': 3,
                        'onFailureRetryInterval': 10,
                        'onSubmissionFailureRetries': 5,
                        'onSubmissionFailureRetryInterval': 20,
                    },
                    'driver': {
                        'cores': int(float(config_map.data['driver-cpu'])),
                        'memory': config_map.data['driver-memory'],
                        'serviceAccount': 'spark',
                        'env': [
                            {'name': k, 'value': v}
                            for k, v in job_config.environment_variables.items()
                        ],
                    },
                    'executor': {
                        'cores': job_config.executor_cores,
                        'instances': job_config.executor_count,
                        'memory': f"{job_config.executor_memory_gb}g",
                    },
                    'deps': {
                        'jars': [dep for dep in job_config.dependencies if dep.endswith('.jar')],
                        'files': [dep for dep in job_config.dependencies if not dep.endswith('.jar')],
                    },
                },
            }

            await self._custom_api.create_namespaced_custom_object(
                group='sparkoperator.k8s.io',
                version='v1beta2',
                namespace=namespace,
                plural='sparkapplications',
                body=spark_app,
            )

            return {
                'job_id': f"{namespace}/{job_config.job_name}",
                'cluster_id': cluster_id,
                'status': 'submitted',
                'submitted_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'namespace': namespace,
                    'name': job_config.job_name,
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to submit Spark job: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def get_spark_job_status(
        self,
        cluster_id: str,
        job_id: str
    ) -> Dict[str, Any]:
        """Get status of a Spark job."""
        await self._ensure_initialized()

        try:
            namespace, job_name = job_id.split('/')

            spark_app = await self._custom_api.get_namespaced_custom_object(
                group='sparkoperator.k8s.io',
                version='v1beta2',
                namespace=namespace,
                plural='sparkapplications',
                name=job_name,
            )

            status = spark_app.get('status', {})
            app_state = status.get('applicationState', {}).get('state', 'UNKNOWN')

            # Map Spark states to JobStatus
            status_map = {
                'SUBMITTED': JobStatus.PENDING,
                'RUNNING': JobStatus.RUNNING,
                'COMPLETED': JobStatus.SUCCEEDED,
                'FAILED': JobStatus.FAILED,
                'UNKNOWN': JobStatus.UNKNOWN,
            }

            return {
                'job_id': job_id,
                'status': status_map.get(app_state, JobStatus.UNKNOWN).value,
                'progress': 100 if app_state == 'COMPLETED' else 50 if app_state == 'RUNNING' else 0,
                'started_at': status.get('submissionTime'),
                'completed_at': status.get('terminationTime'),
                'error_message': status.get('applicationState', {}).get('errorMessage'),
                'metadata': {
                    'driver_info': status.get('driverInfo', {}),
                    'executor_state': status.get('executorState', {}),
                },
            }
        except ApiException as e:
            if e.status == 404:
                raise BigDataProvisionerException(
                    f"Spark job {job_id} not found",
                    provider='kubernetes',
                    job_id=job_id,
                )
            raise BigDataProvisionerException(
                f"Failed to get Spark job status: {e.reason}",
                provider='kubernetes',
                job_id=job_id,
                original_error=e
            )

    async def kill_spark_job(
        self,
        cluster_id: str,
        job_id: str
    ) -> bool:
        """Kill a running Spark job."""
        await self._ensure_initialized()

        try:
            namespace, job_name = job_id.split('/')
            await self._custom_api.delete_namespaced_custom_object(
                group='sparkoperator.k8s.io',
                version='v1beta2',
                namespace=namespace,
                plural='sparkapplications',
                name=job_name,
            )
            logger.info(f"Spark job {job_id} killed successfully")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Spark job {job_id} not found")
                return False
            raise BigDataProvisionerException(
                f"Failed to kill Spark job: {e.reason}",
                provider='kubernetes',
                job_id=job_id,
                original_error=e
            )

    # Flink Job Management
    async def submit_flink_job(
        self,
        cluster_id: str,
        job_config: JobConfig
    ) -> Dict[str, Any]:
        """Submit a Flink job using FlinkDeployment CRD with job spec."""
        await self._ensure_initialized()

        try:
            namespace, cluster_name = cluster_id.split('/')

            flink_job = {
                'apiVersion': 'flink.apache.org/v1beta1',
                'kind': 'FlinkDeployment',
                'metadata': {
                    'name': job_config.job_name,
                    'namespace': namespace,
                    'labels': job_config.labels,
                },
                'spec': {
                    'image': 'flink:1.18',
                    'flinkVersion': 'v1_18',
                    'flinkConfiguration': {
                        'taskmanager.numberOfTaskSlots': '4',
                        'parallelism.default': str(job_config.parallelism),
                    },
                    'serviceAccount': 'flink',
                    'jobManager': {
                        'replicas': 1,
                        'resource': {
                            'memory': f"{job_config.driver_memory_gb}g",
                            'cpu': 2.0,
                        },
                    },
                    'taskManager': {
                        'replicas': job_config.executor_count,
                        'resource': {
                            'memory': f"{job_config.executor_memory_gb}g",
                            'cpu': float(job_config.executor_cores),
                        },
                    },
                    'job': {
                        'jarURI': job_config.application_file,
                        'entryClass': job_config.main_class,
                        'args': job_config.arguments,
                        'parallelism': job_config.parallelism,
                        'state': 'running',
                        'savepointTriggerNonce': 0,
                    },
                },
            }

            if job_config.savepoint_path:
                flink_job['spec']['job']['initialSavepointPath'] = job_config.savepoint_path

            await self._custom_api.create_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                body=flink_job,
            )

            return {
                'job_id': f"{namespace}/{job_config.job_name}",
                'cluster_id': cluster_id,
                'status': 'submitted',
                'submitted_at': datetime.utcnow().isoformat(),
                'metadata': {
                    'namespace': namespace,
                    'name': job_config.job_name,
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to submit Flink job: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def get_flink_job_status(
        self,
        cluster_id: str,
        job_id: str
    ) -> Dict[str, Any]:
        """Get status of a Flink job."""
        await self._ensure_initialized()

        try:
            namespace, job_name = job_id.split('/')

            flink_deployment = await self._custom_api.get_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=job_name,
            )

            status = flink_deployment.get('status', {})
            job_status = status.get('jobStatus', {})
            job_state = job_status.get('state', 'UNKNOWN')

            # Map Flink states to JobStatus
            status_map = {
                'CREATED': JobStatus.PENDING,
                'RUNNING': JobStatus.RUNNING,
                'FINISHED': JobStatus.SUCCEEDED,
                'FAILED': JobStatus.FAILED,
                'CANCELED': JobStatus.CANCELLED,
                'UNKNOWN': JobStatus.UNKNOWN,
            }

            return {
                'job_id': job_id,
                'status': status_map.get(job_state, JobStatus.UNKNOWN).value,
                'started_at': job_status.get('startTime'),
                'completed_at': job_status.get('updateTime') if job_state in ['FINISHED', 'FAILED', 'CANCELED'] else None,
                'checkpoints': {
                    'last_checkpoint': job_status.get('checkpointInfo', {}).get('lastCheckpoint'),
                    'savepoint_location': job_status.get('savepointInfo', {}).get('location'),
                },
                'error_message': status.get('error'),
                'metadata': {
                    'job_manager_deployment_status': status.get('jobManagerDeploymentStatus'),
                    'reconciliation_status': status.get('reconciliationStatus', {}),
                },
            }
        except ApiException as e:
            if e.status == 404:
                raise BigDataProvisionerException(
                    f"Flink job {job_id} not found",
                    provider='kubernetes',
                    job_id=job_id,
                )
            raise BigDataProvisionerException(
                f"Failed to get Flink job status: {e.reason}",
                provider='kubernetes',
                job_id=job_id,
                original_error=e
            )

    async def cancel_flink_job(
        self,
        cluster_id: str,
        job_id: str,
        with_savepoint: bool = True
    ) -> Dict[str, Any]:
        """Cancel a running Flink job with optional savepoint."""
        await self._ensure_initialized()

        try:
            namespace, job_name = job_id.split('/')

            flink_deployment = await self._custom_api.get_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=job_name,
            )

            savepoint_path = None
            if with_savepoint:
                # Trigger savepoint before cancellation
                savepoint_result = await self.create_savepoint(cluster_id, job_id)
                savepoint_path = savepoint_result.get('savepoint_path')

            # Update job state to suspended (which cancels it)
            flink_deployment['spec']['job']['state'] = 'suspended'
            if savepoint_path:
                flink_deployment['spec']['job']['upgradeMode'] = 'savepoint'

            await self._custom_api.patch_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=job_name,
                body=flink_deployment,
            )

            return {
                'job_id': job_id,
                'cancelled_at': datetime.utcnow().isoformat(),
                'savepoint_path': savepoint_path,
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to cancel Flink job: {e.reason}",
                provider='kubernetes',
                job_id=job_id,
                original_error=e
            )

    async def create_savepoint(
        self,
        cluster_id: str,
        job_id: str,
        savepoint_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create a savepoint for a running Flink job."""
        await self._ensure_initialized()

        try:
            namespace, job_name = job_id.split('/')

            flink_deployment = await self._custom_api.get_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=job_name,
            )

            # Increment savepoint trigger nonce to trigger a new savepoint
            current_nonce = flink_deployment.get('spec', {}).get('job', {}).get('savepointTriggerNonce', 0)
            flink_deployment['spec']['job']['savepointTriggerNonce'] = current_nonce + 1

            await self._custom_api.patch_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=job_name,
                body=flink_deployment,
            )

            # Wait briefly for savepoint to trigger
            await asyncio.sleep(2)

            # Get updated status
            updated_deployment = await self._custom_api.get_namespaced_custom_object(
                group='flink.apache.org',
                version='v1beta1',
                namespace=namespace,
                plural='flinkdeployments',
                name=job_name,
            )

            savepoint_info = updated_deployment.get('status', {}).get('jobStatus', {}).get('savepointInfo', {})
            created_path = savepoint_info.get('location', savepoint_path or 's3://flink-savepoints/default')

            return {
                'job_id': job_id,
                'savepoint_path': created_path,
                'created_at': datetime.utcnow().isoformat(),
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to create savepoint: {e.reason}",
                provider='kubernetes',
                job_id=job_id,
                original_error=e
            )

    # Monitoring and Health
    async def get_cluster_metrics(
        self,
        cluster_id: str,
        metric_names: List[str],
        start: datetime,
        end: datetime
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Retrieve metrics for a cluster using Kubernetes metrics API."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')

            # Get pods for the cluster
            label_selector = f"app={name}"
            pods = await self._core_api.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector,
            )

            metrics_data = {}

            # Fetch metrics for each requested metric
            for metric_name in metric_names:
                metric_points = []

                for pod in pods.items:
                    try:
                        # Get pod metrics from metrics.k8s.io API
                        pod_metrics = await self._metrics_api.get_namespaced_custom_object(
                            group='metrics.k8s.io',
                            version='v1beta1',
                            namespace=namespace,
                            plural='pods',
                            name=pod.metadata.name,
                        )

                        # Extract relevant metrics
                        for container in pod_metrics.get('containers', []):
                            usage = container.get('usage', {})

                            if metric_name == 'cpu_usage' and 'cpu' in usage:
                                metric_points.append({
                                    'timestamp': datetime.utcnow().isoformat(),
                                    'value': self._parse_cpu_value(usage['cpu']),
                                    'unit': 'millicores',
                                    'pod': pod.metadata.name,
                                })
                            elif metric_name == 'memory_usage' and 'memory' in usage:
                                metric_points.append({
                                    'timestamp': datetime.utcnow().isoformat(),
                                    'value': self._parse_memory_value(usage['memory']),
                                    'unit': 'bytes',
                                    'pod': pod.metadata.name,
                                })
                    except ApiException:
                        # Skip pods without metrics
                        continue

                metrics_data[metric_name] = metric_points

            return metrics_data
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to retrieve cluster metrics: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    async def get_cluster_health(
        self,
        cluster_id: str
    ) -> Dict[str, Any]:
        """Get health status of a cluster by checking pod statuses."""
        await self._ensure_initialized()

        try:
            namespace, name = cluster_id.split('/')

            # Get all pods for the cluster
            label_selector = f"app={name}"
            pods = await self._core_api.list_namespaced_pod(
                namespace=namespace,
                label_selector=label_selector,
            )

            master_nodes = []
            worker_nodes = []
            issues = []

            for pod in pods.items:
                pod_info = {
                    'name': pod.metadata.name,
                    'status': pod.status.phase,
                    'ready': False,
                    'restarts': 0,
                }

                # Check container statuses
                if pod.status.container_statuses:
                    for container_status in pod.status.container_statuses:
                        pod_info['ready'] = container_status.ready
                        pod_info['restarts'] = container_status.restart_count

                        if container_status.restart_count > 5:
                            issues.append(f"Pod {pod.metadata.name} has {container_status.restart_count} restarts")

                # Categorize by role
                if 'master' in pod.metadata.name or 'coordinator' in pod.metadata.name or 'namenode' in pod.metadata.name:
                    master_nodes.append(pod_info)
                else:
                    worker_nodes.append(pod_info)

                # Check for problems
                if pod.status.phase not in ['Running', 'Succeeded']:
                    issues.append(f"Pod {pod.metadata.name} is in {pod.status.phase} state")

            # Determine overall health
            total_pods = len(pods.items)
            ready_pods = sum(1 for pod in pods.items if pod.status.phase == 'Running')

            if ready_pods == total_pods and total_pods > 0:
                health = 'healthy'
            elif ready_pods >= total_pods * 0.7:
                health = 'degraded'
            else:
                health = 'unhealthy'

            return {
                'cluster_id': cluster_id,
                'cluster_type': self._infer_cluster_type(cluster_id),
                'status': 'running' if ready_pods > 0 else 'stopped',
                'health': health,
                'master_nodes': master_nodes,
                'worker_nodes': worker_nodes,
                'last_updated': datetime.utcnow().isoformat(),
                'issues': issues,
                'statistics': {
                    'total_pods': total_pods,
                    'ready_pods': ready_pods,
                    'unhealthy_pods': total_pods - ready_pods,
                },
            }
        except ApiException as e:
            raise BigDataProvisionerException(
                f"Failed to check cluster health: {e.reason}",
                provider='kubernetes',
                cluster_id=cluster_id,
                original_error=e
            )

    # Helper methods
    def _parse_cpu_value(self, cpu_str: str) -> float:
        """Parse Kubernetes CPU value to millicores."""
        if cpu_str.endswith('n'):
            return float(cpu_str[:-1]) / 1_000_000
        elif cpu_str.endswith('u'):
            return float(cpu_str[:-1]) / 1_000
        elif cpu_str.endswith('m'):
            return float(cpu_str[:-1])
        else:
            return float(cpu_str) * 1000

    def _parse_memory_value(self, memory_str: str) -> int:
        """Parse Kubernetes memory value to bytes."""
        units = {
            'Ki': 1024,
            'Mi': 1024 ** 2,
            'Gi': 1024 ** 3,
            'Ti': 1024 ** 4,
        }
        for unit, multiplier in units.items():
            if memory_str.endswith(unit):
                return int(float(memory_str[:-2]) * multiplier)
        return int(memory_str)

    def _infer_cluster_type(self, cluster_id: str) -> str:
        """Infer cluster type from cluster_id."""
        namespace, name = cluster_id.split('/')
        name_lower = name.lower()

        if 'hdfs' in name_lower:
            return 'hdfs'
        elif 'trino' in name_lower:
            return 'trino'
        elif 'spark' in name_lower:
            return 'spark'
        elif 'flink' in name_lower:
            return 'flink'
        elif 'hbase' in name_lower:
            return 'hbase'
        else:
            return 'unknown'
