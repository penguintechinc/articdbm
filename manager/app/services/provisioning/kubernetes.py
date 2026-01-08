"""Kubernetes provisioner for database instances using operators."""
import json
import logging
import time
from typing import Dict, Any, Optional, List

from kubernetes import client, config
from kubernetes.client.rest import ApiException

from .base import BaseProvisioner

logger = logging.getLogger(__name__)


class KubernetesProvisioner(BaseProvisioner):
    """Kubernetes-based database provisioner using operators.

    Supports:
    - PostgreSQL via CloudNativePG
    - MySQL via Percona XtraDB Cluster Operator
    - MongoDB via Percona Server for MongoDB Operator
    - Redis via Redis Operator
    """

    def __init__(self, provisioner_config: Dict[str, Any]):
        """Initialize Kubernetes provisioner.

        Args:
            provisioner_config: Configuration dict containing:
                - kubeconfig_path: Path to kubeconfig (optional)
                - in_cluster: Whether running in cluster (default: False)
                - namespace_prefix: Prefix for namespaces (default: "articdbm")
        """
        self.config = provisioner_config
        self.namespace_prefix = provisioner_config.get("namespace_prefix", "articdbm")

        # Load Kubernetes configuration
        if provisioner_config.get("in_cluster", False):
            config.load_incluster_config()
        else:
            kubeconfig_path = provisioner_config.get("kubeconfig_path")
            if kubeconfig_path:
                config.load_kube_config(config_file=kubeconfig_path)
            else:
                config.load_kube_config()

        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.custom_objects = client.CustomObjectsApi()

    def _ensure_namespace(self, namespace: str) -> None:
        """Create namespace if it doesn't exist.

        Args:
            namespace: Namespace name
        """
        try:
            self.core_v1.read_namespace(name=namespace)
            logger.info(f"Namespace {namespace} already exists")
        except ApiException as e:
            if e.status == 404:
                namespace_manifest = client.V1Namespace(
                    metadata=client.V1ObjectMeta(name=namespace)
                )
                self.core_v1.create_namespace(body=namespace_manifest)
                logger.info(f"Created namespace {namespace}")
            else:
                raise

    def _get_namespace(self, instance_id: str) -> str:
        """Get namespace name for instance.

        Args:
            instance_id: Instance identifier

        Returns:
            Namespace name
        """
        return f"{self.namespace_prefix}-{instance_id}"

    def _create_cloudnativepg_cluster(
        self,
        instance_id: str,
        namespace: str,
        version: str,
        replicas: int,
        storage_size: str,
        labels: Dict[str, str],
        annotations: Dict[str, str]
    ) -> Dict[str, Any]:
        """Create CloudNativePG Cluster CRD.

        Args:
            instance_id: Instance identifier
            namespace: Kubernetes namespace
            version: PostgreSQL version
            replicas: Number of replicas
            storage_size: Storage size (e.g., "10Gi")
            labels: Labels to apply
            annotations: Annotations to apply

        Returns:
            Created resource
        """
        cluster_manifest = {
            "apiVersion": "postgresql.cnpg.io/v1",
            "kind": "Cluster",
            "metadata": {
                "name": instance_id,
                "namespace": namespace,
                "labels": labels,
                "annotations": annotations
            },
            "spec": {
                "instances": replicas,
                "imageName": f"ghcr.io/cloudnative-pg/postgresql:{version}",
                "storage": {
                    "size": storage_size
                },
                "bootstrap": {
                    "initdb": {
                        "database": "app",
                        "owner": "app"
                    }
                },
                "monitoring": {
                    "enablePodMonitor": True
                }
            }
        }

        return self.custom_objects.create_namespaced_custom_object(
            group="postgresql.cnpg.io",
            version="v1",
            namespace=namespace,
            plural="clusters",
            body=cluster_manifest
        )

    def _create_percona_xtradb_cluster(
        self,
        instance_id: str,
        namespace: str,
        version: str,
        replicas: int,
        storage_size: str,
        labels: Dict[str, str],
        annotations: Dict[str, str]
    ) -> Dict[str, Any]:
        """Create Percona XtraDB Cluster CRD.

        Args:
            instance_id: Instance identifier
            namespace: Kubernetes namespace
            version: MySQL version
            replicas: Number of replicas
            storage_size: Storage size (e.g., "10Gi")
            labels: Labels to apply
            annotations: Annotations to apply

        Returns:
            Created resource
        """
        cluster_manifest = {
            "apiVersion": "pxc.percona.com/v1",
            "kind": "PerconaXtraDBCluster",
            "metadata": {
                "name": instance_id,
                "namespace": namespace,
                "labels": labels,
                "annotations": annotations
            },
            "spec": {
                "crVersion": "1.13.0",
                "secretsName": f"{instance_id}-secrets",
                "pxc": {
                    "size": replicas,
                    "image": f"percona/percona-xtradb-cluster:{version}",
                    "resources": {
                        "requests": {
                            "memory": "1G",
                            "cpu": "600m"
                        }
                    },
                    "volumeSpec": {
                        "persistentVolumeClaim": {
                            "resources": {
                                "requests": {
                                    "storage": storage_size
                                }
                            }
                        }
                    }
                },
                "haproxy": {
                    "enabled": True,
                    "size": min(replicas, 3)
                },
                "proxysql": {
                    "enabled": False
                }
            }
        }

        # Create secrets for Percona
        self._create_percona_secrets(instance_id, namespace)

        return self.custom_objects.create_namespaced_custom_object(
            group="pxc.percona.com",
            version="v1",
            namespace=namespace,
            plural="perconaxtradbclusters",
            body=cluster_manifest
        )

    def _create_percona_mongodb_cluster(
        self,
        instance_id: str,
        namespace: str,
        version: str,
        replicas: int,
        storage_size: str,
        labels: Dict[str, str],
        annotations: Dict[str, str]
    ) -> Dict[str, Any]:
        """Create Percona Server for MongoDB CRD.

        Args:
            instance_id: Instance identifier
            namespace: Kubernetes namespace
            version: MongoDB version
            replicas: Number of replicas
            storage_size: Storage size (e.g., "10Gi")
            labels: Labels to apply
            annotations: Annotations to apply

        Returns:
            Created resource
        """
        cluster_manifest = {
            "apiVersion": "psmdb.percona.com/v1",
            "kind": "PerconaServerMongoDB",
            "metadata": {
                "name": instance_id,
                "namespace": namespace,
                "labels": labels,
                "annotations": annotations
            },
            "spec": {
                "crVersion": "1.15.0",
                "image": f"percona/percona-server-mongodb:{version}",
                "secrets": {
                    "users": f"{instance_id}-secrets"
                },
                "replsets": [
                    {
                        "name": "rs0",
                        "size": replicas,
                        "volumeSpec": {
                            "persistentVolumeClaim": {
                                "resources": {
                                    "requests": {
                                        "storage": storage_size
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        }

        # Create secrets for MongoDB
        self._create_percona_secrets(instance_id, namespace)

        return self.custom_objects.create_namespaced_custom_object(
            group="psmdb.percona.com",
            version="v1",
            namespace=namespace,
            plural="perconaservermongodbs",
            body=cluster_manifest
        )

    def _create_redis_cluster(
        self,
        instance_id: str,
        namespace: str,
        version: str,
        replicas: int,
        storage_size: str,
        labels: Dict[str, str],
        annotations: Dict[str, str]
    ) -> Dict[str, Any]:
        """Create Redis Cluster CRD.

        Args:
            instance_id: Instance identifier
            namespace: Kubernetes namespace
            version: Redis version
            replicas: Number of replicas
            storage_size: Storage size (e.g., "10Gi")
            labels: Labels to apply
            annotations: Annotations to apply

        Returns:
            Created resource
        """
        cluster_manifest = {
            "apiVersion": "redis.redis.opstreelabs.in/v1beta1",
            "kind": "RedisCluster",
            "metadata": {
                "name": instance_id,
                "namespace": namespace,
                "labels": labels,
                "annotations": annotations
            },
            "spec": {
                "clusterSize": replicas,
                "kubernetesConfig": {
                    "image": f"redis:{version}",
                    "imagePullPolicy": "IfNotPresent"
                },
                "storage": {
                    "volumeClaimTemplate": {
                        "spec": {
                            "accessModes": ["ReadWriteOnce"],
                            "resources": {
                                "requests": {
                                    "storage": storage_size
                                }
                            }
                        }
                    }
                },
                "redisExporter": {
                    "enabled": True
                }
            }
        }

        return self.custom_objects.create_namespaced_custom_object(
            group="redis.redis.opstreelabs.in",
            version="v1beta1",
            namespace=namespace,
            plural="redisclusters",
            body=cluster_manifest
        )

    def _create_percona_secrets(self, instance_id: str, namespace: str) -> None:
        """Create secrets for Percona operators.

        Args:
            instance_id: Instance identifier
            namespace: Kubernetes namespace
        """
        import base64
        import secrets

        # Generate random passwords
        root_password = secrets.token_urlsafe(32)
        user_password = secrets.token_urlsafe(32)

        secret_data = {
            "root": base64.b64encode(root_password.encode()).decode(),
            "operator": base64.b64encode(user_password.encode()).decode(),
            "monitor": base64.b64encode(secrets.token_urlsafe(32).encode()).decode(),
            "clustercheck": base64.b64encode(secrets.token_urlsafe(32).encode()).decode(),
        }

        secret = client.V1Secret(
            metadata=client.V1ObjectMeta(
                name=f"{instance_id}-secrets",
                namespace=namespace
            ),
            data=secret_data,
            type="Opaque"
        )

        try:
            self.core_v1.create_namespaced_secret(namespace=namespace, body=secret)
        except ApiException as e:
            if e.status != 409:  # Already exists
                raise

    def _create_service(
        self,
        instance_id: str,
        namespace: str,
        port: int,
        labels: Dict[str, str]
    ) -> None:
        """Create LoadBalancer service for external access.

        Args:
            instance_id: Instance identifier
            namespace: Kubernetes namespace
            port: Service port
            labels: Labels for service selection
        """
        service = client.V1Service(
            metadata=client.V1ObjectMeta(
                name=f"{instance_id}-lb",
                namespace=namespace,
                labels=labels
            ),
            spec=client.V1ServiceSpec(
                type="LoadBalancer",
                selector=labels,
                ports=[
                    client.V1ServicePort(
                        name="database",
                        port=port,
                        target_port=port,
                        protocol="TCP"
                    )
                ]
            )
        )

        try:
            self.core_v1.create_namespaced_service(namespace=namespace, body=service)
        except ApiException as e:
            if e.status != 409:  # Already exists
                raise

    def _parse_size(self, size: str) -> tuple:
        """Parse size into replicas and storage.

        Args:
            size: Size string (e.g., "small", "medium", "large")

        Returns:
            Tuple of (replicas, storage_size)
        """
        size_map = {
            "small": (1, "10Gi"),
            "medium": (3, "50Gi"),
            "large": (5, "100Gi")
        }
        return size_map.get(size.lower(), (1, "10Gi"))

    def _get_tags(self, config: Dict[str, Any]) -> tuple:
        """Extract labels and annotations from config.

        Args:
            config: Configuration dict

        Returns:
            Tuple of (labels, annotations)
        """
        labels = config.get("labels", {})
        labels.update({
            "app.kubernetes.io/managed-by": "articdbm",
            "app.kubernetes.io/part-of": "articdbm"
        })

        annotations = config.get("annotations", {})
        return labels, annotations

    def create_instance(
        self,
        instance_id: str,
        engine: str,
        version: str,
        size: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create database instance using Kubernetes operators."""
        namespace = self._get_namespace(instance_id)
        self._ensure_namespace(namespace)

        replicas, storage_size = self._parse_size(size)
        labels, annotations = self._get_tags(config)
        labels["app"] = instance_id

        try:
            # Create CRD based on engine type
            if engine.lower() == "postgresql":
                resource = self._create_cloudnativepg_cluster(
                    instance_id, namespace, version, replicas,
                    storage_size, labels, annotations
                )
                port = 5432
            elif engine.lower() == "mysql":
                resource = self._create_percona_xtradb_cluster(
                    instance_id, namespace, version, replicas,
                    storage_size, labels, annotations
                )
                port = 3306
            elif engine.lower() == "mongodb":
                resource = self._create_percona_mongodb_cluster(
                    instance_id, namespace, version, replicas,
                    storage_size, labels, annotations
                )
                port = 27017
            elif engine.lower() == "redis":
                resource = self._create_redis_cluster(
                    instance_id, namespace, version, replicas,
                    storage_size, labels, annotations
                )
                port = 6379
            else:
                raise ValueError(f"Unsupported engine: {engine}")

            # Create external service
            if config.get("external_access", False):
                self._create_service(instance_id, namespace, port, labels)

            return {
                "instance_id": instance_id,
                "namespace": namespace,
                "engine": engine,
                "version": version,
                "replicas": replicas,
                "status": "creating",
                "resource": resource
            }

        except Exception as e:
            logger.error(f"Failed to create instance {instance_id}: {e}")
            raise

    def delete_instance(self, instance_id: str) -> bool:
        """Delete database instance."""
        namespace = self._get_namespace(instance_id)

        try:
            # Delete namespace (cascades to all resources)
            self.core_v1.delete_namespace(name=namespace)
            logger.info(f"Deleted namespace {namespace} for instance {instance_id}")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"Namespace {namespace} not found")
                return True
            logger.error(f"Failed to delete instance {instance_id}: {e}")
            return False

    def get_instance_status(self, instance_id: str) -> Dict[str, Any]:
        """Get instance status from Kubernetes resources."""
        namespace = self._get_namespace(instance_id)

        try:
            # Try each operator type
            for group, version, plural in [
                ("postgresql.cnpg.io", "v1", "clusters"),
                ("pxc.percona.com", "v1", "perconaxtradbclusters"),
                ("psmdb.percona.com", "v1", "perconaservermongodbs"),
                ("redis.redis.opstreelabs.in", "v1beta1", "redisclusters")
            ]:
                try:
                    resource = self.custom_objects.get_namespaced_custom_object(
                        group=group,
                        version=version,
                        namespace=namespace,
                        plural=plural,
                        name=instance_id
                    )

                    status = resource.get("status", {})
                    return {
                        "instance_id": instance_id,
                        "namespace": namespace,
                        "status": status.get("phase", "unknown"),
                        "ready_replicas": status.get("readyReplicas", 0),
                        "details": status
                    }
                except ApiException as e:
                    if e.status != 404:
                        raise

            return {
                "instance_id": instance_id,
                "status": "not_found"
            }

        except Exception as e:
            logger.error(f"Failed to get status for {instance_id}: {e}")
            return {
                "instance_id": instance_id,
                "status": "error",
                "error": str(e)
            }

    def scale_instance(
        self,
        instance_id: str,
        replicas: Optional[int] = None,
        size: Optional[str] = None
    ) -> bool:
        """Scale database instance."""
        if not replicas and not size:
            return False

        namespace = self._get_namespace(instance_id)

        if size:
            replicas, _ = self._parse_size(size)

        try:
            # Try each operator type and update replicas
            for group, version, plural, replica_path in [
                ("postgresql.cnpg.io", "v1", "clusters", ["spec", "instances"]),
                ("pxc.percona.com", "v1", "perconaxtradbclusters", ["spec", "pxc", "size"]),
                ("psmdb.percona.com", "v1", "perconaservermongodbs", ["spec", "replsets", 0, "size"]),
                ("redis.redis.opstreelabs.in", "v1beta1", "redisclusters", ["spec", "clusterSize"])
            ]:
                try:
                    # Patch the resource
                    patch = {"spec": {}}
                    current = patch["spec"]
                    for key in replica_path[:-1]:
                        if isinstance(key, int):
                            continue
                        current[key] = {}
                        current = current[key]
                    current[replica_path[-1]] = replicas

                    self.custom_objects.patch_namespaced_custom_object(
                        group=group,
                        version=version,
                        namespace=namespace,
                        plural=plural,
                        name=instance_id,
                        body=patch
                    )

                    logger.info(f"Scaled instance {instance_id} to {replicas} replicas")
                    return True

                except ApiException as e:
                    if e.status != 404:
                        raise

            logger.warning(f"Instance {instance_id} not found for scaling")
            return False

        except Exception as e:
            logger.error(f"Failed to scale instance {instance_id}: {e}")
            return False

    def list_instances(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """List all database instances."""
        instances = []

        try:
            # List namespaces with our prefix
            namespaces = self.core_v1.list_namespace(
                label_selector="app.kubernetes.io/managed-by=articdbm"
            )

            for ns in namespaces.items:
                namespace = ns.metadata.name
                if not namespace.startswith(self.namespace_prefix):
                    continue

                instance_id = namespace[len(self.namespace_prefix) + 1:]
                status = self.get_instance_status(instance_id)

                if filters:
                    # Apply filters
                    match = True
                    for key, value in filters.items():
                        if status.get(key) != value:
                            match = False
                            break
                    if not match:
                        continue

                instances.append(status)

            return instances

        except Exception as e:
            logger.error(f"Failed to list instances: {e}")
            return []
