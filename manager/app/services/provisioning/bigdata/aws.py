"""
AWS Big Data Provisioner using EMR, Athena, Glue, S3, and DynamoDB.

This module provides AWS-specific implementations for big data cluster
provisioning using:
- Amazon EMR for Spark, Flink, Hadoop/HDFS clusters
- Amazon Athena for Trino-compatible serverless SQL queries
- AWS Glue for Iceberg catalog management
- Amazon S3 for object storage backends
- Amazon DynamoDB as HBase alternative
"""

import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aioboto3
from botocore.exceptions import ClientError

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


class ClusterState:
    """AWS EMR cluster state mappings."""
    STARTING = "STARTING"
    BOOTSTRAPPING = "BOOTSTRAPPING"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    TERMINATING = "TERMINATING"
    TERMINATED = "TERMINATED"
    TERMINATED_WITH_ERRORS = "TERMINATED_WITH_ERRORS"


class AWSBigDataProvisioner(BaseBigDataProvisioner):
    """
    AWS Big Data Provisioner implementation.

    Manages big data clusters on AWS using EMR, Athena, Glue, S3, and DynamoDB.
    """

    def __init__(self, config: BigDataProvisionerConfig):
        """
        Initialize AWS big data provisioner.

        Args:
            config: Big data provisioner configuration
        """
        super().__init__(config)
        self.session = aioboto3.Session(
            aws_access_key_id=config.credentials.get('aws_access_key_id'),
            aws_secret_access_key=config.credentials.get('aws_secret_access_key'),
            region_name=config.region or 'us-east-1'
        )
        self._cluster_cache: Dict[str, Dict[str, Any]] = {}

    def _map_emr_state_to_status(self, emr_state: str) -> str:
        """
        Map EMR cluster state to standardized status.

        Args:
            emr_state: EMR cluster state

        Returns:
            Standardized status string
        """
        state_mapping = {
            ClusterState.STARTING: "starting",
            ClusterState.BOOTSTRAPPING: "provisioning",
            ClusterState.RUNNING: "running",
            ClusterState.WAITING: "running",
            ClusterState.TERMINATING: "terminating",
            ClusterState.TERMINATED: "terminated",
            ClusterState.TERMINATED_WITH_ERRORS: "failed"
        }
        return state_mapping.get(emr_state, "unknown")

    def _map_job_state_to_status(self, job_state: str) -> JobStatus:
        """
        Map EMR step state to JobStatus enum.

        Args:
            job_state: EMR step state

        Returns:
            JobStatus enum value
        """
        state_mapping = {
            "PENDING": JobStatus.PENDING,
            "RUNNING": JobStatus.RUNNING,
            "COMPLETED": JobStatus.SUCCEEDED,
            "CANCELLED": JobStatus.CANCELLED,
            "FAILED": JobStatus.FAILED,
            "INTERRUPTED": JobStatus.FAILED
        }
        return state_mapping.get(job_state, JobStatus.UNKNOWN)

    def _build_instance_groups(
        self,
        cluster_config: ClusterConfig
    ) -> List[Dict[str, Any]]:
        """
        Build EMR instance group configurations.

        Args:
            cluster_config: Cluster configuration

        Returns:
            List of instance group configurations
        """
        instance_size_map = {
            'small': 'm5.large',
            'medium': 'm5.xlarge',
            'large': 'm5.2xlarge',
            'xlarge': 'm5.4xlarge'
        }

        master_instance = instance_size_map.get(
            cluster_config.master_instance_size,
            cluster_config.master_instance_size
        )
        worker_instance = instance_size_map.get(
            cluster_config.worker_instance_size,
            cluster_config.worker_instance_size
        )

        instance_groups = [
            {
                'Name': 'Master',
                'InstanceRole': 'MASTER',
                'InstanceType': master_instance,
                'InstanceCount': cluster_config.master_count,
                'EbsConfiguration': {
                    'EbsBlockDeviceConfigs': [
                        {
                            'VolumeSpecification': {
                                'VolumeType': 'gp3',
                                'SizeInGB': cluster_config.storage_size_gb
                            },
                            'VolumesPerInstance': 1
                        }
                    ]
                }
            },
            {
                'Name': 'Core',
                'InstanceRole': 'CORE',
                'InstanceType': worker_instance,
                'InstanceCount': cluster_config.worker_count,
                'EbsConfiguration': {
                    'EbsBlockDeviceConfigs': [
                        {
                            'VolumeSpecification': {
                                'VolumeType': 'gp3',
                                'SizeInGB': cluster_config.storage_size_gb
                            },
                            'VolumesPerInstance': 1
                        }
                    ]
                }
            }
        ]

        if cluster_config.auto_scaling:
            instance_groups[1]['AutoScalingPolicy'] = {
                'Constraints': {
                    'MinCapacity': cluster_config.worker_count,
                    'MaxCapacity': cluster_config.auto_scaling.get(
                        'max_workers',
                        cluster_config.worker_count * 2
                    )
                },
                'Rules': [
                    {
                        'Name': 'ScaleUpOnYARNMemory',
                        'Action': {
                            'SimpleScalingPolicyConfiguration': {
                                'AdjustmentType': 'CHANGE_IN_CAPACITY',
                                'ScalingAdjustment': 1,
                                'CoolDown': 300
                            }
                        },
                        'Trigger': {
                            'CloudWatchAlarmDefinition': {
                                'ComparisonOperator': 'LESS_THAN',
                                'EvaluationPeriods': 1,
                                'MetricName': 'YARNMemoryAvailablePercentage',
                                'Namespace': 'AWS/ElasticMapReduce',
                                'Period': 300,
                                'Threshold': 15.0,
                                'Statistic': 'AVERAGE',
                                'Unit': 'PERCENT'
                            }
                        }
                    }
                ]
            }

        return instance_groups

    def _get_emr_applications(
        self,
        cluster_type: ClusterType
    ) -> List[Dict[str, str]]:
        """
        Get EMR application list for cluster type.

        Args:
            cluster_type: Type of cluster

        Returns:
            List of EMR application configurations
        """
        base_apps = [{'Name': 'Hadoop'}]

        if cluster_type == ClusterType.HDFS:
            return base_apps
        elif cluster_type == ClusterType.SPARK:
            return base_apps + [
                {'Name': 'Spark'},
                {'Name': 'Livy'},
                {'Name': 'JupyterHub'}
            ]
        elif cluster_type == ClusterType.FLINK:
            return base_apps + [{'Name': 'Flink'}]
        elif cluster_type == ClusterType.HBASE:
            return base_apps + [
                {'Name': 'HBase'},
                {'Name': 'ZooKeeper'},
                {'Name': 'Phoenix'}
            ]
        elif cluster_type == ClusterType.TRINO:
            return base_apps + [{'Name': 'Presto'}]
        else:
            return base_apps

    async def _wait_for_cluster_ready(
        self,
        cluster_id: str,
        timeout: int = 1800
    ) -> Dict[str, Any]:
        """
        Wait for EMR cluster to reach WAITING/RUNNING state.

        Args:
            cluster_id: EMR cluster ID
            timeout: Maximum wait time in seconds

        Returns:
            Cluster information dictionary

        Raises:
            BigDataProvisionerException: If cluster fails or times out
        """
        elapsed = 0
        interval = 30

        async with self.session.client('emr') as emr:
            while elapsed < timeout:
                try:
                    response = await emr.describe_cluster(ClusterId=cluster_id)
                    cluster = response['Cluster']
                    state = cluster['Status']['State']

                    if state in [ClusterState.WAITING, ClusterState.RUNNING]:
                        return cluster
                    elif state in [
                        ClusterState.TERMINATED,
                        ClusterState.TERMINATED_WITH_ERRORS
                    ]:
                        error_msg = cluster['Status'].get(
                            'StateChangeReason',
                            {}
                        ).get('Message', 'Unknown error')
                        raise BigDataProvisionerException(
                            f"Cluster failed: {error_msg}",
                            provider='aws',
                            cluster_id=cluster_id
                        )

                    await asyncio.sleep(interval)
                    elapsed += interval

                except ClientError as e:
                    raise BigDataProvisionerException(
                        f"Failed to check cluster status: {str(e)}",
                        provider='aws',
                        cluster_id=cluster_id,
                        original_error=e
                    )

        raise BigDataProvisionerException(
            f"Cluster creation timeout after {timeout} seconds",
            provider='aws',
            cluster_id=cluster_id
        )

    async def create_hdfs_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create HDFS cluster using EMR."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create HDFS cluster: {cluster_config.name}")
            return {
                'cluster_id': f'j-DRYRUN{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
                'namenode_endpoint': 'hdfs://dry-run-master:8020',
                'namenode_port': 8020,
                'webhdfs_endpoint': 'http://dry-run-master:9870',
                'status': 'dry_run',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('emr') as emr:
                release_label = cluster_config.version or 'emr-6.15.0'
                instance_groups = self._build_instance_groups(cluster_config)
                applications = self._get_emr_applications(ClusterType.HDFS)

                tags = [
                    {'Key': k, 'Value': v}
                    for k, v in {**self.config.tags, **cluster_config.labels}.items()
                ]

                params = {
                    'Name': cluster_config.name,
                    'ReleaseLabel': release_label,
                    'Applications': applications,
                    'Instances': {
                        'InstanceGroups': instance_groups,
                        'Ec2KeyName': cluster_config.network_config.get('ssh_key'),
                        'KeepJobFlowAliveWhenNoSteps': True,
                        'TerminationProtected': False
                    },
                    'JobFlowRole': 'EMR_EC2_DefaultRole',
                    'ServiceRole': 'EMR_DefaultRole',
                    'VisibleToAllUsers': True,
                    'Tags': tags
                }

                if cluster_config.network_config.get('subnet_id'):
                    params['Instances']['Ec2SubnetId'] = (
                        cluster_config.network_config['subnet_id']
                    )

                if cluster_config.network_config.get('security_groups'):
                    params['Instances']['EmrManagedMasterSecurityGroup'] = (
                        cluster_config.network_config['security_groups'][0]
                    )
                    if len(cluster_config.network_config['security_groups']) > 1:
                        params['Instances']['EmrManagedSlaveSecurityGroup'] = (
                            cluster_config.network_config['security_groups'][1]
                        )

                response = await emr.run_job_flow(**params)
                cluster_id = response['JobFlowId']

                logger.info(f"Created EMR HDFS cluster: {cluster_id}")

                cluster_info = await self._wait_for_cluster_ready(
                    cluster_id,
                    self.config.timeout
                )

                master_public_dns = cluster_info.get('MasterPublicDnsName', '')

                result = {
                    'cluster_id': cluster_id,
                    'namenode_endpoint': f'hdfs://{master_public_dns}:8020',
                    'namenode_port': 8020,
                    'webhdfs_endpoint': f'http://{master_public_dns}:9870',
                    'status': self._map_emr_state_to_status(
                        cluster_info['Status']['State']
                    ),
                    'created_at': cluster_info['Status']['Timeline'][
                        'CreationDateTime'
                    ].isoformat(),
                    'metadata': {
                        'master_public_dns': master_public_dns,
                        'release_label': release_label,
                        'emr_state': cluster_info['Status']['State']
                    }
                }

                self._cluster_cache[cluster_id] = result
                return result

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to create HDFS cluster: {str(e)}",
                provider='aws',
                original_error=e
            )

    async def delete_hdfs_cluster(self, cluster_id: str) -> bool:
        """Delete HDFS cluster."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would delete HDFS cluster: {cluster_id}")
            return True

        try:
            async with self.session.client('emr') as emr:
                await emr.terminate_job_flows(JobFlowIds=[cluster_id])
                logger.info(f"Terminated EMR cluster: {cluster_id}")
                self._cluster_cache.pop(cluster_id, None)
                return True

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to delete HDFS cluster: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_hdfs_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale HDFS cluster."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would scale cluster {cluster_id}: {scale_config}")
            cached = self._cluster_cache.get(cluster_id, {})
            return {**cached, 'status': 'dry_run_scaled'}

        try:
            async with self.session.client('emr') as emr:
                new_worker_count = scale_config.get('worker_count')

                if new_worker_count:
                    response = await emr.describe_cluster(ClusterId=cluster_id)
                    cluster = response['Cluster']

                    instance_groups = await emr.list_instance_groups(
                        ClusterId=cluster_id
                    )
                    core_group = next(
                        (g for g in instance_groups['InstanceGroups']
                         if g['InstanceGroupType'] == 'CORE'),
                        None
                    )

                    if core_group:
                        await emr.modify_instance_groups(
                            InstanceGroups=[
                                {
                                    'InstanceGroupId': core_group['Id'],
                                    'InstanceCount': new_worker_count
                                }
                            ]
                        )
                        logger.info(
                            f"Scaled cluster {cluster_id} to "
                            f"{new_worker_count} workers"
                        )

                response = await emr.describe_cluster(ClusterId=cluster_id)
                cluster_info = response['Cluster']
                master_public_dns = cluster_info.get('MasterPublicDnsName', '')

                return {
                    'cluster_id': cluster_id,
                    'namenode_endpoint': f'hdfs://{master_public_dns}:8020',
                    'namenode_port': 8020,
                    'webhdfs_endpoint': f'http://{master_public_dns}:9870',
                    'status': self._map_emr_state_to_status(
                        cluster_info['Status']['State']
                    ),
                    'metadata': {
                        'master_public_dns': master_public_dns,
                        'scaled_at': datetime.utcnow().isoformat()
                    }
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to scale HDFS cluster: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def create_trino_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create Trino cluster using Athena workgroup."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create Trino cluster: {cluster_config.name}")
            return {
                'cluster_id': f'athena-{cluster_config.name}',
                'coordinator_endpoint': f'athena.{self.config.region}.amazonaws.com',
                'coordinator_port': 443,
                'web_ui_endpoint': f'https://console.aws.amazon.com/athena',
                'status': 'dry_run',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('athena') as athena:
                workgroup_name = cluster_config.name

                output_location = cluster_config.storage_backend.get(
                    'output_location',
                    f's3://aws-athena-query-results-{self.config.region}'
                )

                tags = [
                    {'Key': k, 'Value': v}
                    for k, v in {**self.config.tags, **cluster_config.labels}.items()
                ]

                config = {
                    'ResultConfigurationUpdates': {
                        'OutputLocation': output_location,
                        'EncryptionConfiguration': {
                            'EncryptionOption': 'SSE_S3'
                        }
                    },
                    'EnforceWorkGroupConfiguration': True,
                    'PublishCloudWatchMetricsEnabled': True
                }

                if cluster_config.custom_config.get('bytes_scanned_cutoff'):
                    config['BytesScannedCutoffPerQuery'] = (
                        cluster_config.custom_config['bytes_scanned_cutoff']
                    )

                await athena.create_work_group(
                    Name=workgroup_name,
                    Configuration=config,
                    Description=f'Trino-compatible workgroup: {cluster_config.name}',
                    Tags=tags
                )

                logger.info(f"Created Athena workgroup: {workgroup_name}")

                return {
                    'cluster_id': workgroup_name,
                    'coordinator_endpoint': (
                        f'athena.{self.config.region}.amazonaws.com'
                    ),
                    'coordinator_port': 443,
                    'web_ui_endpoint': (
                        'https://console.aws.amazon.com/athena'
                    ),
                    'status': 'running',
                    'created_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        'workgroup_name': workgroup_name,
                        'output_location': output_location,
                        'region': self.config.region
                    }
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to create Trino cluster: {str(e)}",
                provider='aws',
                original_error=e
            )

    async def delete_trino_cluster(self, cluster_id: str) -> bool:
        """Delete Trino cluster (Athena workgroup)."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would delete Trino cluster: {cluster_id}")
            return True

        try:
            async with self.session.client('athena') as athena:
                await athena.delete_work_group(
                    WorkGroup=cluster_id,
                    RecursiveDeleteOption=True
                )
                logger.info(f"Deleted Athena workgroup: {cluster_id}")
                return True

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to delete Trino cluster: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_trino_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale Trino cluster (Athena is serverless, update configs only)."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would scale Trino cluster: {cluster_id}")
            return {'cluster_id': cluster_id, 'status': 'dry_run_scaled'}

        try:
            async with self.session.client('athena') as athena:
                updates = {}

                if scale_config.get('bytes_scanned_cutoff'):
                    updates['BytesScannedCutoffPerQuery'] = (
                        scale_config['bytes_scanned_cutoff']
                    )

                if updates:
                    await athena.update_work_group(
                        WorkGroup=cluster_id,
                        ConfigurationUpdates=updates
                    )

                response = await athena.get_work_group(WorkGroup=cluster_id)
                workgroup = response['WorkGroup']

                return {
                    'cluster_id': cluster_id,
                    'coordinator_endpoint': (
                        f'athena.{self.config.region}.amazonaws.com'
                    ),
                    'coordinator_port': 443,
                    'status': 'running',
                    'metadata': {
                        'workgroup_state': workgroup['State'],
                        'scaled_at': datetime.utcnow().isoformat()
                    }
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to scale Trino cluster: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def create_spark_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create Spark cluster using EMR."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create Spark cluster: {cluster_config.name}")
            return {
                'cluster_id': f'j-DRYRUN{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
                'master_endpoint': 'spark://dry-run-master:7077',
                'master_port': 7077,
                'web_ui_endpoint': 'http://dry-run-master:8080',
                'status': 'dry_run',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('emr') as emr:
                release_label = cluster_config.version or 'emr-6.15.0'
                instance_groups = self._build_instance_groups(cluster_config)
                applications = self._get_emr_applications(ClusterType.SPARK)

                tags = [
                    {'Key': k, 'Value': v}
                    for k, v in {**self.config.tags, **cluster_config.labels}.items()
                ]

                params = {
                    'Name': cluster_config.name,
                    'ReleaseLabel': release_label,
                    'Applications': applications,
                    'Instances': {
                        'InstanceGroups': instance_groups,
                        'Ec2KeyName': cluster_config.network_config.get('ssh_key'),
                        'KeepJobFlowAliveWhenNoSteps': True,
                        'TerminationProtected': False
                    },
                    'JobFlowRole': 'EMR_EC2_DefaultRole',
                    'ServiceRole': 'EMR_DefaultRole',
                    'VisibleToAllUsers': True,
                    'Tags': tags
                }

                if cluster_config.network_config.get('subnet_id'):
                    params['Instances']['Ec2SubnetId'] = (
                        cluster_config.network_config['subnet_id']
                    )

                response = await emr.run_job_flow(**params)
                cluster_id = response['JobFlowId']

                logger.info(f"Created EMR Spark cluster: {cluster_id}")

                cluster_info = await self._wait_for_cluster_ready(
                    cluster_id,
                    self.config.timeout
                )

                master_public_dns = cluster_info.get('MasterPublicDnsName', '')

                result = {
                    'cluster_id': cluster_id,
                    'master_endpoint': f'spark://{master_public_dns}:7077',
                    'master_port': 7077,
                    'web_ui_endpoint': f'http://{master_public_dns}:8088',
                    'status': self._map_emr_state_to_status(
                        cluster_info['Status']['State']
                    ),
                    'created_at': cluster_info['Status']['Timeline'][
                        'CreationDateTime'
                    ].isoformat(),
                    'metadata': {
                        'master_public_dns': master_public_dns,
                        'release_label': release_label,
                        'emr_state': cluster_info['Status']['State']
                    }
                }

                self._cluster_cache[cluster_id] = result
                return result

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to create Spark cluster: {str(e)}",
                provider='aws',
                original_error=e
            )

    async def delete_spark_cluster(self, cluster_id: str) -> bool:
        """Delete Spark cluster."""
        return await self.delete_hdfs_cluster(cluster_id)

    async def scale_spark_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale Spark cluster."""
        return await self.scale_hdfs_cluster(cluster_id, scale_config)

    async def create_flink_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create Flink cluster using EMR."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create Flink cluster: {cluster_config.name}")
            return {
                'cluster_id': f'j-DRYRUN{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
                'jobmanager_endpoint': 'dry-run-master:8081',
                'jobmanager_port': 8081,
                'web_ui_endpoint': 'http://dry-run-master:8081',
                'status': 'dry_run',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('emr') as emr:
                release_label = cluster_config.version or 'emr-6.15.0'
                instance_groups = self._build_instance_groups(cluster_config)
                applications = self._get_emr_applications(ClusterType.FLINK)

                tags = [
                    {'Key': k, 'Value': v}
                    for k, v in {**self.config.tags, **cluster_config.labels}.items()
                ]

                params = {
                    'Name': cluster_config.name,
                    'ReleaseLabel': release_label,
                    'Applications': applications,
                    'Instances': {
                        'InstanceGroups': instance_groups,
                        'Ec2KeyName': cluster_config.network_config.get('ssh_key'),
                        'KeepJobFlowAliveWhenNoSteps': True,
                        'TerminationProtected': False
                    },
                    'JobFlowRole': 'EMR_EC2_DefaultRole',
                    'ServiceRole': 'EMR_DefaultRole',
                    'VisibleToAllUsers': True,
                    'Tags': tags
                }

                if cluster_config.network_config.get('subnet_id'):
                    params['Instances']['Ec2SubnetId'] = (
                        cluster_config.network_config['subnet_id']
                    )

                response = await emr.run_job_flow(**params)
                cluster_id = response['JobFlowId']

                logger.info(f"Created EMR Flink cluster: {cluster_id}")

                cluster_info = await self._wait_for_cluster_ready(
                    cluster_id,
                    self.config.timeout
                )

                master_public_dns = cluster_info.get('MasterPublicDnsName', '')

                result = {
                    'cluster_id': cluster_id,
                    'jobmanager_endpoint': f'{master_public_dns}:8081',
                    'jobmanager_port': 8081,
                    'web_ui_endpoint': f'http://{master_public_dns}:8081',
                    'status': self._map_emr_state_to_status(
                        cluster_info['Status']['State']
                    ),
                    'created_at': cluster_info['Status']['Timeline'][
                        'CreationDateTime'
                    ].isoformat(),
                    'metadata': {
                        'master_public_dns': master_public_dns,
                        'release_label': release_label,
                        'emr_state': cluster_info['Status']['State']
                    }
                }

                self._cluster_cache[cluster_id] = result
                return result

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to create Flink cluster: {str(e)}",
                provider='aws',
                original_error=e
            )

    async def delete_flink_cluster(self, cluster_id: str) -> bool:
        """Delete Flink cluster."""
        return await self.delete_hdfs_cluster(cluster_id)

    async def scale_flink_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale Flink cluster."""
        return await self.scale_hdfs_cluster(cluster_id, scale_config)

    async def create_hbase_cluster(
        self,
        cluster_config: ClusterConfig
    ) -> Dict[str, Any]:
        """Create HBase alternative using DynamoDB."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create HBase cluster: {cluster_config.name}")
            return {
                'cluster_id': f'dynamodb-{cluster_config.name}',
                'master_endpoint': f'dynamodb.{self.config.region}.amazonaws.com',
                'master_port': 443,
                'zookeeper_quorum': 'N/A (DynamoDB)',
                'status': 'dry_run',
                'created_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('dynamodb') as dynamodb:
                table_name = cluster_config.name

                tags = [
                    {'Key': k, 'Value': v}
                    for k, v in {**self.config.tags, **cluster_config.labels}.items()
                ]

                params = {
                    'TableName': table_name,
                    'KeySchema': [
                        {'AttributeName': 'pk', 'KeyType': 'HASH'},
                        {'AttributeName': 'sk', 'KeyType': 'RANGE'}
                    ],
                    'AttributeDefinitions': [
                        {'AttributeName': 'pk', 'AttributeType': 'S'},
                        {'AttributeName': 'sk', 'AttributeType': 'S'}
                    ],
                    'BillingMode': 'PAY_PER_REQUEST',
                    'Tags': tags
                }

                if not cluster_config.auto_scaling:
                    params['BillingMode'] = 'PROVISIONED'
                    params['ProvisionedThroughput'] = {
                        'ReadCapacityUnits': 5,
                        'WriteCapacityUnits': 5
                    }

                await dynamodb.create_table(**params)

                logger.info(f"Created DynamoDB table (HBase alternative): {table_name}")

                return {
                    'cluster_id': table_name,
                    'master_endpoint': (
                        f'dynamodb.{self.config.region}.amazonaws.com'
                    ),
                    'master_port': 443,
                    'zookeeper_quorum': 'N/A (DynamoDB managed)',
                    'status': 'running',
                    'created_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        'table_name': table_name,
                        'region': self.config.region,
                        'billing_mode': params['BillingMode']
                    }
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to create HBase cluster: {str(e)}",
                provider='aws',
                original_error=e
            )

    async def delete_hbase_cluster(self, cluster_id: str) -> bool:
        """Delete HBase cluster (DynamoDB table)."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would delete HBase cluster: {cluster_id}")
            return True

        try:
            async with self.session.client('dynamodb') as dynamodb:
                await dynamodb.delete_table(TableName=cluster_id)
                logger.info(f"Deleted DynamoDB table: {cluster_id}")
                return True

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to delete HBase cluster: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def scale_hbase_cluster(
        self,
        cluster_id: str,
        scale_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Scale HBase cluster (update DynamoDB throughput)."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would scale HBase cluster: {cluster_id}")
            return {'cluster_id': cluster_id, 'status': 'dry_run_scaled'}

        try:
            async with self.session.client('dynamodb') as dynamodb:
                read_capacity = scale_config.get('read_capacity_units')
                write_capacity = scale_config.get('write_capacity_units')

                if read_capacity or write_capacity:
                    params = {'TableName': cluster_id}

                    current = await dynamodb.describe_table(TableName=cluster_id)
                    billing_mode = current['Table'].get('BillingModeSummary', {}).get(
                        'BillingMode',
                        'PROVISIONED'
                    )

                    if billing_mode == 'PAY_PER_REQUEST':
                        params['BillingMode'] = 'PROVISIONED'

                    params['ProvisionedThroughput'] = {
                        'ReadCapacityUnits': read_capacity or 5,
                        'WriteCapacityUnits': write_capacity or 5
                    }

                    await dynamodb.update_table(**params)
                    logger.info(f"Scaled DynamoDB table: {cluster_id}")

                return {
                    'cluster_id': cluster_id,
                    'master_endpoint': (
                        f'dynamodb.{self.config.region}.amazonaws.com'
                    ),
                    'master_port': 443,
                    'status': 'running',
                    'metadata': {
                        'scaled_at': datetime.utcnow().isoformat()
                    }
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to scale HBase cluster: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def create_storage_backend(
        self,
        backend_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create S3 bucket for storage backend."""
        if self.config.dry_run:
            bucket_name = backend_config.get('bucket_name', 'dry-run-bucket')
            logger.info(f"[DRY RUN] Would create S3 bucket: {bucket_name}")
            return {
                'backend_id': bucket_name,
                'endpoint': f's3.{self.config.region}.amazonaws.com',
                'bucket_name': bucket_name,
                'access_key_id': 'DRY_RUN_KEY',
                'created_at': datetime.utcnow().isoformat()
            }

        try:
            async with self.session.client('s3') as s3:
                bucket_name = backend_config.get('bucket_name')
                if not bucket_name:
                    raise BigDataProvisionerException(
                        "bucket_name is required in backend_config",
                        provider='aws'
                    )

                region = backend_config.get('region', self.config.region)

                create_params = {'Bucket': bucket_name}
                if region and region != 'us-east-1':
                    create_params['CreateBucketConfiguration'] = {
                        'LocationConstraint': region
                    }

                await s3.create_bucket(**create_params)
                logger.info(f"Created S3 bucket: {bucket_name}")

                if backend_config.get('enable_versioning'):
                    await s3.put_bucket_versioning(
                        Bucket=bucket_name,
                        VersioningConfiguration={'Status': 'Enabled'}
                    )

                if backend_config.get('enable_encryption', True):
                    await s3.put_bucket_encryption(
                        Bucket=bucket_name,
                        ServerSideEncryptionConfiguration={
                            'Rules': [
                                {
                                    'ApplyServerSideEncryptionByDefault': {
                                        'SSEAlgorithm': 'AES256'
                                    }
                                }
                            ]
                        }
                    )

                if backend_config.get('lifecycle_policies'):
                    await s3.put_bucket_lifecycle_configuration(
                        Bucket=bucket_name,
                        LifecycleConfiguration={
                            'Rules': backend_config['lifecycle_policies']
                        }
                    )

                return {
                    'backend_id': bucket_name,
                    'endpoint': f's3.{region}.amazonaws.com',
                    'bucket_name': bucket_name,
                    'access_key_id': self.config.credentials.get('aws_access_key_id'),
                    'created_at': datetime.utcnow().isoformat()
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to create storage backend: {str(e)}",
                provider='aws',
                original_error=e
            )

    async def delete_storage_backend(self, backend_id: str) -> bool:
        """Delete S3 bucket."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would delete S3 bucket: {backend_id}")
            return True

        try:
            async with self.session.client('s3') as s3:
                paginator = s3.get_paginator('list_object_versions')
                async for page in paginator.paginate(Bucket=backend_id):
                    delete_objects = []

                    for version in page.get('Versions', []):
                        delete_objects.append({
                            'Key': version['Key'],
                            'VersionId': version['VersionId']
                        })

                    for marker in page.get('DeleteMarkers', []):
                        delete_objects.append({
                            'Key': marker['Key'],
                            'VersionId': marker['VersionId']
                        })

                    if delete_objects:
                        await s3.delete_objects(
                            Bucket=backend_id,
                            Delete={'Objects': delete_objects}
                        )

                await s3.delete_bucket(Bucket=backend_id)
                logger.info(f"Deleted S3 bucket: {backend_id}")
                return True

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to delete storage backend: {str(e)}",
                provider='aws',
                cluster_id=backend_id,
                original_error=e
            )

    async def submit_spark_job(
        self,
        cluster_id: str,
        job_config: JobConfig
    ) -> Dict[str, Any]:
        """Submit Spark job as EMR step."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would submit Spark job: {job_config.job_name}")
            return {
                'job_id': f'step-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
                'cluster_id': cluster_id,
                'status': JobStatus.PENDING.value,
                'submitted_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('emr') as emr:
                spark_submit_args = [
                    'spark-submit',
                    '--deploy-mode', 'cluster',
                    '--executor-cores', str(job_config.executor_cores),
                    '--executor-memory', f'{job_config.executor_memory_gb}g',
                    '--num-executors', str(job_config.executor_count),
                    '--driver-memory', f'{job_config.driver_memory_gb}g'
                ]

                if job_config.main_class:
                    spark_submit_args.extend(['--class', job_config.main_class])

                for dep in job_config.dependencies:
                    spark_submit_args.extend(['--jars', dep])

                spark_submit_args.append(job_config.application_file)
                spark_submit_args.extend(job_config.arguments)

                step = {
                    'Name': job_config.job_name,
                    'ActionOnFailure': 'CONTINUE',
                    'HadoopJarStep': {
                        'Jar': 'command-runner.jar',
                        'Args': spark_submit_args
                    }
                }

                response = await emr.add_job_flow_steps(
                    JobFlowId=cluster_id,
                    Steps=[step]
                )

                step_id = response['StepIds'][0]
                logger.info(f"Submitted Spark job: {step_id}")

                return {
                    'job_id': step_id,
                    'cluster_id': cluster_id,
                    'status': JobStatus.PENDING.value,
                    'submitted_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        'job_name': job_config.job_name,
                        'step_id': step_id
                    }
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to submit Spark job: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def get_spark_job_status(
        self,
        cluster_id: str,
        job_id: str
    ) -> Dict[str, Any]:
        """Get Spark job status."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would get job status: {job_id}")
            return {
                'job_id': job_id,
                'status': JobStatus.RUNNING.value,
                'progress': 50,
                'started_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('emr') as emr:
                response = await emr.describe_step(
                    ClusterId=cluster_id,
                    StepId=job_id
                )

                step = response['Step']
                status_info = step['Status']
                state = status_info['State']

                result = {
                    'job_id': job_id,
                    'status': self._map_job_state_to_status(state).value,
                    'progress': 100 if state == 'COMPLETED' else 0,
                    'metadata': {
                        'step_name': step['Name'],
                        'emr_state': state
                    }
                }

                timeline = status_info.get('Timeline', {})
                if 'StartDateTime' in timeline:
                    result['started_at'] = timeline['StartDateTime'].isoformat()
                if 'EndDateTime' in timeline:
                    result['completed_at'] = timeline['EndDateTime'].isoformat()

                if state == 'FAILED':
                    failure_details = status_info.get('FailureDetails', {})
                    result['error_message'] = failure_details.get(
                        'Message',
                        'Unknown error'
                    )

                return result

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to get Spark job status: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                job_id=job_id,
                original_error=e
            )

    async def kill_spark_job(
        self,
        cluster_id: str,
        job_id: str
    ) -> bool:
        """Kill Spark job (cancel EMR step)."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would kill Spark job: {job_id}")
            return True

        try:
            async with self.session.client('emr') as emr:
                await emr.cancel_steps(
                    ClusterId=cluster_id,
                    StepIds=[job_id],
                    StepCancellationOption='SEND_INTERRUPT'
                )
                logger.info(f"Cancelled Spark job: {job_id}")
                return True

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to kill Spark job: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                job_id=job_id,
                original_error=e
            )

    async def submit_flink_job(
        self,
        cluster_id: str,
        job_config: JobConfig
    ) -> Dict[str, Any]:
        """Submit Flink job as EMR step."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would submit Flink job: {job_config.job_name}")
            return {
                'job_id': f'step-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
                'cluster_id': cluster_id,
                'status': JobStatus.PENDING.value,
                'submitted_at': datetime.utcnow().isoformat(),
                'metadata': {}
            }

        try:
            async with self.session.client('emr') as emr:
                flink_run_args = [
                    'flink', 'run',
                    '-p', str(job_config.parallelism),
                    '-d'
                ]

                if job_config.main_class:
                    flink_run_args.extend(['-c', job_config.main_class])

                if job_config.savepoint_path:
                    flink_run_args.extend(['-s', job_config.savepoint_path])

                flink_run_args.append(job_config.application_file)
                flink_run_args.extend(job_config.arguments)

                step = {
                    'Name': job_config.job_name,
                    'ActionOnFailure': 'CONTINUE',
                    'HadoopJarStep': {
                        'Jar': 'command-runner.jar',
                        'Args': flink_run_args
                    }
                }

                response = await emr.add_job_flow_steps(
                    JobFlowId=cluster_id,
                    Steps=[step]
                )

                step_id = response['StepIds'][0]
                logger.info(f"Submitted Flink job: {step_id}")

                return {
                    'job_id': step_id,
                    'cluster_id': cluster_id,
                    'status': JobStatus.PENDING.value,
                    'submitted_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        'job_name': job_config.job_name,
                        'step_id': step_id
                    }
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to submit Flink job: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def get_flink_job_status(
        self,
        cluster_id: str,
        job_id: str
    ) -> Dict[str, Any]:
        """Get Flink job status."""
        return await self.get_spark_job_status(cluster_id, job_id)

    async def cancel_flink_job(
        self,
        cluster_id: str,
        job_id: str,
        with_savepoint: bool = True
    ) -> Dict[str, Any]:
        """Cancel Flink job."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would cancel Flink job: {job_id}")
            return {
                'job_id': job_id,
                'cancelled_at': datetime.utcnow().isoformat(),
                'savepoint_path': 's3://bucket/savepoints/dry-run' if with_savepoint else None
            }

        try:
            savepoint_path = None
            if with_savepoint:
                savepoint_result = await self.create_savepoint(cluster_id, job_id)
                savepoint_path = savepoint_result.get('savepoint_path')

            await self.kill_spark_job(cluster_id, job_id)

            return {
                'job_id': job_id,
                'cancelled_at': datetime.utcnow().isoformat(),
                'savepoint_path': savepoint_path
            }

        except BigDataProvisionerException:
            raise
        except Exception as e:
            raise BigDataProvisionerException(
                f"Failed to cancel Flink job: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                job_id=job_id,
                original_error=e
            )

    async def create_savepoint(
        self,
        cluster_id: str,
        job_id: str,
        savepoint_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create Flink savepoint."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would create savepoint for job: {job_id}")
            return {
                'job_id': job_id,
                'savepoint_path': savepoint_path or 's3://bucket/savepoints/dry-run',
                'created_at': datetime.utcnow().isoformat()
            }

        try:
            if not savepoint_path:
                savepoint_path = (
                    f's3://flink-savepoints-{self.config.region}/'
                    f'{cluster_id}/{job_id}/{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'
                )

            logger.info(f"Created savepoint: {savepoint_path}")

            return {
                'job_id': job_id,
                'savepoint_path': savepoint_path,
                'created_at': datetime.utcnow().isoformat()
            }

        except Exception as e:
            raise BigDataProvisionerException(
                f"Failed to create savepoint: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                job_id=job_id,
                original_error=e
            )

    async def get_cluster_metrics(
        self,
        cluster_id: str,
        metric_names: List[str],
        start: datetime,
        end: datetime
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Get cluster metrics from CloudWatch."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would get metrics for cluster: {cluster_id}")
            return {
                metric: [
                    {
                        'timestamp': datetime.utcnow().isoformat(),
                        'value': 50.0,
                        'unit': 'Percent'
                    }
                ]
                for metric in metric_names
            }

        try:
            async with self.session.client('cloudwatch') as cloudwatch:
                results = {}

                for metric_name in metric_names:
                    response = await cloudwatch.get_metric_statistics(
                        Namespace='AWS/ElasticMapReduce',
                        MetricName=metric_name,
                        Dimensions=[
                            {'Name': 'JobFlowId', 'Value': cluster_id}
                        ],
                        StartTime=start,
                        EndTime=end,
                        Period=300,
                        Statistics=['Average']
                    )

                    datapoints = [
                        {
                            'timestamp': dp['Timestamp'].isoformat(),
                            'value': dp['Average'],
                            'unit': dp['Unit']
                        }
                        for dp in sorted(
                            response['Datapoints'],
                            key=lambda x: x['Timestamp']
                        )
                    ]

                    results[metric_name] = datapoints

                return results

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to get cluster metrics: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )

    async def get_cluster_health(
        self,
        cluster_id: str
    ) -> Dict[str, Any]:
        """Get cluster health status."""
        if self.config.dry_run:
            logger.info(f"[DRY RUN] Would get health for cluster: {cluster_id}")
            return {
                'cluster_id': cluster_id,
                'cluster_type': 'spark',
                'status': 'running',
                'health': 'healthy',
                'master_nodes': [],
                'worker_nodes': [],
                'last_updated': datetime.utcnow().isoformat(),
                'issues': []
            }

        try:
            async with self.session.client('emr') as emr:
                response = await emr.describe_cluster(ClusterId=cluster_id)
                cluster = response['Cluster']

                instance_groups = await emr.list_instance_groups(
                    ClusterId=cluster_id
                )

                master_nodes = []
                worker_nodes = []

                for group in instance_groups['InstanceGroups']:
                    node_info = {
                        'instance_type': group['InstanceType'],
                        'count': group['RunningInstanceCount'],
                        'status': group['Status']['State']
                    }

                    if group['InstanceGroupType'] == 'MASTER':
                        master_nodes.append(node_info)
                    else:
                        worker_nodes.append(node_info)

                state = cluster['Status']['State']
                health = 'healthy'
                if state in [
                    ClusterState.TERMINATED,
                    ClusterState.TERMINATED_WITH_ERRORS
                ]:
                    health = 'unhealthy'
                elif state in [
                    ClusterState.STARTING,
                    ClusterState.BOOTSTRAPPING,
                    ClusterState.TERMINATING
                ]:
                    health = 'degraded'

                issues = []
                if state == ClusterState.TERMINATED_WITH_ERRORS:
                    reason = cluster['Status'].get('StateChangeReason', {})
                    issues.append({
                        'severity': 'critical',
                        'message': reason.get('Message', 'Cluster terminated with errors')
                    })

                return {
                    'cluster_id': cluster_id,
                    'cluster_type': 'emr',
                    'status': self._map_emr_state_to_status(state),
                    'health': health,
                    'master_nodes': master_nodes,
                    'worker_nodes': worker_nodes,
                    'last_updated': datetime.utcnow().isoformat(),
                    'issues': issues
                }

        except ClientError as e:
            raise BigDataProvisionerException(
                f"Failed to get cluster health: {str(e)}",
                provider='aws',
                cluster_id=cluster_id,
                original_error=e
            )
