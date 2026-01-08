"""
AWS provisioner for ArticDBM.

Implements database and cache provisioning using AWS services:
- RDS for relational databases (PostgreSQL, MySQL, MariaDB, SQL Server)
- ElastiCache for Redis/Memcached
- DocumentDB for MongoDB

Copyright (c) 2025 Penguin Tech Inc
Licensed under Limited AGPL3
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False

from .base import BaseProvisioner, ProvisioningError, ResourceType

logger = logging.getLogger(__name__)


class AWSProvisioner(BaseProvisioner):
    """AWS cloud provisioner using boto3 for RDS, ElastiCache, and DocumentDB."""

    # Map ArticDBM resource types to AWS services
    SERVICE_MAPPING = {
        ResourceType.POSTGRESQL: 'rds',
        ResourceType.MYSQL: 'rds',
        ResourceType.MARIADB: 'rds',
        ResourceType.SQLSERVER: 'rds',
        ResourceType.REDIS: 'elasticache',
        ResourceType.MEMCACHED: 'elasticache',
        ResourceType.MONGODB: 'docdb',
    }

    # RDS engine names
    RDS_ENGINE_MAPPING = {
        ResourceType.POSTGRESQL: 'postgres',
        ResourceType.MYSQL: 'mysql',
        ResourceType.MARIADB: 'mariadb',
        ResourceType.SQLSERVER: 'sqlserver-ex',
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize AWS provisioner.

        Args:
            config: Configuration dictionary containing:
                - aws_access_key_id: AWS access key
                - aws_secret_access_key: AWS secret key
                - region: AWS region (e.g., 'us-east-1')
                - vpc_id: VPC ID for resource placement
                - subnet_ids: List of subnet IDs for subnet groups
        """
        super().__init__(config)

        if not BOTO3_AVAILABLE:
            raise ProvisioningError("boto3 library not installed")

        self.access_key = config.get('aws_access_key_id')
        self.secret_key = config.get('aws_secret_access_key')
        self.region = config.get('region', 'us-east-1')
        self.vpc_id = config.get('vpc_id')
        self.subnet_ids = config.get('subnet_ids', [])

        if not all([self.access_key, self.secret_key, self.vpc_id]):
            raise ProvisioningError(
                "Missing required AWS configuration: "
                "aws_access_key_id, aws_secret_access_key, vpc_id"
            )

        # Initialize boto3 session
        self.session = boto3.Session(
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key,
            region_name=self.region
        )

        # Initialize service clients (lazy loaded)
        self._rds_client = None
        self._elasticache_client = None
        self._docdb_client = None
        self._ec2_client = None
        self._cloudwatch_client = None

    @property
    def rds_client(self):
        """Lazy-load RDS client."""
        if self._rds_client is None:
            self._rds_client = self.session.client('rds')
        return self._rds_client

    @property
    def elasticache_client(self):
        """Lazy-load ElastiCache client."""
        if self._elasticache_client is None:
            self._elasticache_client = self.session.client('elasticache')
        return self._elasticache_client

    @property
    def docdb_client(self):
        """Lazy-load DocumentDB client."""
        if self._docdb_client is None:
            self._docdb_client = self.session.client('docdb')
        return self._docdb_client

    @property
    def ec2_client(self):
        """Lazy-load EC2 client."""
        if self._ec2_client is None:
            self._ec2_client = self.session.client('ec2')
        return self._ec2_client

    @property
    def cloudwatch_client(self):
        """Lazy-load CloudWatch client."""
        if self._cloudwatch_client is None:
            self._cloudwatch_client = self.session.client('cloudwatch')
        return self._cloudwatch_client

    def provision(
        self,
        resource_type: ResourceType,
        resource_name: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Provision AWS resource based on type.

        Args:
            resource_type: Type of resource to provision
            resource_name: Unique name for the resource
            config: Resource-specific configuration

        Returns:
            Dict containing provisioned resource details

        Raises:
            ProvisioningError: If provisioning fails
        """
        service = self.SERVICE_MAPPING.get(resource_type)
        if not service:
            raise ProvisioningError(f"Unsupported resource type: {resource_type}")

        try:
            if service == 'rds':
                return self._provision_rds(resource_type, resource_name, config)
            elif service == 'elasticache':
                return self._provision_elasticache(resource_type, resource_name, config)
            elif service == 'docdb':
                return self._provision_docdb(resource_name, config)
            else:
                raise ProvisioningError(f"Unknown service: {service}")
        except (BotoCoreError, ClientError) as e:
            logger.error(f"AWS API error provisioning {resource_name}: {e}")
            raise ProvisioningError(f"AWS provisioning failed: {str(e)}")

    def _provision_rds(
        self,
        resource_type: ResourceType,
        instance_id: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Provision RDS database instance."""
        engine = self.RDS_ENGINE_MAPPING[resource_type]

        # Create DB subnet group if needed
        subnet_group_name = f"{instance_id}-subnet-group"
        self._create_db_subnet_group(subnet_group_name)

        # Create security group
        sg_id = self._create_security_group(
            name=f"{instance_id}-sg",
            description=f"Security group for {instance_id}",
            ingress_rules=config.get('ingress_rules', [])
        )

        # Prepare RDS parameters
        params = {
            'DBInstanceIdentifier': instance_id,
            'Engine': engine,
            'DBInstanceClass': config.get('instance_class', 'db.t3.micro'),
            'AllocatedStorage': config.get('allocated_storage', 20),
            'MasterUsername': config.get('master_username', 'admin'),
            'MasterUserPassword': config.get('master_password'),
            'VpcSecurityGroupIds': [sg_id],
            'DBSubnetGroupName': subnet_group_name,
            'PubliclyAccessible': config.get('publicly_accessible', False),
            'StorageEncrypted': config.get('storage_encrypted', True),
            'BackupRetentionPeriod': config.get('backup_retention', 7),
            'MultiAZ': config.get('multi_az', False),
            'Tags': self._format_tags(config.get('tags', {}))
        }

        # Add engine version if specified
        if 'engine_version' in config:
            params['EngineVersion'] = config['engine_version']

        # Create DB instance
        response = self.rds_client.create_db_instance(**params)
        db_instance = response['DBInstance']

        result = {
            'resource_id': db_instance['DBInstanceIdentifier'],
            'endpoint': db_instance.get('Endpoint', {}).get('Address'),
            'port': db_instance.get('Endpoint', {}).get('Port'),
            'status': db_instance['DBInstanceStatus'],
            'engine': db_instance['Engine'],
            'security_group_id': sg_id,
            'subnet_group_name': subnet_group_name
        }

        # Create read replicas if requested
        if config.get('read_replicas', 0) > 0:
            replicas = self._create_read_replicas(
                instance_id,
                config['read_replicas'],
                config
            )
            result['read_replicas'] = replicas

        return result

    def _provision_elasticache(
        self,
        resource_type: ResourceType,
        cluster_id: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Provision ElastiCache cluster (Redis or Memcached)."""
        engine = 'redis' if resource_type == ResourceType.REDIS else 'memcached'

        # Create cache subnet group
        subnet_group_name = f"{cluster_id}-subnet-group"
        self._create_cache_subnet_group(subnet_group_name)

        # Create security group
        sg_id = self._create_security_group(
            name=f"{cluster_id}-sg",
            description=f"Security group for {cluster_id}",
            ingress_rules=config.get('ingress_rules', [])
        )

        # Prepare ElastiCache parameters
        params = {
            'CacheClusterId': cluster_id,
            'Engine': engine,
            'CacheNodeType': config.get('node_type', 'cache.t3.micro'),
            'NumCacheNodes': config.get('num_nodes', 1),
            'SecurityGroupIds': [sg_id],
            'CacheSubnetGroupName': subnet_group_name,
            'Tags': self._format_tags(config.get('tags', {}))
        }

        # Redis-specific configuration
        if engine == 'redis':
            params['EngineVersion'] = config.get('engine_version', '7.0')
            if config.get('tls_enabled', True):
                params['TransitEncryptionEnabled'] = True
            if config.get('auth_token'):
                params['AuthToken'] = config['auth_token']

        # Create cache cluster
        response = self.elasticache_client.create_cache_cluster(**params)
        cache_cluster = response['CacheCluster']

        return {
            'resource_id': cache_cluster['CacheClusterId'],
            'endpoint': cache_cluster.get('ConfigurationEndpoint', {}).get('Address'),
            'port': cache_cluster.get('ConfigurationEndpoint', {}).get('Port'),
            'status': cache_cluster['CacheClusterStatus'],
            'engine': cache_cluster['Engine'],
            'security_group_id': sg_id,
            'subnet_group_name': subnet_group_name
        }

    def _provision_docdb(
        self,
        cluster_id: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Provision DocumentDB cluster."""
        # Create DB subnet group
        subnet_group_name = f"{cluster_id}-subnet-group"
        self._create_db_subnet_group(subnet_group_name)

        # Create security group
        sg_id = self._create_security_group(
            name=f"{cluster_id}-sg",
            description=f"Security group for {cluster_id}",
            ingress_rules=config.get('ingress_rules', [])
        )

        # Create DocumentDB cluster
        cluster_params = {
            'DBClusterIdentifier': cluster_id,
            'Engine': 'docdb',
            'MasterUsername': config.get('master_username', 'admin'),
            'MasterUserPassword': config.get('master_password'),
            'VpcSecurityGroupIds': [sg_id],
            'DBSubnetGroupName': subnet_group_name,
            'StorageEncrypted': config.get('storage_encrypted', True),
            'BackupRetentionPeriod': config.get('backup_retention', 7),
            'Tags': self._format_tags(config.get('tags', {}))
        }

        if config.get('tls_enabled', True):
            cluster_params['EnableCloudwatchLogsExports'] = ['audit', 'profiler']

        response = self.docdb_client.create_db_cluster(**cluster_params)
        cluster = response['DBCluster']

        # Create cluster instances
        num_instances = config.get('num_instances', 1)
        instances = []
        for i in range(num_instances):
            instance_id = f"{cluster_id}-instance-{i+1}"
            instance_response = self.docdb_client.create_db_instance(
                DBInstanceIdentifier=instance_id,
                DBInstanceClass=config.get('instance_class', 'db.t3.medium'),
                Engine='docdb',
                DBClusterIdentifier=cluster_id
            )
            instances.append(instance_response['DBInstance'])

        return {
            'resource_id': cluster['DBClusterIdentifier'],
            'endpoint': cluster.get('Endpoint'),
            'port': cluster.get('Port'),
            'status': cluster['Status'],
            'engine': 'docdb',
            'instances': [inst['DBInstanceIdentifier'] for inst in instances],
            'security_group_id': sg_id,
            'subnet_group_name': subnet_group_name
        }

    def _create_db_subnet_group(self, group_name: str) -> None:
        """Create RDS/DocumentDB subnet group."""
        try:
            self.rds_client.create_db_subnet_group(
                DBSubnetGroupName=group_name,
                DBSubnetGroupDescription=f"Subnet group for {group_name}",
                SubnetIds=self.subnet_ids,
                Tags=self._format_tags({'ManagedBy': 'ArticDBM'})
            )
            logger.info(f"Created DB subnet group: {group_name}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'DBSubnetGroupAlreadyExists':
                raise

    def _create_cache_subnet_group(self, group_name: str) -> None:
        """Create ElastiCache subnet group."""
        try:
            self.elasticache_client.create_cache_subnet_group(
                CacheSubnetGroupName=group_name,
                CacheSubnetGroupDescription=f"Subnet group for {group_name}",
                SubnetIds=self.subnet_ids
            )
            logger.info(f"Created cache subnet group: {group_name}")
        except ClientError as e:
            if e.response['Error']['Code'] != 'CacheSubnetGroupAlreadyExists':
                raise

    def _create_security_group(
        self,
        name: str,
        description: str,
        ingress_rules: List[Dict[str, Any]]
    ) -> str:
        """
        Create EC2 security group with ingress rules.

        Args:
            name: Security group name
            description: Security group description
            ingress_rules: List of ingress rule dicts with keys:
                - protocol: 'tcp', 'udp', etc.
                - port: Port number
                - cidr: CIDR block (e.g., '0.0.0.0/0')

        Returns:
            Security group ID
        """
        try:
            response = self.ec2_client.create_security_group(
                GroupName=name,
                Description=description,
                VpcId=self.vpc_id,
                TagSpecifications=[{
                    'ResourceType': 'security-group',
                    'Tags': self._format_tags({'ManagedBy': 'ArticDBM'})
                }]
            )
            sg_id = response['GroupId']

            # Add ingress rules
            if ingress_rules:
                ip_permissions = []
                for rule in ingress_rules:
                    ip_permissions.append({
                        'IpProtocol': rule.get('protocol', 'tcp'),
                        'FromPort': rule['port'],
                        'ToPort': rule['port'],
                        'IpRanges': [{'CidrIp': rule.get('cidr', '0.0.0.0/0')}]
                    })

                self.ec2_client.authorize_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=ip_permissions
                )

            logger.info(f"Created security group: {sg_id}")
            return sg_id

        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidGroup.Duplicate':
                # Get existing security group
                response = self.ec2_client.describe_security_groups(
                    Filters=[
                        {'Name': 'group-name', 'Values': [name]},
                        {'Name': 'vpc-id', 'Values': [self.vpc_id]}
                    ]
                )
                return response['SecurityGroups'][0]['GroupId']
            raise

    def _create_read_replicas(
        self,
        source_instance_id: str,
        count: int,
        config: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Create read replicas for RDS instance."""
        replicas = []
        for i in range(count):
            replica_id = f"{source_instance_id}-replica-{i+1}"
            response = self.rds_client.create_db_instance_read_replica(
                DBInstanceIdentifier=replica_id,
                SourceDBInstanceIdentifier=source_instance_id,
                DBInstanceClass=config.get('replica_instance_class', config.get('instance_class')),
                PubliclyAccessible=config.get('publicly_accessible', False),
                Tags=self._format_tags(config.get('tags', {}))
            )
            replica = response['DBInstance']
            replicas.append({
                'replica_id': replica['DBInstanceIdentifier'],
                'endpoint': replica.get('Endpoint', {}).get('Address'),
                'port': replica.get('Endpoint', {}).get('Port')
            })

        return replicas

    def _format_tags(self, tags: Dict[str, str]) -> List[Dict[str, str]]:
        """Format tags dict to AWS tag list format."""
        aws_tags = [{'Key': k, 'Value': v} for k, v in tags.items()]
        # Add default tags
        aws_tags.extend([
            {'Key': 'ManagedBy', 'Value': 'ArticDBM'},
            {'Key': 'CreatedAt', 'Value': datetime.utcnow().isoformat()}
        ])
        return aws_tags

    def deprovision(self, resource_type: ResourceType, resource_id: str) -> bool:
        """
        Deprovision AWS resource.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier

        Returns:
            True if successful

        Raises:
            ProvisioningError: If deprovisioning fails
        """
        service = self.SERVICE_MAPPING.get(resource_type)
        if not service:
            raise ProvisioningError(f"Unsupported resource type: {resource_type}")

        try:
            if service == 'rds':
                self.rds_client.delete_db_instance(
                    DBInstanceIdentifier=resource_id,
                    SkipFinalSnapshot=True,
                    DeleteAutomatedBackups=True
                )
            elif service == 'elasticache':
                self.elasticache_client.delete_cache_cluster(
                    CacheClusterId=resource_id
                )
            elif service == 'docdb':
                # Delete instances first
                cluster = self.docdb_client.describe_db_clusters(
                    DBClusterIdentifier=resource_id
                )['DBClusters'][0]

                for member in cluster.get('DBClusterMembers', []):
                    self.docdb_client.delete_db_instance(
                        DBInstanceIdentifier=member['DBInstanceIdentifier']
                    )

                # Delete cluster
                self.docdb_client.delete_db_cluster(
                    DBClusterIdentifier=resource_id,
                    SkipFinalSnapshot=True
                )

            logger.info(f"Deprovisioned {resource_type.value}: {resource_id}")
            return True

        except (BotoCoreError, ClientError) as e:
            logger.error(f"AWS API error deprovisioning {resource_id}: {e}")
            raise ProvisioningError(f"AWS deprovisioning failed: {str(e)}")

    def get_status(
        self,
        resource_type: ResourceType,
        resource_id: str
    ) -> Dict[str, Any]:
        """
        Get AWS resource status.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier

        Returns:
            Dict with status information

        Raises:
            ProvisioningError: If status check fails
        """
        service = self.SERVICE_MAPPING.get(resource_type)
        if not service:
            raise ProvisioningError(f"Unsupported resource type: {resource_type}")

        try:
            if service == 'rds':
                response = self.rds_client.describe_db_instances(
                    DBInstanceIdentifier=resource_id
                )
                instance = response['DBInstances'][0]
                return {
                    'status': instance['DBInstanceStatus'],
                    'endpoint': instance.get('Endpoint', {}).get('Address'),
                    'port': instance.get('Endpoint', {}).get('Port'),
                    'engine': instance['Engine'],
                    'storage': instance['AllocatedStorage'],
                    'multi_az': instance.get('MultiAZ', False)
                }

            elif service == 'elasticache':
                response = self.elasticache_client.describe_cache_clusters(
                    CacheClusterId=resource_id,
                    ShowCacheNodeInfo=True
                )
                cluster = response['CacheClusters'][0]
                return {
                    'status': cluster['CacheClusterStatus'],
                    'endpoint': cluster.get('ConfigurationEndpoint', {}).get('Address'),
                    'port': cluster.get('ConfigurationEndpoint', {}).get('Port'),
                    'engine': cluster['Engine'],
                    'num_nodes': cluster['NumCacheNodes']
                }

            elif service == 'docdb':
                response = self.docdb_client.describe_db_clusters(
                    DBClusterIdentifier=resource_id
                )
                cluster = response['DBClusters'][0]
                return {
                    'status': cluster['Status'],
                    'endpoint': cluster.get('Endpoint'),
                    'port': cluster.get('Port'),
                    'engine': cluster['Engine'],
                    'members': len(cluster.get('DBClusterMembers', []))
                }

        except (BotoCoreError, ClientError) as e:
            logger.error(f"AWS API error getting status for {resource_id}: {e}")
            raise ProvisioningError(f"AWS status check failed: {str(e)}")

    def get_metrics(
        self,
        resource_type: ResourceType,
        resource_id: str,
        metric_names: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Get CloudWatch metrics for resource.

        Args:
            resource_type: Type of resource
            resource_id: Resource identifier
            metric_names: Specific metrics to retrieve (None for defaults)

        Returns:
            Dict with metric data

        Raises:
            ProvisioningError: If metrics retrieval fails
        """
        service = self.SERVICE_MAPPING.get(resource_type)
        if not service:
            raise ProvisioningError(f"Unsupported resource type: {resource_type}")

        # Default metrics per service
        default_metrics = {
            'rds': ['CPUUtilization', 'DatabaseConnections', 'FreeStorageSpace'],
            'elasticache': ['CPUUtilization', 'NetworkBytesIn', 'NetworkBytesOut'],
            'docdb': ['CPUUtilization', 'DatabaseConnections', 'VolumeBytesUsed']
        }

        metrics_to_fetch = metric_names or default_metrics.get(service, [])
        namespace = {
            'rds': 'AWS/RDS',
            'elasticache': 'AWS/ElastiCache',
            'docdb': 'AWS/DocDB'
        }[service]

        dimension_name = {
            'rds': 'DBInstanceIdentifier',
            'elasticache': 'CacheClusterId',
            'docdb': 'DBClusterIdentifier'
        }[service]

        try:
            metrics_data = {}
            for metric_name in metrics_to_fetch:
                response = self.cloudwatch_client.get_metric_statistics(
                    Namespace=namespace,
                    MetricName=metric_name,
                    Dimensions=[{'Name': dimension_name, 'Value': resource_id}],
                    StartTime=datetime.utcnow().replace(hour=0, minute=0, second=0),
                    EndTime=datetime.utcnow(),
                    Period=3600,
                    Statistics=['Average', 'Maximum']
                )
                metrics_data[metric_name] = response['Datapoints']

            return metrics_data

        except (BotoCoreError, ClientError) as e:
            logger.error(f"CloudWatch API error for {resource_id}: {e}")
            raise ProvisioningError(f"Metrics retrieval failed: {str(e)}")

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate AWS-specific configuration.

        Args:
            config: Configuration to validate

        Returns:
            True if valid

        Raises:
            ProvisioningError: If configuration is invalid
        """
        required_fields = ['aws_access_key_id', 'aws_secret_access_key', 'region', 'vpc_id']
        missing = [f for f in required_fields if not config.get(f)]

        if missing:
            raise ProvisioningError(f"Missing required AWS config: {', '.join(missing)}")

        # Validate region format
        if not config['region'].startswith(('us-', 'eu-', 'ap-', 'ca-', 'sa-')):
            raise ProvisioningError(f"Invalid AWS region: {config['region']}")

        # Validate VPC exists
        try:
            self.ec2_client.describe_vpcs(VpcIds=[config['vpc_id']])
        except ClientError:
            raise ProvisioningError(f"VPC not found: {config['vpc_id']}")

        return True
