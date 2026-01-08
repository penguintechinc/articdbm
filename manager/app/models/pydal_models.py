"""
PyDAL Database Models for ArticDBM

Defines all database tables using PyDAL ORM with proper validation,
relationships, and timestamp tracking.
"""

from datetime import datetime
from pydal import DAL, Field


def define_models(db: DAL) -> None:
    """
    Define all PyDAL models for ArticDBM.

    Args:
        db: PyDAL database instance
    """

    # ========================
    # Authentication & Users
    # ========================

    db.define_table(
        'auth_user',
        Field('first_name', 'string', default=''),
        Field('last_name', 'string', default=''),
        Field('email', 'string', unique=True, required=True),
        Field('username', 'string', unique=True, required=True),
        Field('password', 'password', required=True),
        Field('last_login', 'datetime'),
        Field('is_active', 'boolean', default=True),
        Field('fs_enabled', 'boolean', default=True),  # Flask-Security enabled
        Field('confirmed_at', 'datetime'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
        format='%(email)s',
    )

    db.define_table(
        'auth_role',
        Field('name', 'string', unique=True, required=True),
        Field('description', 'text'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
    )

    db.define_table(
        'auth_user_role',
        Field('user_id', 'reference auth_user', required=True),
        Field('role_id', 'reference auth_role', required=True),
    )

    # ========================
    # Applications
    # ========================

    db.define_table(
        'applications',
        Field('name', 'string', required=True, unique=True),
        Field('description', 'text'),
        Field('deployment_model', 'string',
              default='shared',
              requires=IS_IN_SET(['shared', 'separate']),
              comment='Shared: multiple apps per cluster, Separate: dedicated resources'),
        Field('organization_id', 'reference organizations'),
        Field('elder_entity_id', 'string',
              comment='Elder service entity ID for sync'),
        Field('elder_service_id', 'string',
              comment='Elder service ID reference'),
        Field('tags', 'json', default='{}',
              comment='JSON tags for categorization'),
        Field('is_active', 'boolean', default=True),
        Field('created_by', 'reference auth_user'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
        format='%(name)s',
    )

    db.define_table(
        'organizations',
        Field('name', 'string', required=True, unique=True),
        Field('description', 'text'),
        Field('is_active', 'boolean', default=True),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
    )

    # ========================
    # Providers
    # ========================

    db.define_table(
        'providers',
        Field('name', 'string', required=True),
        Field('provider_type', 'string', required=True,
              requires=IS_IN_SET(['kubernetes', 'aws', 'gcp', 'azure', 'vultr'])),
        Field('configuration', 'json', default='{}',
              comment='Provider-specific config (kubeconfig, credentials, regions, etc)'),
        Field('credentials_secret_name', 'string',
              comment='Reference to secret management system'),
        Field('is_default', 'boolean', default=False,
              comment='Default provider for new resources'),
        Field('is_active', 'boolean', default=True),
        Field('status', 'string', default='unknown',
              requires=IS_IN_SET(['healthy', 'degraded', 'unhealthy', 'unknown'])),
        Field('last_health_check', 'datetime'),
        Field('created_by', 'reference auth_user'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
        format='%(name)s',
    )

    # ========================
    # Resources
    # ========================

    db.define_table(
        'resources',
        Field('name', 'string', required=True),
        Field('resource_type', 'string', required=True,
              requires=IS_IN_SET(['database', 'cache']),
              comment='Type of resource: database or cache'),
        Field('engine', 'string', required=True,
              comment='Engine type: postgresql, mysql, redis, memcached, etc'),
        Field('engine_version', 'string',
              comment='Version of the database/cache engine'),
        Field('provider_id', 'reference providers', required=True),
        Field('application_id', 'reference applications', required=True),
        Field('cluster_id', 'reference resource_clusters',
              comment='Optional cluster this resource belongs to'),
        Field('endpoint', 'string', required=True,
              comment='Hostname or IP address'),
        Field('port', 'integer', required=True,
              comment='Network port'),
        Field('database_name', 'string',
              comment='Database name (for databases, not cache)'),
        Field('instance_class', 'string',
              comment='Instance type/class (t3.micro, db.r5.large, etc)'),
        Field('storage_size_gb', 'integer',
              comment='Allocated storage in GB'),
        Field('multi_az', 'boolean', default=False,
              comment='Multi-availability zone deployment'),
        Field('replicas', 'integer', default=0,
              comment='Number of read replicas'),
        Field('tls_mode', 'string', default='required',
              requires=IS_IN_SET(['required', 'optional', 'disabled']),
              comment='TLS requirement level'),
        Field('tls_ca_cert', 'text',
              comment='CA certificate for TLS validation'),
        Field('provider_resource_id', 'string',
              comment='Provider-specific resource ID (AWS ARN, etc)'),
        Field('provider_metadata', 'json', default='{}',
              comment='Provider-specific metadata and tags'),
        Field('status', 'string', default='creating',
              requires=IS_IN_SET(['creating', 'available', 'modifying', 'deleting',
                                 'deleted', 'failed', 'unknown'])),
        Field('status_message', 'text',
              comment='Status detail message'),
        Field('tags', 'json', default='{}',
              comment='Resource tags - synced to cloud provider'),
        Field('elder_entity_id', 'string',
              comment='Elder entity ID for sync'),
        Field('created_by', 'reference auth_user'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
        format='%(name)s',
    )

    db.define_table(
        'resource_clusters',
        Field('name', 'string', required=True),
        Field('cluster_type', 'string', required=True,
              requires=IS_IN_SET(['kubernetes', 'aws_rds', 'gcp_cloudsql',
                                 'azure_sql', 'vultr_db', 'redis_cluster']),
              comment='Type of cluster'),
        Field('engine', 'string', required=True,
              comment='Primary engine: postgresql, mysql, redis, etc'),
        Field('provider_id', 'reference providers', required=True),
        Field('application_id', 'reference applications', required=True),
        Field('deployment_model', 'string',
              requires=IS_IN_SET(['shared', 'separate']),
              comment='Resource deployment model'),
        Field('status', 'string', default='unknown',
              requires=IS_IN_SET(['creating', 'available', 'modifying', 'deleting', 'failed'])),
        Field('tags', 'json', default='{}'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
        format='%(name)s',
    )

    # ========================
    # Credentials
    # ========================

    db.define_table(
        'credentials',
        Field('name', 'string', required=True),
        Field('resource_id', 'reference resources', required=True),
        Field('application_id', 'reference applications', required=True),
        Field('credential_type', 'string', required=True,
              requires=IS_IN_SET(['password', 'iam_role', 'jwt', 'mtls']),
              comment='Type of credential'),
        # Password auth
        Field('username', 'string',
              comment='Username for password-based auth'),
        Field('password_encrypted', 'blob',
              comment='Encrypted password (uses encryption.py utilities)'),
        # IAM auth
        Field('iam_role_arn', 'string',
              comment='IAM role ARN for cloud provider'),
        Field('iam_policy', 'json', default='{}',
              comment='IAM policy document'),
        # JWT auth
        Field('jwt_subject', 'string',
              comment='JWT subject (sub) claim'),
        Field('jwt_claims', 'json', default='{}',
              comment='Additional JWT claims'),
        # mTLS auth
        Field('mtls_cert', 'text',
              comment='Client certificate (PEM)'),
        Field('mtls_key_encrypted', 'blob',
              comment='Encrypted client private key'),
        Field('mtls_ca_cert', 'text',
              comment='CA certificate (PEM) for verification'),
        # General
        Field('permissions', 'json', default='[]',
              comment='Permissions array: ["read", "write", "admin"]'),
        Field('expires_at', 'datetime',
              comment='Credential expiration timestamp'),
        # Auto-rotation
        Field('auto_rotate', 'boolean', default=False,
              comment='Enable automatic credential rotation'),
        Field('rotation_interval_days', 'integer', default=30,
              comment='Days between rotations (30, 60, 90, etc)'),
        Field('last_rotated_at', 'datetime',
              comment='Last rotation timestamp'),
        Field('next_rotation_at', 'datetime',
              comment='Scheduled next rotation'),
        Field('is_active', 'boolean', default=True),
        Field('created_by', 'reference auth_user'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
        format='%(name)s',
    )

    # ========================
    # Resource Tags
    # ========================

    db.define_table(
        'resource_tags',
        Field('resource_id', 'reference resources', required=True),
        Field('key', 'string', required=True),
        Field('value', 'string', required=True),
        Field('synced_to_provider', 'boolean', default=False,
              comment='Whether tag is synced to cloud provider'),
        Field('last_synced', 'datetime',
              comment='Last sync timestamp'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
    )

    # ========================
    # MarchProxy Configuration
    # ========================

    db.define_table(
        'marchproxy_configs',
        Field('resource_id', 'reference resources', required=True, unique=True,
              comment='One-to-one with resource'),
        Field('enabled', 'boolean', default=False,
              comment='Enable MarchProxy routing for this resource'),
        Field('route_name', 'string',
              comment='MarchProxy route name/identifier'),
        Field('listen_port', 'integer',
              comment='Port MarchProxy listens on'),
        Field('rate_limit_connections', 'integer',
              comment='Max concurrent connections'),
        Field('rate_limit_queries', 'integer',
              comment='Max queries per second'),
        Field('security_config', 'json', default='{}',
              comment='SQL injection detection, threat blocking settings'),
        Field('last_synced', 'datetime',
              comment='Last sync with MarchProxy'),
        Field('sync_status', 'string', default='pending',
              requires=IS_IN_SET(['pending', 'synced', 'failed'])),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
    )

    # ========================
    # Elder Sync State
    # ========================

    db.define_table(
        'elder_sync_state',
        Field('resource_type', 'string', required=True,
              requires=IS_IN_SET(['application', 'resource', 'credential']),
              comment='Type of entity being synced'),
        Field('local_id', 'integer', required=True,
              comment='Local database ID'),
        Field('elder_entity_id', 'string', required=True,
              comment='Elder entity ID'),
        Field('elder_service_id', 'string',
              comment='Elder service ID (for applications)'),
        Field('sync_direction', 'string', default='push',
              requires=IS_IN_SET(['push', 'pull', 'bidirectional']),
              comment='Direction of sync'),
        Field('last_synced', 'datetime',
              comment='Last successful sync'),
        Field('sync_status', 'string', default='pending',
              requires=IS_IN_SET(['pending', 'syncing', 'synced', 'failed'])),
        Field('sync_error', 'text',
              comment='Error message if sync failed'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
    )

    # ========================
    # License Info
    # ========================

    db.define_table(
        'license_info',
        Field('license_key', 'string', unique=True, required=True),
        Field('tier', 'string', required=True,
              requires=IS_IN_SET(['free', 'professional', 'enterprise']),
              comment='License tier'),
        Field('features', 'json', default='{}',
              comment='Enabled features per tier'),
        Field('resource_count', 'integer', default=0,
              comment='Current resource count'),
        Field('resource_limit', 'integer', default=3,
              comment='Max resources (free=3, professional=100, enterprise=unlimited)'),
        Field('is_active', 'boolean', default=True),
        Field('last_validated', 'datetime',
              comment='Last validation with license server'),
        Field('next_validation', 'datetime',
              comment='Next scheduled validation'),
        Field('validation_failures', 'integer', default=0,
              comment='Consecutive validation failures'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False),
    )

    # ========================
    # Audit Logging
    # ========================

    db.define_table(
        'audit_log',
        Field('user_id', 'reference auth_user'),
        Field('action', 'string', required=True,
              requires=IS_IN_SET(['create', 'read', 'update', 'delete',
                                 'login', 'logout', 'export', 'sync']),
              comment='Action type'),
        Field('resource_type', 'string',
              comment='Type of resource affected'),
        Field('resource_id', 'integer',
              comment='ID of resource affected'),
        Field('details', 'json', default='{}',
              comment='Action details and changes'),
        Field('ip_address', 'string',
              comment='Source IP address'),
        Field('user_agent', 'string',
              comment='HTTP user agent'),
        Field('status', 'string', default='success',
              requires=IS_IN_SET(['success', 'failure']),
              comment='Action result'),
        Field('error_message', 'text',
              comment='Error message if failed'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False),
        indexes=[['user_id', 'created_on'], ['action', 'created_on']],
    )

    db.commit()
