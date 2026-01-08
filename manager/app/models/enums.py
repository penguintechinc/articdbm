"""ArticDBM Enumeration Types"""

from enum import Enum


class ResourceType(Enum):
    """Supported resource types"""
    DATABASE = "database"
    CACHE = "cache"


class EngineType(Enum):
    """Supported database and cache engines"""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    MARIADB = "mariadb"
    MSSQL = "mssql"
    MONGODB = "mongodb"
    REDIS = "redis"
    VALKEY = "valkey"
    MEMCACHED = "memcached"
    DOCUMENTDB = "documentdb"


class ProviderType(Enum):
    """Infrastructure providers"""
    KUBERNETES = "kubernetes"
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"
    VULTR = "vultr"


class CredentialType(Enum):
    """Authentication credential types"""
    PASSWORD = "password"
    IAM_ROLE = "iam_role"
    JWT = "jwt"
    MTLS = "mtls"


class TLSMode(Enum):
    """TLS enforcement modes"""
    REQUIRED = "required"
    OPTIONAL = "optional"
    DISABLED = "disabled"


class ResourceStatus(Enum):
    """Resource provisioning and operational status"""
    PENDING = "pending"
    PROVISIONING = "provisioning"
    AVAILABLE = "available"
    MODIFYING = "modifying"
    DELETING = "deleting"
    DELETED = "deleted"
    FAILED = "failed"


class DeploymentModel(Enum):
    """Deployment model for resources"""
    SHARED = "shared"
    SEPARATE = "separate"


class LicenseTier(Enum):
    """License tier levels"""
    FREE = "free"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class SyncDirection(Enum):
    """Data synchronization direction"""
    PUSH = "push"
    PULL = "pull"
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(Enum):
    """Data synchronization status"""
    PENDING = "pending"
    SYNCED = "synced"
    ERROR = "error"
