"""
Password credential generation and management service.

Provides secure password credential generation, rotation, and revocation
with support for multiple database engines and connection string builders.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from app.models.enums import EngineType
from app.utils.security import generate_secure_password, generate_username

logger = logging.getLogger(__name__)


class PasswordCredentialService:
    """
    Service for managing password-based credentials.

    Handles generation, rotation, and revocation of database credentials
    with engine-specific connection string building.
    """

    def __init__(self):
        """Initialize the password credential service."""
        self.engine_builders = {
            EngineType.POSTGRESQL.value: self._build_postgresql_connection_string,
            EngineType.MYSQL.value: self._build_mysql_connection_string,
            EngineType.MARIADB.value: self._build_mysql_connection_string,
            EngineType.REDIS.value: self._build_redis_connection_string,
            EngineType.MONGODB.value: self._build_mongodb_connection_string,
        }

    def generate_credential(
        self,
        resource: Dict[str, Any],
        application: Optional[Dict[str, Any]] = None,
        permissions: Optional[list[str]] = None,
        expires_at: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Generate a new password credential for a resource.

        Args:
            resource: Resource dict with 'engine', 'endpoint', 'port', 'database_name', etc.
            application: Optional application dict for context
            permissions: List of permissions (default: ['read'])
            expires_at: Optional expiration datetime

        Returns:
            Dictionary containing:
            - username: Generated secure username
            - password: Generated secure password
            - connection_string: Engine-specific connection string

        Raises:
            ValueError: If resource engine is not supported or resource data is invalid
            KeyError: If required resource fields are missing
        """
        if permissions is None:
            permissions = ["read"]

        # Validate resource has required fields
        if not resource.get("engine"):
            raise KeyError("Resource must have 'engine' field")
        if not resource.get("endpoint"):
            raise KeyError("Resource must have 'endpoint' field")
        if not resource.get("port"):
            raise KeyError("Resource must have 'port' field")

        engine = resource.get("engine")
        app_name = application.get("name", "app") if application else "app"

        # Generate username with application context
        username = generate_username(prefix=f"{app_name}_cred", length=12)

        # Generate secure password
        password = generate_secure_password(length=32)

        # Build engine-specific connection string
        if engine not in self.engine_builders:
            raise ValueError(f"Unsupported database engine: {engine}")

        builder = self.engine_builders[engine]
        connection_string = builder(resource, username, password)

        return {
            "username": username,
            "password": password,
            "connection_string": connection_string,
        }

    def rotate_credential(
        self,
        credential_id: int,
        resource: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Rotate a credential by generating a new password.

        Args:
            credential_id: ID of credential to rotate
            resource: Resource dict for connection string building

        Returns:
            Dictionary containing:
            - username: Same as original credential
            - password: New secure password
            - connection_string: Updated connection string

        Raises:
            ValueError: If resource engine is not supported
        """
        logger.info(f"Rotating credential {credential_id}")

        # Validate resource engine is supported
        engine = resource.get("engine")
        if engine not in self.engine_builders:
            raise ValueError(f"Unsupported database engine: {engine}")

        # For rotation, we assume username stays the same
        # This is a simplification - in practice, you'd retrieve the existing username
        # from the database using credential_id
        username = "placeholder_username"  # Should be fetched from DB in real implementation
        password = generate_secure_password(length=32)

        builder = self.engine_builders[engine]
        connection_string = builder(resource, username, password)

        return {
            "username": username,
            "password": password,
            "connection_string": connection_string,
        }

    def revoke_credential(self, credential_id: int) -> bool:
        """
        Revoke a credential by marking it as inactive.

        Args:
            credential_id: ID of credential to revoke

        Returns:
            True if revocation was successful, False otherwise

        Note:
            In a real implementation, this would:
            1. Update the credential's is_active flag to False
            2. Log the revocation
            3. Notify connected systems
        """
        logger.info(f"Revoking credential {credential_id}")
        # In actual implementation, this would update the database
        # and potentially revoke database user access
        return True

    @staticmethod
    def _build_postgresql_connection_string(
        resource: Dict[str, Any],
        username: str,
        password: str,
    ) -> str:
        """
        Build PostgreSQL connection string.

        Format: postgresql://user:pass@host:port/dbname

        Args:
            resource: Resource configuration dict
            username: Database username
            password: Database password

        Returns:
            PostgreSQL connection string
        """
        host = resource.get("endpoint", "localhost")
        port = resource.get("port", 5432)
        dbname = resource.get("database_name", "postgres")

        # URL-encode password to handle special characters
        from urllib.parse import quote_plus

        encoded_password = quote_plus(password)

        return f"postgresql://{username}:{encoded_password}@{host}:{port}/{dbname}"

    @staticmethod
    def _build_mysql_connection_string(
        resource: Dict[str, Any],
        username: str,
        password: str,
    ) -> str:
        """
        Build MySQL/MariaDB connection string.

        Format: mysql://user:pass@host:port/dbname

        Args:
            resource: Resource configuration dict
            username: Database username
            password: Database password

        Returns:
            MySQL connection string
        """
        host = resource.get("endpoint", "localhost")
        port = resource.get("port", 3306)
        dbname = resource.get("database_name", "mysql")

        # URL-encode password to handle special characters
        from urllib.parse import quote_plus

        encoded_password = quote_plus(password)

        return f"mysql://{username}:{encoded_password}@{host}:{port}/{dbname}"

    @staticmethod
    def _build_redis_connection_string(
        resource: Dict[str, Any],
        username: str,
        password: str,
    ) -> str:
        """
        Build Redis connection string.

        Format: redis://:pass@host:port
        Note: Redis username is optional, typically only password is used

        Args:
            resource: Resource configuration dict
            username: Username (optional for Redis)
            password: Redis password

        Returns:
            Redis connection string
        """
        host = resource.get("endpoint", "localhost")
        port = resource.get("port", 6379)
        db = resource.get("database_name", "0")

        # URL-encode password to handle special characters
        from urllib.parse import quote_plus

        encoded_password = quote_plus(password)

        # Redis format with optional username (Redis 6.0+)
        if username:
            return f"redis://{username}:{encoded_password}@{host}:{port}/{db}"
        return f"redis://:{encoded_password}@{host}:{port}/{db}"

    @staticmethod
    def _build_mongodb_connection_string(
        resource: Dict[str, Any],
        username: str,
        password: str,
    ) -> str:
        """
        Build MongoDB connection string.

        Format: mongodb://user:pass@host:port/dbname

        Args:
            resource: Resource configuration dict
            username: Database username
            password: Database password

        Returns:
            MongoDB connection string
        """
        host = resource.get("endpoint", "localhost")
        port = resource.get("port", 27017)
        dbname = resource.get("database_name", "admin")

        # URL-encode password to handle special characters
        from urllib.parse import quote_plus

        encoded_password = quote_plus(password)

        return f"mongodb://{username}:{encoded_password}@{host}:{port}/{dbname}"
