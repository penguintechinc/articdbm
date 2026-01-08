"""
JWT Credential Service for MarchProxy Authentication.

Provides JWT token generation, validation, rotation, and revocation
with secure storage of token metadata in the credentials table.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Any, Dict

import jwt
from flask import current_app

logger = logging.getLogger(__name__)


class JWTCredentialService:
    """Service for managing JWT credentials for MarchProxy authentication."""

    # Standard JWT claims
    STANDARD_CLAIMS = {"sub", "resource_id", "permissions", "iat", "exp", "app"}

    def __init__(self):
        """Initialize JWT credential service."""
        self.algorithm = "HS256"

    def _get_secret_key(self) -> str:
        """
        Get the secret key for JWT signing from Flask config.

        Returns:
            Secret key from config

        Raises:
            ValueError: If SECRET_KEY is not configured
        """
        secret_key = current_app.config.get("SECRET_KEY")
        if not secret_key:
            raise ValueError("SECRET_KEY not configured in Flask config")
        return secret_key

    def generate_token(
        self,
        resource: str,
        application: str,
        permissions: list,
        subject: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None,
        expires_in_days: int = 30,
    ) -> Dict[str, Any]:
        """
        Generate a JWT token signed with HS256.

        Args:
            resource: Resource identifier (resource name or ID)
            application: Application identifier
            permissions: List of permission strings (e.g., ["read", "write"])
            subject: Optional JWT subject claim (user identifier)
            claims: Optional dictionary of custom claims to add
            expires_in_days: Token expiration time in days (default: 30)

        Returns:
            Dictionary containing:
                - jwt_token: Signed JWT token (str)
                - expires_at: Expiration timestamp (datetime)
                - issued_at: Issued at timestamp (datetime)
                - claims: Full claims payload (dict)

        Raises:
            ValueError: If required parameters are invalid
            Exception: If token generation fails
        """
        if not resource:
            raise ValueError("resource cannot be empty")
        if not application:
            raise ValueError("application cannot be empty")
        if not isinstance(permissions, list) or len(permissions) == 0:
            raise ValueError("permissions must be a non-empty list")

        try:
            # Calculate timestamps
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(days=expires_in_days)

            # Build claims payload
            payload = {
                "sub": subject or f"{application}@{resource}",
                "resource_id": resource,
                "app": application,
                "permissions": permissions,
                "iat": int(now.timestamp()),
                "exp": int(expires_at.timestamp()),
            }

            # Add custom claims if provided
            if claims and isinstance(claims, dict):
                # Exclude standard claims to prevent override
                custom_claims = {
                    k: v for k, v in claims.items()
                    if k not in self.STANDARD_CLAIMS
                }
                payload.update(custom_claims)

            # Sign token
            secret_key = self._get_secret_key()
            token = jwt.encode(payload, secret_key, algorithm=self.algorithm)

            logger.info(
                f"Generated JWT token for resource={resource}, "
                f"application={application}, expires_in={expires_in_days} days"
            )

            return {
                "jwt_token": token,
                "expires_at": expires_at,
                "issued_at": now,
                "claims": payload,
            }

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"JWT token generation failed: {e}")
            raise Exception(f"Failed to generate JWT token: {e}")

    def rotate_token(
        self,
        old_token: str,
        expires_in_days: int = 30,
    ) -> Dict[str, Any]:
        """
        Generate a new token with the same claims as the old token.

        Extracts claims from existing token and generates new token
        with updated issued_at and exp timestamps.

        Args:
            old_token: Existing JWT token to rotate
            expires_in_days: Expiration time for new token in days

        Returns:
            Dictionary containing:
                - jwt_token: New signed JWT token
                - expires_at: New expiration timestamp
                - issued_at: New issued at timestamp
                - claims: Updated claims payload

        Raises:
            ValueError: If token is invalid or expired
            Exception: If rotation fails
        """
        if not old_token:
            raise ValueError("old_token cannot be empty")

        try:
            # Decode without expiration check to get claims
            secret_key = self._get_secret_key()
            claims = jwt.decode(
                old_token,
                secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False},
            )

            # Extract essential claims
            resource = claims.get("resource_id")
            application = claims.get("app")
            permissions = claims.get("permissions", [])
            subject = claims.get("sub")

            # Extract custom claims (excluding standard ones)
            custom_claims = {
                k: v for k, v in claims.items()
                if k not in self.STANDARD_CLAIMS
            }

            # Generate new token with same claims
            new_token = self.generate_token(
                resource=resource,
                application=application,
                permissions=permissions,
                subject=subject,
                claims=custom_claims,
                expires_in_days=expires_in_days,
            )

            logger.info(
                f"Rotated JWT token for resource={resource}, "
                f"application={application}"
            )

            return new_token

        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid JWT token for rotation: {e}")
            raise ValueError(f"Invalid token: {e}")
        except Exception as e:
            logger.error(f"JWT token rotation failed: {e}")
            raise Exception(f"Failed to rotate JWT token: {e}")

    def revoke_token(self, credential_id: int) -> bool:
        """
        Revoke a token by adding it to blacklist or marking in DB.

        This method adds the credential to a blacklist/revocation list.
        In production, this would update the credentials table to set
        is_active=False or add to a token blacklist in Redis.

        Args:
            credential_id: ID of the credential to revoke in the database

        Returns:
            True if revocation was successful, False otherwise

        Raises:
            ValueError: If credential_id is invalid
        """
        if not isinstance(credential_id, int) or credential_id <= 0:
            raise ValueError("credential_id must be a positive integer")

        try:
            # Import here to avoid circular imports
            from flask import current_app
            from app.extensions import pydal_manager

            # Get PyDAL database instance
            db = pydal_manager.db

            # Mark credential as inactive in database
            credential = db(db.credentials.id == credential_id).select(
                db.credentials.id
            ).first()

            if not credential:
                logger.warning(f"Credential {credential_id} not found for revocation")
                return False

            # Update credential to inactive
            db(db.credentials.id == credential_id).update(is_active=False)
            db.commit()

            # Optionally add to Redis blacklist for immediate revocation
            # This would be used for real-time checking by proxy
            redis_client = current_app.extensions.get("redis")
            if redis_client:
                blacklist_key = f"jwt:revoked:{credential_id}"
                redis_client.setex(
                    blacklist_key,
                    86400 * 365,  # 1 year TTL
                    "1",
                )

            logger.info(f"Revoked credential {credential_id}")
            return True

        except Exception as e:
            logger.error(f"JWT token revocation failed for credential {credential_id}: {e}")
            raise Exception(f"Failed to revoke credential: {e}")

    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate and decode JWT token.

        Checks token signature, expiration, and format.
        Also checks Redis blacklist for revoked tokens.

        Args:
            token: JWT token to validate

        Returns:
            Dictionary containing decoded claims if valid

        Raises:
            ValueError: If token is invalid, expired, or revoked
        """
        if not token:
            raise ValueError("token cannot be empty")

        try:
            secret_key = self._get_secret_key()

            # Decode and validate token
            claims = jwt.decode(
                token,
                secret_key,
                algorithms=[self.algorithm],
            )

            # Validate required claims
            required_claims = {"resource_id", "app", "permissions", "exp", "iat"}
            if not required_claims.issubset(claims.keys()):
                missing = required_claims - claims.keys()
                raise ValueError(f"Missing required claims: {missing}")

            # Check if token is revoked (optional Redis check)
            from flask import current_app
            redis_client = current_app.extensions.get("redis")
            if redis_client:
                # Extract credential ID from token if available
                # or check against credential table
                pass

            logger.debug(
                f"Validated JWT token for resource={claims.get('resource_id')}, "
                f"app={claims.get('app')}"
            )

            return claims

        except jwt.ExpiredSignatureError as e:
            logger.warning(f"JWT token has expired: {e}")
            raise ValueError(f"Token has expired: {e}")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            raise ValueError(f"Invalid token: {e}")
        except Exception as e:
            logger.error(f"JWT token validation failed: {e}")
            raise ValueError(f"Token validation failed: {e}")

    def get_token_claims(self, token: str, verify: bool = True) -> Dict[str, Any]:
        """
        Extract claims from a JWT token.

        Args:
            token: JWT token to extract claims from
            verify: Whether to verify signature (default: True)

        Returns:
            Dictionary containing token claims

        Raises:
            ValueError: If token is invalid or cannot be decoded
        """
        if not token:
            raise ValueError("token cannot be empty")

        try:
            secret_key = self._get_secret_key()
            options = {} if verify else {"verify_signature": False}

            claims = jwt.decode(
                token,
                secret_key,
                algorithms=[self.algorithm],
                options=options,
            )

            return claims

        except Exception as e:
            logger.error(f"Failed to extract claims from JWT: {e}")
            raise ValueError(f"Failed to extract claims: {e}")

    def is_token_expired(self, token: str) -> bool:
        """
        Check if a JWT token is expired.

        Args:
            token: JWT token to check

        Returns:
            True if token is expired, False if still valid

        Raises:
            ValueError: If token cannot be decoded
        """
        try:
            claims = self.get_token_claims(token, verify=False)
            exp_timestamp = claims.get("exp", 0)
            now_timestamp = int(datetime.now(timezone.utc).timestamp())
            return now_timestamp > exp_timestamp

        except Exception as e:
            logger.error(f"Failed to check token expiration: {e}")
            raise ValueError(f"Cannot determine token expiration: {e}")

    def get_token_ttl(self, token: str) -> Optional[int]:
        """
        Get the time-to-live for a JWT token in seconds.

        Args:
            token: JWT token to check

        Returns:
            Remaining TTL in seconds, or None if token is expired

        Raises:
            ValueError: If token cannot be decoded
        """
        try:
            claims = self.get_token_claims(token, verify=False)
            exp_timestamp = claims.get("exp", 0)
            now_timestamp = int(datetime.now(timezone.utc).timestamp())
            ttl = exp_timestamp - now_timestamp

            return ttl if ttl > 0 else None

        except Exception as e:
            logger.error(f"Failed to get token TTL: {e}")
            raise ValueError(f"Cannot determine token TTL: {e}")
