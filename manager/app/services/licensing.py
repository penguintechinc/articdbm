"""License management service for ArticDBM.

Provides license validation, feature checking, and free tier enforcement
with resource counting and periodic validation.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from pydal import DAL

from app.integrations.license_client import (
    LicenseClient,
    get_resource_limit,
    is_feature_enabled,
)

logger = logging.getLogger(__name__)


class LicenseService:
    """Service for managing license validation and feature enforcement."""

    def __init__(self, license_client: LicenseClient, db: DAL):
        """Initialize LicenseService.

        Args:
            license_client: LicenseClient instance for server communication
            db: PyDAL database instance
        """
        self.license_client = license_client
        self.db = db
        self._current_license_cache: Optional[Dict[str, Any]] = None
        self._cache_timestamp: Optional[datetime] = None
        self._cache_ttl = timedelta(minutes=5)

    async def get_current_license(self) -> Dict[str, Any]:
        """Get current license information from database or cache.

        Returns cached license info if available and recent,
        otherwise validates with server and updates database.

        Returns:
            Dictionary containing:
                - license_key (str): The license key
                - tier (str): License tier (free, professional, enterprise)
                - features (list): Enabled features
                - resource_limit (int): Max resources allowed
                - resource_count (int): Current resource count
                - is_active (bool): Whether license is active
                - last_validated (str): ISO format timestamp
                - expires_at (str, optional): Expiration date
        """
        # Check in-memory cache
        if self._is_cache_fresh():
            return self._current_license_cache

        # Check database for active license
        license_row = self.db(self.db.license_info.is_active == True).select(
            limitby=(0, 1)
        ).first()

        if not license_row:
            # No active license, return free tier
            return {
                "license_key": None,
                "tier": "free",
                "features": [],
                "resource_limit": 3,
                "resource_count": 0,
                "is_active": False,
                "last_validated": datetime.utcnow().isoformat(),
            }

        # Validate with server
        validation = await self.license_client.validate_license(license_row.license_key)

        # Update database
        if validation.get("valid"):
            resource_limit = get_resource_limit(validation.get("tier", "free"))
            self.db(self.db.license_info.id == license_row.id).update(
                tier=validation.get("tier", "free"),
                features=validation.get("features", []),
                resource_limit=resource_limit,
                last_validated=datetime.utcnow(),
                next_validation=datetime.utcnow() + timedelta(hours=1),
                validation_failures=0,
            )
            self.db.commit()

            license_data = {
                "license_key": license_row.license_key,
                "tier": validation.get("tier", "free"),
                "features": validation.get("features", []),
                "resource_limit": resource_limit,
                "is_active": True,
                "last_validated": datetime.utcnow().isoformat(),
            }
            if "expires_at" in validation:
                license_data["expires_at"] = validation["expires_at"]

            self._update_cache(license_data)
            return license_data
        else:
            # Validation failed, increment failure counter
            new_failures = license_row.validation_failures + 1
            self.db(self.db.license_info.id == license_row.id).update(
                validation_failures=new_failures,
                next_validation=datetime.utcnow() + timedelta(minutes=15),
            )
            self.db.commit()

            # Deactivate after 3 consecutive failures
            if new_failures >= 3:
                self.db(self.db.license_info.id == license_row.id).update(
                    is_active=False
                )
                self.db.commit()
                logger.warning(
                    f"License {license_row.license_key} deactivated after "
                    f"validation failures"
                )

            # Return last known good state or free tier
            license_data = {
                "license_key": license_row.license_key,
                "tier": license_row.tier,
                "features": license_row.features,
                "resource_limit": license_row.resource_limit,
                "resource_count": license_row.resource_count,
                "is_active": False,
                "last_validated": license_row.last_validated.isoformat()
                if license_row.last_validated
                else None,
            }
            self._update_cache(license_data)
            return license_data

    async def activate_license(self, license_key: str) -> Dict[str, Any]:
        """Activate a new license key.

        Validates with license server, stores in database, and returns
        license information. Deactivates any existing license.

        Args:
            license_key: License key to activate

        Returns:
            Dictionary with license information or error details

        Raises:
            ValueError: If license is invalid or server unreachable
        """
        # Validate with server
        validation = await self.license_client.validate_license(license_key)

        if not validation.get("valid"):
            logger.warning(f"Failed to validate license key: {license_key}")
            raise ValueError(f"Invalid license key: {license_key}")

        # Deactivate existing licenses
        self.db(self.db.license_info.is_active == True).update(is_active=False)
        self.db.commit()

        # Get resource limit for tier
        tier = validation.get("tier", "free")
        resource_limit = get_resource_limit(tier)

        # Store new license
        license_row = self.db.license_info.insert(
            license_key=license_key,
            tier=tier,
            features=validation.get("features", []),
            resource_limit=resource_limit,
            resource_count=0,
            is_active=True,
            last_validated=datetime.utcnow(),
            next_validation=datetime.utcnow() + timedelta(hours=1),
            validation_failures=0,
        )
        self.db.commit()

        logger.info(f"License activated: {license_key} (tier: {tier})")

        license_data = {
            "license_key": license_key,
            "tier": tier,
            "features": validation.get("features", []),
            "resource_limit": resource_limit,
            "resource_count": 0,
            "is_active": True,
            "last_validated": datetime.utcnow().isoformat(),
        }
        if "expires_at" in validation:
            license_data["expires_at"] = validation["expires_at"]

        self._update_cache(license_data)
        return license_data

    async def deactivate_license(self) -> bool:
        """Deactivate current license and revert to free tier.

        Returns:
            True if successfully deactivated, False if no active license
        """
        license_row = self.db(self.db.license_info.is_active == True).select(
            limitby=(0, 1)
        ).first()

        if not license_row:
            logger.info("No active license to deactivate")
            return False

        self.db(self.db.license_info.id == license_row.id).update(is_active=False)
        self.db.commit()

        self._current_license_cache = None
        self._cache_timestamp = None

        logger.info(f"License deactivated: {license_row.license_key}")
        return True

    async def check_resource_limit(self) -> Tuple[bool, int, int]:
        """Check if new resource can be created within license limits.

        Returns:
            Tuple of (can_create, current_count, limit)
                - can_create: True if current count is below limit
                - current_count: Number of active resources
                - limit: Maximum resources allowed by license
        """
        license_info = await self.get_current_license()
        limit = license_info.get("resource_limit", 3)

        # Count active resources
        current_count = self.db(self.db.resources.status != "deleted").count()

        # Update resource count in license info
        if license_info.get("license_key"):
            self.db(self.db.license_info.license_key == license_info["license_key"]).update(
                resource_count=current_count
            )
            self.db.commit()

        # Check if limit is exceeded (enterprise tier has -1 for unlimited)
        can_create = current_count < limit if limit > 0 else True

        return (can_create, current_count, limit)

    async def is_feature_enabled(self, feature: str) -> bool:
        """Check if a specific feature is enabled in current license.

        Args:
            feature: Feature name to check

        Returns:
            True if feature is enabled, False otherwise
        """
        license_info = await self.get_current_license()
        features = license_info.get("features", [])

        return is_feature_enabled(features, feature)

    async def validate_periodically(self) -> None:
        """Validate license periodically (called by scheduler).

        Revalidates license with server once per hour,
        updating database with latest information.
        """
        license_row = self.db(self.db.license_info.is_active == True).select(
            limitby=(0, 1)
        ).first()

        if not license_row:
            logger.debug("No active license to validate")
            return

        # Check if validation is due
        if license_row.next_validation and license_row.next_validation > datetime.utcnow():
            logger.debug(
                f"License validation not due until {license_row.next_validation}"
            )
            return

        logger.info(f"Running periodic license validation for {license_row.license_key}")

        try:
            validation = await self.license_client.validate_license(
                license_row.license_key
            )

            if validation.get("valid"):
                tier = validation.get("tier", "free")
                resource_limit = get_resource_limit(tier)

                self.db(self.db.license_info.id == license_row.id).update(
                    tier=tier,
                    features=validation.get("features", []),
                    resource_limit=resource_limit,
                    last_validated=datetime.utcnow(),
                    next_validation=datetime.utcnow() + timedelta(hours=1),
                    validation_failures=0,
                )
                self.db.commit()

                logger.info(f"License validation successful: {license_row.license_key}")
                self._current_license_cache = None
                self._cache_timestamp = None
            else:
                new_failures = license_row.validation_failures + 1
                self.db(self.db.license_info.id == license_row.id).update(
                    validation_failures=new_failures,
                    next_validation=datetime.utcnow() + timedelta(minutes=15),
                )
                self.db.commit()

                # Deactivate after 3 consecutive failures
                if new_failures >= 3:
                    self.db(self.db.license_info.id == license_row.id).update(
                        is_active=False
                    )
                    self.db.commit()
                    logger.warning(
                        f"License deactivated after {new_failures} validation failures"
                    )

        except Exception as e:
            logger.error(f"Error during periodic license validation: {e}")

    async def get_usage_stats(self) -> Dict[str, Any]:
        """Get current usage statistics and limits.

        Returns:
            Dictionary with:
                - tier (str): Current license tier
                - resource_count (int): Number of active resources
                - resource_limit (int): Maximum resources allowed
                - features (list): Enabled features
                - is_active (bool): Whether license is active
                - last_validated (str): Last validation timestamp
                - next_validation (str): Next scheduled validation
        """
        license_info = await self.get_current_license()
        license_row = self.db(self.db.license_info.license_key == license_info.get("license_key")).select(
            limitby=(0, 1)
        ).first()

        if not license_row:
            # Free tier default
            resource_count = self.db(self.db.resources.status != "deleted").count()
            return {
                "tier": "free",
                "resource_count": resource_count,
                "resource_limit": 3,
                "features": [],
                "is_active": False,
                "last_validated": None,
                "next_validation": None,
            }

        # Count active resources
        resource_count = self.db(self.db.resources.status != "deleted").count()

        return {
            "tier": license_row.tier,
            "resource_count": resource_count,
            "resource_limit": license_row.resource_limit,
            "features": license_row.features,
            "is_active": license_row.is_active,
            "last_validated": license_row.last_validated.isoformat()
            if license_row.last_validated
            else None,
            "next_validation": license_row.next_validation.isoformat()
            if license_row.next_validation
            else None,
        }

    def _is_cache_fresh(self) -> bool:
        """Check if in-memory cache is still fresh.

        Returns:
            True if cache exists and hasn't expired, False otherwise
        """
        if not self._current_license_cache or not self._cache_timestamp:
            return False
        return datetime.utcnow() < self._cache_timestamp + self._cache_ttl

    def _update_cache(self, license_data: Dict[str, Any]) -> None:
        """Update in-memory license cache.

        Args:
            license_data: License data to cache
        """
        self._current_license_cache = license_data
        self._cache_timestamp = datetime.utcnow()
        logger.debug("License cache updated")
