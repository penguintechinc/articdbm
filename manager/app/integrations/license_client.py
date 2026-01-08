"""
PenguinTech License Server client for ArticDBM.

Handles license validation, feature checking, and usage reporting with
graceful fallback to cached license information on network errors.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)


class LicenseClient:
    """Client for interacting with PenguinTech License Server."""

    def __init__(
        self,
        server_url: str = "https://license.penguintech.io",
        product_name: str = "articdbm",
    ):
        """Initialize LicenseClient.

        Args:
            server_url: Base URL of license server
            product_name: Product identifier for license server
        """
        self.server_url = server_url
        self.product_name = product_name
        self._cache: Dict[str, Any] = {}
        self._cache_expiry: Optional[datetime] = None
        self._cache_ttl = timedelta(hours=24)

    async def validate_license(self, license_key: str) -> Dict[str, Any]:
        """Validate license with PenguinTech License Server.

        Args:
            license_key: License key to validate

        Returns:
            Dictionary with:
                - valid (bool): Whether license is valid
                - tier (str): License tier (free, professional, enterprise)
                - features (list): List of enabled features
                - expires_at (str, optional): License expiration date

        Falls back to cached info on network errors.
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.server_url}/api/v2/validate"
                payload = {"license_key": license_key, "product": self.product_name}

                async with session.post(
                    url, json=payload, timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._update_cache(data)
                        return data
                    else:
                        logger.warning(
                            f"License validation failed with status {response.status}"
                        )
                        return self._get_cached_license(valid=False)

        except aiohttp.ClientError as e:
            logger.warning(f"Network error during license validation: {e}")
            return self._get_cached_license()
        except asyncio.TimeoutError:
            logger.warning("License validation request timed out")
            return self._get_cached_license()
        except Exception as e:
            logger.error(f"Unexpected error during license validation: {e}")
            return self._get_cached_license(valid=False)

    async def check_features(self, license_key: str) -> Dict[str, Any]:
        """Check available features for license.

        Args:
            license_key: License key to check

        Returns:
            Dictionary with:
                - features (list): List of available features
                - tier (str): License tier
                - limits (dict): Feature limits and usage thresholds
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.server_url}/api/v2/features"
                payload = {"license_key": license_key, "product": self.product_name}

                async with session.post(
                    url, json=payload, timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        self._update_cache(data)
                        return data
                    else:
                        logger.warning(
                            f"Feature check failed with status {response.status}"
                        )
                        return self._get_cached_features()

        except aiohttp.ClientError as e:
            logger.warning(f"Network error during feature check: {e}")
            return self._get_cached_features()
        except asyncio.TimeoutError:
            logger.warning("Feature check request timed out")
            return self._get_cached_features()
        except Exception as e:
            logger.error(f"Unexpected error during feature check: {e}")
            return self._get_cached_features()

    async def report_usage(
        self, license_key: str, resource_count: int = 0
    ) -> bool:
        """Report usage statistics to license server.

        Args:
            license_key: License key for usage tracking
            resource_count: Number of resources in use

        Returns:
            True if report was successful, False otherwise
        """
        try:
            async with aiohttp.ClientSession() as session:
                url = f"{self.server_url}/api/v2/keepalive"
                payload = {
                    "license_key": license_key,
                    "product": self.product_name,
                    "resource_count": resource_count,
                    "timestamp": datetime.utcnow().isoformat(),
                }

                async with session.post(
                    url, json=payload, timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        logger.debug("Usage report sent successfully")
                        return True
                    else:
                        logger.warning(
                            f"Usage report failed with status {response.status}"
                        )
                        return False

        except aiohttp.ClientError as e:
            logger.warning(f"Network error during usage report: {e}")
            return False
        except asyncio.TimeoutError:
            logger.warning("Usage report request timed out")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during usage report: {e}")
            return False

    def _update_cache(self, data: Dict[str, Any]) -> None:
        """Update internal cache with license data.

        Args:
            data: License data to cache
        """
        self._cache = data
        self._cache_expiry = datetime.utcnow() + self._cache_ttl
        logger.debug("License cache updated")

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid.

        Returns:
            True if cache exists and hasn't expired, False otherwise
        """
        if not self._cache or not self._cache_expiry:
            return False
        return datetime.utcnow() < self._cache_expiry

    def _get_cached_license(self, valid: bool = True) -> Dict[str, Any]:
        """Get cached license information with fallback defaults.

        Args:
            valid: Whether to return license as valid

        Returns:
            Cached license data or sensible defaults
        """
        if self._is_cache_valid():
            return self._cache

        # Fallback defaults when cache is not available
        return {
            "valid": valid,
            "tier": "free",
            "features": [],
            "cached": True,
        }

    def _get_cached_features(self) -> Dict[str, Any]:
        """Get cached features with fallback defaults.

        Returns:
            Cached features data or sensible defaults
        """
        if self._is_cache_valid() and "features" in self._cache:
            return {
                "features": self._cache.get("features", []),
                "tier": self._cache.get("tier", "free"),
                "limits": self._cache.get("limits", {}),
                "cached": True,
            }

        # Fallback defaults
        return {
            "features": [],
            "tier": "free",
            "limits": {"connections": 3},
            "cached": True,
        }


def get_resource_limit(tier: str) -> int:
    """Get maximum resource limit for license tier.

    Args:
        tier: License tier (free, professional, enterprise)

    Returns:
        Maximum number of resources allowed. -1 indicates unlimited.
    """
    limits = {
        "free": 3,
        "professional": 50,
        "enterprise": -1,
    }
    return limits.get(tier.lower(), 3)


def is_feature_enabled(features: List[str], feature_name: str) -> bool:
    """Check if specific feature is enabled in feature list.

    Args:
        features: List of enabled features
        feature_name: Name of feature to check

    Returns:
        True if feature is in the features list, False otherwise
    """
    if not features or not isinstance(features, list):
        return False
    return feature_name.lower() in [f.lower() for f in features]
