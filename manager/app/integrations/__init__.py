"""
Integration clients for external services.

Includes clients for:
- PenguinTech License Server
- Elder Infrastructure Management System
"""

from .elder_client import ElderClient
from .license_client import LicenseClient

__all__ = ["ElderClient", "LicenseClient"]
