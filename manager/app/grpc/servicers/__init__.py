"""gRPC Servicers for ArticDBM Manager

Provides gRPC service implementations for WebUI and proxy communication.
"""

from .manager_servicer import ManagerServicer

__all__ = ['ManagerServicer']
