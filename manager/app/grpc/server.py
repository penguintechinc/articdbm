"""
gRPC server setup for ArticDBM manager.

Provides gRPC server functionality for communication between manager and proxy services.
"""

import logging
import os
import time
from concurrent import futures
from typing import Any, Optional

import grpc
from grpc_reflection.v1alpha import reflection

logger = logging.getLogger(__name__)


class GRPCServer:
    """gRPC server implementation for ArticDBM manager."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 50051,
        max_workers: int = 10,
        max_message_length: int = 100 * 1024 * 1024,  # 100MB
    ):
        """
        Initialize gRPC server.

        Args:
            host: Host address to bind to
            port: Port number to bind to
            max_workers: Maximum number of worker threads
            max_message_length: Maximum message size in bytes
        """
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.max_message_length = max_message_length

        # gRPC server options
        self.options = [
            ("grpc.max_send_message_length", max_message_length),
            ("grpc.max_receive_message_length", max_message_length),
            ("grpc.keepalive_time_ms", 10000),
            ("grpc.keepalive_timeout_ms", 5000),
            ("grpc.keepalive_permit_without_calls", True),
            ("grpc.http2.max_pings_without_data", 0),
            ("grpc.http2.min_time_between_pings_ms", 10000),
            ("grpc.http2.min_ping_interval_without_data_ms", 5000),
        ]

        self.server: Optional[grpc.Server] = None
        self.servicers = []
        self.service_names = []

    def add_servicer(self, servicer: Any) -> None:
        """
        Add a service implementation to the server.

        Args:
            servicer: Service implementation instance
        """
        self.servicers.append(servicer)

    def _setup_tls(self) -> Optional[grpc.ServerCredentials]:
        """
        Setup TLS credentials if configured.

        Returns:
            ServerCredentials if TLS is configured, None otherwise
        """
        tls_enabled = os.getenv("GRPC_TLS_ENABLED", "false").lower() == "true"
        if not tls_enabled:
            return None

        cert_file = os.getenv("GRPC_TLS_CERT_FILE")
        key_file = os.getenv("GRPC_TLS_KEY_FILE")
        ca_file = os.getenv("GRPC_TLS_CA_FILE")

        if not cert_file or not key_file:
            logger.warning(
                "GRPC_TLS_ENABLED is true but cert/key files not configured"
            )
            return None

        try:
            with open(key_file, "rb") as f:
                private_key = f.read()
            with open(cert_file, "rb") as f:
                certificate_chain = f.read()

            root_certificates = None
            if ca_file and os.path.exists(ca_file):
                with open(ca_file, "rb") as f:
                    root_certificates = f.read()

            credentials = grpc.ssl_server_credentials(
                [(private_key, certificate_chain)],
                root_certificates=root_certificates,
                require_client_auth=root_certificates is not None,
            )

            logger.info("TLS configured for gRPC server")
            return credentials

        except Exception as e:
            logger.error(f"Failed to setup TLS credentials: {e}")
            return None

    def start(self) -> None:
        """Start the gRPC server with reflection enabled."""
        if self.server is not None:
            logger.warning("gRPC server already started")
            return

        # Create server with thread pool
        self.server = grpc.server(
            futures.ThreadPoolExecutor(max_workers=self.max_workers),
            options=self.options,
        )

        # Add all registered servicers
        for servicer in self.servicers:
            # Each servicer should have an add_to_server method
            if hasattr(servicer, "add_to_server"):
                servicer.add_to_server(self.server)
                if hasattr(servicer, "SERVICE_NAME"):
                    self.service_names.append(servicer.SERVICE_NAME)
            else:
                logger.warning(
                    f"Servicer {servicer.__class__.__name__} "
                    f"does not have add_to_server method"
                )

        # Enable reflection for debugging
        service_names_for_reflection = self.service_names + [
            reflection.SERVICE_NAME
        ]
        reflection.enable_server_reflection(
            service_names_for_reflection, self.server
        )
        logger.info("gRPC reflection enabled")

        # Setup TLS if configured
        credentials = self._setup_tls()
        address = f"{self.host}:{self.port}"

        if credentials:
            self.server.add_secure_port(address, credentials)
            logger.info(f"gRPC server listening on {address} (TLS enabled)")
        else:
            self.server.add_insecure_port(address)
            logger.info(f"gRPC server listening on {address} (insecure)")

        # Start the server
        self.server.start()
        logger.info(
            f"gRPC server started with {len(self.servicers)} service(s)"
        )

    def stop(self, grace: int = 5) -> None:
        """
        Stop the gRPC server gracefully.

        Args:
            grace: Grace period in seconds for ongoing RPCs to complete
        """
        if self.server is None:
            logger.warning("gRPC server not running")
            return

        logger.info(f"Stopping gRPC server (grace period: {grace}s)")
        self.server.stop(grace)
        self.server = None
        logger.info("gRPC server stopped")

    def wait_for_termination(self, timeout: Optional[float] = None) -> None:
        """
        Block until the server is terminated.

        Args:
            timeout: Maximum time to wait in seconds
        """
        if self.server is None:
            return

        try:
            self.server.wait_for_termination(timeout=timeout)
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
            self.stop()


def create_grpc_server(app: Any) -> GRPCServer:
    """
    Create and configure gRPC server with Flask app context.

    Args:
        app: Flask application instance

    Returns:
        Configured GRPCServer instance
    """
    # Get configuration from Flask app or environment
    host = app.config.get("GRPC_HOST", os.getenv("GRPC_HOST", "0.0.0.0"))
    port = int(app.config.get("GRPC_PORT", os.getenv("GRPC_PORT", "50051")))
    max_workers = int(
        app.config.get("GRPC_MAX_WORKERS", os.getenv("GRPC_MAX_WORKERS", "10"))
    )
    max_message_length = int(
        app.config.get(
            "GRPC_MAX_MESSAGE_LENGTH",
            os.getenv("GRPC_MAX_MESSAGE_LENGTH", str(100 * 1024 * 1024)),
        )
    )

    # Create server instance
    server = GRPCServer(
        host=host,
        port=port,
        max_workers=max_workers,
        max_message_length=max_message_length,
    )

    # Import and add servicers
    # Note: Servicers should be imported and added here
    # Example:
    # from app.grpc.servicers.config_servicer import ConfigServicer
    # server.add_servicer(ConfigServicer(app))

    logger.info(
        f"gRPC server created: {host}:{port} "
        f"(workers={max_workers}, max_msg={max_message_length})"
    )

    return server
