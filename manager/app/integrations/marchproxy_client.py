"""
MarchProxy gRPC client for configuring database routes.

Handles communication with MarchProxy DBLB module for route management,
rate limiting, metrics collection, and health monitoring.
"""

import asyncio
import logging
from typing import Any, Dict, List, Optional, Tuple

import grpc

logger = logging.getLogger(__name__)


# Placeholder imports - will be generated from proto files
# from app.grpc.generated import module_service_pb2, module_service_pb2_grpc


class MarchProxyClient:
    """Client for interacting with MarchProxy gRPC ModuleService."""

    def __init__(
        self,
        grpc_address: str = "localhost:50051",
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """Initialize MarchProxyClient.

        Args:
            grpc_address: MarchProxy gRPC server address (host:port)
            max_retries: Maximum number of connection retry attempts
            retry_delay: Delay in seconds between retry attempts
        """
        self.grpc_address = grpc_address
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self._channel: Optional[grpc.aio.Channel] = None
        self._stub = None
        self._connected = False

    async def connect(self) -> bool:
        """Establish gRPC connection to MarchProxy.

        Returns:
            True if connection successful, False otherwise
        """
        for attempt in range(self.max_retries):
            try:
                self._channel = grpc.aio.insecure_channel(self.grpc_address)
                # TODO: Uncomment when proto files are generated
                # self._stub = module_service_pb2_grpc.ModuleServiceStub(
                #     self._channel
                # )

                # Test connection with health check
                await self._channel.channel_ready()
                self._connected = True
                logger.info(f"Connected to MarchProxy at {self.grpc_address}")
                return True

            except grpc.RpcError as e:
                logger.warning(
                    f"Connection attempt {attempt + 1}/{self.max_retries} failed: {e}"
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
            except Exception as e:
                logger.error(f"Unexpected error during connection: {e}")
                return False

        logger.error(f"Failed to connect to MarchProxy after {self.max_retries} attempts")
        return False

    async def disconnect(self) -> None:
        """Close gRPC connection to MarchProxy."""
        if self._channel:
            await self._channel.close()
            self._channel = None
            self._stub = None
            self._connected = False
            logger.info("Disconnected from MarchProxy")

    async def create_route(self, route_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new database route in MarchProxy.

        Args:
            route_config: Route configuration dictionary with fields:
                - name (str): Unique route identifier
                - protocol (str): Database protocol (mysql/postgresql/redis)
                - listen_port (int): Port for MarchProxy to listen on
                - backend_host (str): Backend database host
                - backend_port (int): Backend database port
                - max_connections (int): Maximum concurrent connections
                - enable_auth (bool): Enable authentication
                - enable_ssl (bool): Enable SSL/TLS
                - health_check_sql (str): SQL query for health checks

        Returns:
            Dictionary with route creation result:
                - success (bool): Whether creation succeeded
                - route_name (str): Name of created route
                - error (str, optional): Error message if failed
        """
        if not self._connected:
            logger.error("Not connected to MarchProxy")
            return {"success": False, "error": "Not connected to MarchProxy"}

        try:
            # TODO: Implement actual gRPC call when proto is available
            # request = module_service_pb2.CreateRouteRequest(
            #     name=route_config.get("name"),
            #     protocol=route_config.get("protocol"),
            #     listen_port=route_config.get("listen_port"),
            #     backend_host=route_config.get("backend_host"),
            #     backend_port=route_config.get("backend_port"),
            #     max_connections=route_config.get("max_connections", 100),
            #     enable_auth=route_config.get("enable_auth", False),
            #     enable_ssl=route_config.get("enable_ssl", False),
            #     health_check_sql=route_config.get("health_check_sql", "SELECT 1"),
            # )
            # response = await self._stub.CreateRoute(request)

            # Placeholder response
            logger.info(f"Creating route: {route_config.get('name')}")
            return {
                "success": True,
                "route_name": route_config.get("name"),
                "message": "Route created successfully (placeholder)",
            }

        except grpc.RpcError as e:
            logger.error(f"gRPC error creating route: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error creating route: {e}")
            return {"success": False, "error": str(e)}

    async def update_route(
        self, route_name: str, updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update existing route configuration.

        Args:
            route_name: Name of route to update
            updates: Dictionary of fields to update

        Returns:
            Dictionary with update result:
                - success (bool): Whether update succeeded
                - route_name (str): Name of updated route
                - error (str, optional): Error message if failed
        """
        if not self._connected:
            logger.error("Not connected to MarchProxy")
            return {"success": False, "error": "Not connected to MarchProxy"}

        try:
            # TODO: Implement actual gRPC call when proto is available
            logger.info(f"Updating route: {route_name} with {updates}")
            return {
                "success": True,
                "route_name": route_name,
                "message": "Route updated successfully (placeholder)",
            }

        except grpc.RpcError as e:
            logger.error(f"gRPC error updating route: {e}")
            return {"success": False, "error": str(e)}
        except Exception as e:
            logger.error(f"Unexpected error updating route: {e}")
            return {"success": False, "error": str(e)}

    async def delete_route(self, route_name: str) -> bool:
        """Delete a route from MarchProxy.

        Args:
            route_name: Name of route to delete

        Returns:
            True if deletion successful, False otherwise
        """
        if not self._connected:
            logger.error("Not connected to MarchProxy")
            return False

        try:
            # TODO: Implement actual gRPC call when proto is available
            logger.info(f"Deleting route: {route_name}")
            return True

        except grpc.RpcError as e:
            logger.error(f"gRPC error deleting route: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error deleting route: {e}")
            return False

    async def get_routes(self) -> List[Dict[str, Any]]:
        """Get all configured routes from MarchProxy.

        Returns:
            List of route configuration dictionaries
        """
        if not self._connected:
            logger.error("Not connected to MarchProxy")
            return []

        try:
            # TODO: Implement actual gRPC call when proto is available
            logger.debug("Fetching routes from MarchProxy")
            return []

        except grpc.RpcError as e:
            logger.error(f"gRPC error fetching routes: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching routes: {e}")
            return []

    async def set_rate_limit(
        self, route_name: str, connection_rate: float, query_rate: float
    ) -> bool:
        """Set rate limits for a route.

        Args:
            route_name: Name of route to configure
            connection_rate: Maximum connections per second
            query_rate: Maximum queries per second

        Returns:
            True if rate limits set successfully, False otherwise
        """
        if not self._connected:
            logger.error("Not connected to MarchProxy")
            return False

        try:
            # TODO: Implement actual gRPC call when proto is available
            logger.info(
                f"Setting rate limits for {route_name}: "
                f"conn={connection_rate}/s, query={query_rate}/s"
            )
            return True

        except grpc.RpcError as e:
            logger.error(f"gRPC error setting rate limits: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error setting rate limits: {e}")
            return False

    async def get_metrics(self, route_name: str) -> Dict[str, Any]:
        """Get metrics for a specific route.

        Args:
            route_name: Name of route to get metrics for

        Returns:
            Dictionary with route metrics:
                - active_connections (int): Current active connections
                - total_queries (int): Total queries processed
                - avg_query_time_ms (float): Average query time
                - errors_total (int): Total errors
                - last_health_check (str): Last health check timestamp
        """
        if not self._connected:
            logger.error("Not connected to MarchProxy")
            return {}

        try:
            # TODO: Implement actual gRPC call when proto is available
            logger.debug(f"Fetching metrics for route: {route_name}")
            return {
                "active_connections": 0,
                "total_queries": 0,
                "avg_query_time_ms": 0.0,
                "errors_total": 0,
                "last_health_check": None,
            }

        except grpc.RpcError as e:
            logger.error(f"gRPC error fetching metrics: {e}")
            return {}
        except Exception as e:
            logger.error(f"Unexpected error fetching metrics: {e}")
            return {}

    async def health_check(self) -> Tuple[bool, str]:
        """Check health of MarchProxy connection.

        Returns:
            Tuple of (healthy: bool, status_message: str)
        """
        if not self._connected or not self._channel:
            return False, "Not connected to MarchProxy"

        try:
            # Check channel state
            state = self._channel.get_state(try_to_connect=False)
            if state == grpc.ChannelConnectivity.READY:
                return True, "MarchProxy connection healthy"
            else:
                return False, f"MarchProxy connection state: {state.name}"

        except Exception as e:
            logger.error(f"Error checking MarchProxy health: {e}")
            return False, str(e)

    @staticmethod
    def build_route_config(
        resource: Dict[str, Any], marchproxy_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Convert ArticDBM resource to MarchProxy route configuration.

        Args:
            resource: ArticDBM resource dictionary with fields:
                - name (str): Resource name
                - db_type (str): Database type (postgres/mysql/redis)
                - host (str): Database host
                - port (int): Database port
                - max_connections (int): Max connections
            marchproxy_config: Additional MarchProxy-specific configuration:
                - listen_port (int): Port for MarchProxy to listen on
                - enable_auth (bool): Enable authentication
                - enable_ssl (bool): Enable SSL/TLS
                - health_check_sql (str): Health check query

        Returns:
            Dictionary formatted for MarchProxy route creation
        """
        # Map ArticDBM db_type to MarchProxy protocol
        protocol_mapping = {
            "postgres": "postgresql",
            "postgresql": "postgresql",
            "mysql": "mysql",
            "mariadb": "mysql",
            "redis": "redis",
        }

        db_type = resource.get("db_type", "postgresql").lower()
        protocol = protocol_mapping.get(db_type, "postgresql")

        # Default health check queries by protocol
        default_health_checks = {
            "postgresql": "SELECT 1",
            "mysql": "SELECT 1",
            "redis": "PING",
        }

        return {
            "name": resource.get("name"),
            "protocol": protocol,
            "listen_port": marchproxy_config.get("listen_port"),
            "backend_host": resource.get("host"),
            "backend_port": resource.get("port"),
            "max_connections": resource.get("max_connections", 100),
            "enable_auth": marchproxy_config.get("enable_auth", False),
            "enable_ssl": marchproxy_config.get("enable_ssl", False),
            "health_check_sql": marchproxy_config.get(
                "health_check_sql", default_health_checks.get(protocol, "SELECT 1")
            ),
        }
