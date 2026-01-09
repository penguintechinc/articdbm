#!/usr/bin/env python3
"""
gRPC Server Launcher for ArticDBM Manager

This script starts the gRPC server separately from the Flask REST API.
"""

import sys
import os
import time
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Add app directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

def main():
    """Start the gRPC server"""
    try:
        logger.info("Starting ArticDBM gRPC Server...")

        # Import the gRPC server
        from grpc.server import GRPCServer

        # Create and start server
        server = GRPCServer(host='0.0.0.0', port=50051)
        logger.info("gRPC Server created")

        # Start the server (this blocks)
        server.start()
        logger.info("gRPC Server started successfully on port 50051")

        # Keep the server running
        while True:
            time.sleep(3600)  # Sleep for 1 hour at a time

    except Exception as e:
        logger.error(f"Failed to start gRPC server: {e}", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
