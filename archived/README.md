# Archived Proxy - ArticDBM v1.x

This directory contains the archived v1.x Go-based database proxy implementation.

## Overview

The Go proxy was the original database protocol handler for ArticDBM, providing:
- PostgreSQL and MySQL wire protocol handling
- SQL injection detection
- Connection pooling
- Query routing and load balancing
- Prometheus metrics collection

## Archival Reason

As of ArticDBM v2.0, the database proxy functionality has been integrated with **MarchProxy**, a dedicated high-performance proxy service that provides enhanced capabilities while maintaining backward compatibility.

## What Was Here

- **proxy-v1/**: Original Go 1.23.x proxy implementation
  - Protocol handlers for MySQL and PostgreSQL
  - Security checks and SQL injection detection
  - Connection pooling and lifecycle management
  - Metrics collection

## Migration to MarchProxy

ArticDBM v2.0+ uses MarchProxy for database proxy operations:
- More specialized proxy functionality
- Enhanced performance and feature set
- Simplified deployment and configuration
- Maintained separately as dedicated proxy service

For information on using MarchProxy with ArticDBM v2.0+, see the main documentation.
