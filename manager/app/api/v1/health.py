"""Health check endpoints for ArticDBM."""

from flask import Blueprint, jsonify
from manager.app.utils.api_responses import success_response, error_response
from manager.app.extensions import db, cache
import redis
import os

health_bp = Blueprint('health', __name__, url_prefix='/health')


def check_database_connection() -> bool:
    """
    Check if database connection is available.

    Returns:
        True if database is accessible, False otherwise.
    """
    try:
        db.session.execute('SELECT 1')
        return True
    except Exception:
        return False


def check_redis_connection() -> bool:
    """
    Check if Redis connection is available.

    Returns:
        True if Redis is accessible, False otherwise.
    """
    try:
        # Attempt to use the cache
        cache.set('health_check', 'ok', timeout=1)
        result = cache.get('health_check')
        return result == 'ok'
    except Exception:
        return False


@health_bp.route('', methods=['GET'])
def health_check():
    """
    Basic health check endpoint.

    Returns:
        JSON response with health status.
    """
    data = {
        'service': 'articdbm-manager',
        'status': 'healthy',
    }
    return success_response(data=data, message='Service is healthy')


@health_bp.route('/ready', methods=['GET'])
def readiness_check():
    """
    Readiness check endpoint.

    Verifies that all critical dependencies are available:
    - Database connection
    - Redis connection

    Returns:
        JSON response with readiness status (503 if not ready).
    """
    db_ready = check_database_connection()
    redis_ready = check_redis_connection()

    is_ready = db_ready and redis_ready

    data = {
        'service': 'articdbm-manager',
        'ready': is_ready,
        'dependencies': {
            'database': 'connected' if db_ready else 'disconnected',
            'cache': 'connected' if redis_ready else 'disconnected',
        },
    }

    if is_ready:
        return success_response(data=data, message='Service is ready')
    else:
        return error_response(
            error='Service not ready',
            details=data,
            status_code=503,
        )


@health_bp.route('/live', methods=['GET'])
def liveness_check():
    """
    Liveness check endpoint.

    Returns:
        JSON response with liveness status (always 200 if service is running).
    """
    data = {
        'service': 'articdbm-manager',
        'alive': True,
    }
    return success_response(data=data, message='Service is alive')
