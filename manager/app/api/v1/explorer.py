"""Database Explorer REST API endpoints."""

import logging
from functools import wraps

from flask import Blueprint, jsonify, request
from flask_security import login_required, current_user

from app.api.errors import ForbiddenError, ValidationError
from app.services.explorer import ExplorerService

logger = logging.getLogger(__name__)

explorer_bp = Blueprint('explorer', __name__, url_prefix='/explorer')


def require_explorer_permission(required_permission: str):
    """Decorator to check explorer permission."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.has_permission(required_permission):
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def init_explorer_service(db):
    """Initialize explorer service with database instance."""
    global explorer_service
    explorer_service = ExplorerService(db)


@explorer_bp.route('/clusters', methods=['GET'])
@login_required
@require_explorer_permission('explorer:view:org')
def get_clusters():
    """
    Get list of accessible clusters.

    Returns:
        JSON array of cluster objects with id, name, description, provider_id
    """
    try:
        clusters = explorer_service.get_accessible_clusters()
        return jsonify({
            'clusters': clusters,
            'total': len(clusters),
        })
    except Exception as e:
        logger.error(f"Error getting clusters: {e}")
        return jsonify({'error': str(e)}), 500


@explorer_bp.route('/clusters/<int:cluster_id>/dbs', methods=['GET'])
@login_required
@require_explorer_permission('explorer:view:org')
def get_databases(cluster_id: int):
    """
    Get databases in a cluster.

    Args:
        cluster_id: Cluster ID

    Returns:
        JSON array of database names
    """
    try:
        databases = explorer_service.get_cluster_databases(cluster_id)
        return jsonify({
            'cluster_id': cluster_id,
            'databases': databases,
            'total': len(databases),
        })
    except Exception as e:
        logger.error(f"Error getting databases: {e}")
        return jsonify({'error': str(e)}), 500


@explorer_bp.route('/query', methods=['GET'])
@login_required
@require_explorer_permission('explorer:view:org')
def query_table():
    """
    Execute safe SELECT query on a table.

    Query Parameters:
        resource_id (int, required): Resource/cluster ID
        table (str, required): Table name
        page (int, optional): Page number (default 1)
        per_page (int, optional): Records per page (default 50, max 100)
        orderby (str, optional): Column to order by

    Returns:
        JSON with table data, columns, and metadata
    """
    try:
        # Get parameters
        resource_id = request.args.get('resource_id', type=int)
        table_name = request.args.get('table', type=str)
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        orderby = request.args.get('orderby', type=str)

        # Validate required parameters
        if not resource_id:
            return jsonify({'error': 'resource_id is required'}), 400
        if not table_name:
            return jsonify({'error': 'table is required'}), 400

        # Execute query
        result = explorer_service.execute_safe_query(
            resource_id=resource_id,
            table_name=table_name,
            page=page,
            per_page=per_page,
            orderby=orderby,
        )

        return jsonify(result)

    except ForbiddenError as e:
        return jsonify({'error': str(e)}), 403
    except ValidationError as e:
        return jsonify({'error': str(e)}), 422
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        return jsonify({'error': str(e)}), 500


@explorer_bp.route('/audit-logs', methods=['GET'])
@login_required
@require_explorer_permission('explorer:admin:audit_logs')
def get_audit_logs():
    """
    Get explorer audit logs (admin only).

    Query Parameters:
        limit (int, optional): Number of logs to return (default 100, max 1000)

    Returns:
        JSON array of audit log entries
    """
    try:
        limit = request.args.get('limit', 100, type=int)

        # Cap limit at 1000
        if limit > 1000:
            limit = 1000

        logs = explorer_service.get_audit_logs(limit=limit)

        return jsonify({
            'logs': logs,
            'total': len(logs),
        })

    except ForbiddenError as e:
        return jsonify({'error': str(e)}), 403
    except Exception as e:
        logger.error(f"Error getting audit logs: {e}")
        return jsonify({'error': str(e)}), 500


@explorer_bp.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({'status': 'ok'}), 200
