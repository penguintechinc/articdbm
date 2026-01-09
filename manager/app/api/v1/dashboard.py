"""Dashboard API endpoints for management portal.

Provides overview statistics, recent activity, and system health metrics.
"""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/api/v1/dashboard",
    description="Dashboard statistics and overview endpoints",
)


@dashboard_bp.route("/stats", methods=["GET"])
@login_required
def get_dashboard_stats() -> Tuple[Dict[str, Any], int]:
    """
    Get dashboard statistics including resource counts, application counts,
    license info, and recent activity.

    Returns:
        JSON response with dashboard statistics
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database not initialized'}), 500

        # Get resource statistics
        total_resources = db(db.resources.status != "deleted").count()
        active_resources = db(
            (db.resources.status == "available") |
            (db.resources.status == "running")
        ).count()

        # Get application statistics
        total_applications = db(db.applications.id > 0).count()

        # Count healthy applications (those with available resources)
        healthy_apps = 0
        apps = db(db.applications.id > 0).select()
        for app in apps:
            app_resources = db(
                (db.resources.application_id == app.id) &
                (db.resources.status == "available")
            ).count()
            if app_resources > 0:
                healthy_apps += 1

        # Get license information
        license_client = current_app.extensions.get("license_client")
        license_info = {
            "tier": "free",
            "resource_limit": 3,
            "current_usage": total_resources,
            "valid": True,
            "expires_at": None
        }

        if license_client:
            try:
                license_status = license_client.validate_license()
                if license_status:
                    license_info["tier"] = license_status.get("tier", "free")
                    license_info["resource_limit"] = license_status.get(
                        "resource_limit", 3
                    )
                    license_info["valid"] = license_status.get("valid", True)
                    license_info["expires_at"] = license_status.get("expires_at")
            except Exception as e:
                logger.warning(f"Failed to fetch license status: {e}")

        # Get recent activity (last 10 audit logs)
        recent_activity = []
        audit_logs = db(db.audit_log.id > 0).select(
            orderby=~db.audit_log.created_at,
            limitby=(0, 10)
        )

        for log in audit_logs:
            activity_entry = {
                "id": log.id,
                "action": log.action,
                "resource_type": log.resource_type,
                "resource_id": log.resource_id,
                "status": log.status,
                "timestamp": log.created_at.isoformat()
                    if hasattr(log.created_at, "isoformat")
                    else str(log.created_at),
                "user_id": log.user_id,
                "ip_address": log.ip_address
            }
            recent_activity.append(activity_entry)

        # Get resource breakdown by type
        resource_types = {}
        for resource_type in ["database", "cache"]:
            count = db(
                (db.resources.resource_type == resource_type) &
                (db.resources.status != "deleted")
            ).count()
            resource_types[resource_type] = count

        # Get resource breakdown by engine
        engines = {}
        for engine in ["postgresql", "mysql", "redis", "valkey", "sqlite"]:
            count = db(
                (db.resources.engine == engine) &
                (db.resources.status != "deleted")
            ).count()
            if count > 0:
                engines[engine] = count

        response_data = {
            "totalResources": total_resources,
            "activeResources": active_resources,
            "totalApplications": total_applications,
            "healthyApps": healthy_apps,
            "licenseInfo": license_info,
            "recentActivity": recent_activity,
            "resourcesByType": resource_types,
            "resourcesByEngine": engines,
            "timestamp": datetime.utcnow().isoformat()
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error fetching dashboard stats: {e}")
        return jsonify({'error': 'Failed to fetch dashboard statistics'}), 500
