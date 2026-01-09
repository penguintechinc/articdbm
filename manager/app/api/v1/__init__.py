"""ArticDBM REST API v1 endpoints."""

from flask import Blueprint
from app.api.v1.health import health_bp
from app.api.v1.auth import auth_bp
from app.api.v1.credentials import credentials_bp
from app.api.v1.resources import resources_bp
from app.api.v1.applications import applications_bp
from app.api.v1.providers import providers_bp
from app.api.v1.tags import tags_bp
from app.api.v1.license import license_bp
from app.api.v1.marchproxy import marchproxy_bp


def register_blueprints(app):
    """
    Register all v1 API blueprints with the Flask application.

    Args:
        app: Flask application instance
    """
    # Create v1 API blueprint
    api_v1_bp = Blueprint('api_v1', __name__, url_prefix='/api/v1')

    # Register sub-blueprints
    api_v1_bp.register_blueprint(health_bp)
    api_v1_bp.register_blueprint(auth_bp)
    api_v1_bp.register_blueprint(credentials_bp)
    api_v1_bp.register_blueprint(resources_bp)
    api_v1_bp.register_blueprint(applications_bp)
    api_v1_bp.register_blueprint(providers_bp)
    api_v1_bp.register_blueprint(tags_bp)
    api_v1_bp.register_blueprint(license_bp)
    api_v1_bp.register_blueprint(marchproxy_bp)

    # Register main blueprint with app
    app.register_blueprint(api_v1_bp)

    return api_v1_bp


__all__ = [
    'register_blueprints',
    'health_bp',
    'auth_bp',
    'credentials_bp',
    'resources_bp',
    'applications_bp',
    'providers_bp',
    'tags_bp',
    'license_bp',
    'marchproxy_bp',
]
