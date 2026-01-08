"""ArticDBM REST API v1 endpoints."""

from flask import Blueprint
from manager.app.api.v1.health import health_bp
from manager.app.api.v1.credentials import credentials_bp

# Create v1 API blueprint
api_v1_bp = Blueprint('api_v1', __name__)

# Register sub-blueprints
api_v1_bp.register_blueprint(health_bp)
api_v1_bp.register_blueprint(credentials_bp)

__all__ = ['api_v1_bp']
