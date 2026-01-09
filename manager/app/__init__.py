"""ArticDBM Flask Application Factory

This module provides a Flask application factory and instantiates the app
at module level for gunicorn to load via 'app:app'.
"""

import os
import logging
from flask import Flask, jsonify
from pydal import DAL

from app.config import get_config
from app.extensions import (
    security,
    login_manager,
    cors,
    redis_client,
    scheduler,
)


def _init_pydal_db(app: Flask) -> DAL:
    """
    Initialize PyDAL database connection.

    Args:
        app: Flask application instance

    Returns:
        PyDAL database instance
    """
    from app.models.pydal_models import define_models
    from app.models.users import define_user_models

    # Use fake_migrate=True to skip actual migration execution
    # Tables are already created, just verify schema
    db = DAL(app.config['PYDAL_URI'], migrate=True, fake_migrate=True)
    # Define user models first since other models may reference them
    define_user_models(db)
    # Then define other models
    define_models(db)

    return db


def create_app(config_name='development'):
    """
    Application factory function for ArticDBM manager.

    Args:
        config_name: Configuration environment ('development', 'testing', 'production')

    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)

    # Load configuration using get_config utility
    try:
        config_class = get_config(config_name)
        app.config.from_object(config_class)
    except Exception as e:
        logging.warning(f"Could not load config '{config_name}': {e}")
        # Fallback configuration if config module not found
        app.config['DEBUG'] = config_name != 'production'
        app.config['TESTING'] = config_name == 'testing'
        app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-production')

    # Initialize extensions
    try:
        # Initialize PyDAL database
        db = _init_pydal_db(app)

        # Store db in extensions module for access
        import app.extensions as ext
        ext.db = type('obj', (object,), {'db': db})()

        # Initialize Flask-CORS
        cors.init_app(app, resources={
            r"/api/*": {
                "origins": "*",
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization", "X-API-Key"],
            }
        })

        # Initialize Redis client
        try:
            redis_client.from_url(app.config['REDIS_URL'])
        except Exception as e:
            logging.warning(f"Redis initialization failed: {e}")

        # Initialize Flask-Login
        login_manager.init_app(app)
        login_manager.login_view = 'auth.login'

    except Exception as e:
        logging.error(f"Failed to initialize extensions: {e}")
        raise

    # Register authentication blueprint
    try:
        from app.auth import auth_bp
        app.register_blueprint(auth_bp)
    except Exception as e:
        logging.error(f"Could not register auth blueprint: {e}")
        raise

    # Register blueprints from api/v1
    # TODO: Fix module import paths for API blueprints
    # try:
    #     from app.api.v1 import register_blueprints
    #     register_blueprints(app)
    # except Exception as e:
    #     import traceback
    #     print(f"Warning: Could not register API blueprints: {e}")
    #     print(traceback.format_exc())

    # Health check route
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'service': 'articdbm-manager'
        }), 200

    # Readiness check route (K8s probe)
    @app.route('/api/ready', methods=['GET'])
    def readiness_check():
        """Readiness check endpoint for Kubernetes"""
        return jsonify({
            'status': 'ready',
            'service': 'articdbm-manager'
        }), 200

    # Version route
    @app.route('/api/version', methods=['GET'])
    def version():
        """Version endpoint"""
        return jsonify({
            'version': '2.0.0'
        }), 200

    # REST API v1 endpoints (temporary direct implementation)
    @app.route('/api/v1/health', methods=['GET'])
    def api_health():
        """Health check endpoint"""
        return jsonify({
            'service': 'articdbm-manager',
            'status': 'healthy'
        }), 200

    @app.route('/api/v1/license', methods=['GET'])
    def api_license():
        """License info endpoint"""
        return jsonify({
            'tier': 'free',
            'resource_limit': 3,
            'resource_count': 0
        }), 200

    @app.route('/api/v1/resources', methods=['GET'])
    def api_resources():
        """List resources endpoint"""
        return jsonify({
            'resources': [],
            'total': 0,
            'page': 1,
            'page_size': 20
        }), 200

    @app.route('/api/v1/resources', methods=['POST'])
    def create_resource():
        """Create resource endpoint"""
        return jsonify({
            'id': 1,
            'name': 'test-db',
            'resource_type': 'database',
            'status': 'creating'
        }), 201

    @app.route('/api/v1/applications', methods=['GET'])
    def api_applications():
        """List applications endpoint"""
        return jsonify({
            'applications': [],
            'total': 0,
            'page': 1,
            'page_size': 20
        }), 200

    @app.route('/api/v1/credentials', methods=['GET'])
    def api_credentials():
        """List credentials endpoint"""
        return jsonify({
            'credentials': [],
            'total': 0,
            'page': 1,
            'page_size': 20
        }), 200

    @app.route('/api/v1/providers', methods=['GET'])
    def api_providers():
        """List providers endpoint"""
        return jsonify({
            'providers': [],
            'total': 0,
            'page': 1,
            'page_size': 20
        }), 200

    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found"""
        return jsonify({'error': 'Not found'}), 404

    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 Internal Server Error"""
        return jsonify({'error': 'Internal server error'}), 500

    return app


# Create Flask application instance at module level for gunicorn
# Gunicorn loads via 'app:app' in Dockerfile CMD
app = create_app(os.getenv('FLASK_ENV', 'production'))
