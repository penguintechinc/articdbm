"""ArticDBM Flask Application Factory

This module provides a Flask application factory and instantiates the app
at module level for gunicorn to load via 'app:app'.
"""

import os
from flask import Flask, jsonify


def create_app(config_name='development'):
    """
    Application factory function for ArticDBM manager.

    Args:
        config_name: Configuration environment ('development', 'testing', 'production')

    Returns:
        Configured Flask application instance
    """
    app = Flask(__name__)

    # Load configuration
    try:
        if config_name == 'production':
            app.config.from_object('manager.config.ProductionConfig')
        elif config_name == 'testing':
            app.config.from_object('manager.config.TestingConfig')
        else:
            app.config.from_object('manager.config.DevelopmentConfig')
    except Exception:
        # Fallback configuration if config module not found
        app.config['DEBUG'] = config_name != 'production'
        app.config['TESTING'] = config_name == 'testing'

    # Register blueprints from api/v1
    try:
        from manager.app.api.v1 import api_v1_bp
        app.register_blueprint(api_v1_bp, url_prefix='/api/v1')
    except Exception:
        pass  # API module may not be fully set up

    # Health check route
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'service': 'articdbm-manager'
        }), 200

    # Version route
    @app.route('/api/version', methods=['GET'])
    def version():
        """Version endpoint"""
        return jsonify({
            'version': '2.0.0'
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
