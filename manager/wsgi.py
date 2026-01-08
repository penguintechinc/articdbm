#!/usr/bin/env python3
"""
WSGI Entry Point for ArticDBM Manager Flask Application
"""

import os
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Import the Flask app factory
from app import create_app

# Create the Flask application instance
app = create_app(os.getenv('FLASK_ENV', 'production'))

# Expose for gunicorn
application = app

if __name__ == '__main__':
    app.run()
