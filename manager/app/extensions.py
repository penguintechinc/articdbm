"""Flask extensions initialization.

All extensions are initialized here as uninitialized instances to be
initialized in the app factory pattern.
"""

from flask_security import Security
from flask_login import LoginManager
from flask_cors import CORS
from redis import Redis
from apscheduler.schedulers.background import BackgroundScheduler

# Flask-Security-Too
security = Security()

# Flask-Login
login_manager = LoginManager()

# Flask-CORS
cors = CORS()

# Redis client for caching and configuration distribution
redis_client = Redis()

# PyDAL database connection (lazy initialization in app factory)
db = None

# APScheduler for background tasks
scheduler = BackgroundScheduler()
