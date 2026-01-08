import os
from datetime import timedelta


class Config:
    """Base configuration class with common settings."""

    # Flask settings
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)

    # SQLAlchemy settings
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": int(os.getenv("DB_POOL_SIZE", "10")),
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE", "3600")),
        "pool_pre_ping": True,
    }

    # PyDAL database settings
    DB_TYPE = os.getenv("DB_TYPE", "postgres")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "articdbm")
    DB_USER = os.getenv("DB_USER", "articdbm")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")

    # Build PyDAL database URI
    if DB_TYPE == "postgres":
        PYDAL_URI = f"postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    elif DB_TYPE == "mysql":
        PYDAL_URI = f"mysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    elif DB_TYPE == "sqlite":
        PYDAL_URI = f"sqlite:///{os.getenv('SQLITE_PATH', '/tmp/articdbm.db')}"
    else:
        PYDAL_URI = f"postgres://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

    # Redis settings
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    REDIS_SOCKET_CONNECT_TIMEOUT = 5
    REDIS_SOCKET_TIMEOUT = 5

    # Flask-Security settings
    SECURITY_PASSWORD_SALT = os.getenv("SECURITY_PASSWORD_SALT", "articdbm-salt")
    SECURITY_HASH_ALGORITHM = "bcrypt"
    SECURITY_DEPRECATED_PASSWORD_SCHEMES = []
    SECURITY_PASSWORD_SCHEMES = ["bcrypt"]
    SECURITY_BCRYPT_LOG_ROUNDS = 12
    SECURITY_REGISTERABLE = os.getenv("SECURITY_REGISTERABLE", "False").lower() == "true"
    SECURITY_CONFIRMABLE = os.getenv("SECURITY_CONFIRMABLE", "False").lower() == "true"
    SECURITY_RECOVERABLE = True
    SECURITY_TRACKABLE = True
    SECURITY_CHANGEABLE = True
    SECURITY_TWO_FACTOR_REQUIRED_FOR_LOGIN = (
        os.getenv("TWO_FACTOR_REQUIRED", "False").lower() == "true"
    )
    SECURITY_TWO_FACTOR_LOGIN_ERROR_WINDOW = timedelta(minutes=5)

    # Mail settings for Flask-Security
    MAIL_SERVER = os.getenv("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.getenv("MAIL_PORT", "25"))
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "False").lower() == "true"
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "False").lower() == "true"
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER", "noreply@articdbm.local")

    # License Server settings
    LICENSE_SERVER_URL = os.getenv(
        "LICENSE_SERVER_URL", "https://license.penguintech.io"
    )
    LICENSE_KEY = os.getenv("LICENSE_KEY", "")
    PRODUCT_NAME = os.getenv("PRODUCT_NAME", "articdbm")
    RELEASE_MODE = os.getenv("RELEASE_MODE", "False").lower() == "true"

    # Elder API settings
    ELDER_API_URL = os.getenv("ELDER_API_URL", "http://localhost:8001")
    ELDER_API_KEY = os.getenv("ELDER_API_KEY", "")
    ELDER_API_TIMEOUT = int(os.getenv("ELDER_API_TIMEOUT", "30"))

    # MarchProxy settings
    MARCHPROXY_GRPC_ADDRESS = os.getenv("MARCHPROXY_GRPC_ADDRESS", "localhost:50051")
    MARCHPROXY_GRPC_TIMEOUT = int(os.getenv("MARCHPROXY_GRPC_TIMEOUT", "10"))

    # gRPC server settings
    GRPC_SERVER_PORT = int(os.getenv("GRPC_SERVER_PORT", "50051"))
    GRPC_SERVER_HOST = os.getenv("GRPC_SERVER_HOST", "0.0.0.0")
    GRPC_MAX_CONCURRENT_STREAMS = int(os.getenv("GRPC_MAX_CONCURRENT_STREAMS", "100"))

    # Logging settings
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.getenv(
        "LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # API settings
    JSON_SORT_KEYS = False
    JSONIFY_PRETTYPRINT_REGULAR = False

    # Rate limiting
    RATELIMIT_ENABLED = os.getenv("RATELIMIT_ENABLED", "True").lower() == "true"
    RATELIMIT_DEFAULT = os.getenv("RATELIMIT_DEFAULT", "200 per day, 50 per hour")

    # Audit logging
    AUDIT_LOG_ENABLED = True
    AUDIT_LOG_RETENTION_DAYS = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "90"))

    # Threat intelligence settings
    THREAT_INTEL_ENABLED = os.getenv("THREAT_INTEL_ENABLED", "True").lower() == "true"
    THREAT_INTEL_REFRESH_INTERVAL = int(
        os.getenv("THREAT_INTEL_REFRESH_INTERVAL", "3600")
    )
    STIX_FEED_URL = os.getenv("STIX_FEED_URL", "")
    MISP_SERVER_URL = os.getenv("MISP_SERVER_URL", "")
    MISP_API_KEY = os.getenv("MISP_API_KEY", "")


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_ECHO = True
    PROPAGATE_EXCEPTIONS = True
    PRESERVE_CONTEXT_ON_EXCEPTION = False
    SECURITY_PASSWORD_SCHEMES = ["plaintext"]
    SECURITY_DEPRECATED_PASSWORD_SCHEMES = ["bcrypt"]


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    SQLALCHEMY_ECHO = False
    WTF_CSRF_ENABLED = False
    SECURITY_PASSWORD_HASH_ALGORITHM = "plaintext"
    SECURITY_PASSWORD_SCHEMES = ["plaintext"]
    SECURITY_DEPRECATED_PASSWORD_SCHEMES = []

    # Use SQLite for testing
    DB_TYPE = "sqlite"
    PYDAL_URI = "sqlite:///:memory:"

    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SQLALCHEMY_ECHO = False
    RELEASE_MODE = True

    # Production must have SECRET_KEY set
    SECRET_KEY = os.getenv(
        "SECRET_KEY",
        None,
    )
    if not SECRET_KEY:
        raise ValueError(
            "SECRET_KEY environment variable is required for production"
        )

    # Production must have LICENSE_KEY set
    LICENSE_KEY = os.getenv("LICENSE_KEY", None)
    if not LICENSE_KEY:
        raise ValueError(
            "LICENSE_KEY environment variable is required for production"
        )


# Configuration dictionary for easy selection
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config(config_name=None):
    """Get configuration class based on environment.

    Args:
        config_name: Configuration name ('development', 'testing', 'production').
                    If None, uses FLASK_ENV environment variable or defaults to 'development'.

    Returns:
        Configuration class instance.
    """
    if config_name is None:
        config_name = os.getenv("FLASK_ENV", "development")

    config_class = config.get(config_name, DevelopmentConfig)
    return config_class
