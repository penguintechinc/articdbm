"""
PyDAL User and Role Models for ArticDBM Authentication

Defines PyDAL models for user authentication and role-based access control
using Flask-Security-Too integration.
"""

from datetime import datetime
from pydal import DAL, Field
from pydal.validators import IS_EMAIL, CRYPT


def define_user_models(db: DAL) -> None:
    """
    Define user and role models for Flask-Security-Too integration.

    Args:
        db: PyDAL database instance
    """

    # ========================
    # User Model
    # ========================
    db.define_table(
        'auth_user',
        Field('first_name', 'string', default='', label='First Name'),
        Field('last_name', 'string', default='', label='Last Name'),
        Field('email', 'string', unique=True, required=True, label='Email',
              requires=IS_EMAIL()),
        Field('username', 'string', unique=True, required=True, label='Username'),
        Field('password', 'password', required=True, label='Password',
              requires=CRYPT()),
        Field('last_login', 'datetime', label='Last Login'),
        Field('is_active', 'boolean', default=True, label='Active'),
        Field('fs_enabled', 'boolean', default=True, label='Flask-Security Enabled',
              comment='Enable Flask-Security features for this user'),
        Field('confirmed_at', 'datetime', label='Confirmed At',
              comment='Email confirmation timestamp'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False,
              label='Created On'),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False,
              label='Modified On'),
        format='%(email)s',
        singular='User',
        plural='Users',
    )

    # ========================
    # Role Model
    # ========================
    db.define_table(
        'auth_role',
        Field('name', 'string', unique=True, required=True, label='Name'),
        Field('description', 'text', label='Description'),
        Field('permissions', 'json', default='[]', label='Permissions',
              comment='JSON array of permission names'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False,
              label='Created On'),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False,
              label='Modified On'),
        format='%(name)s',
        singular='Role',
        plural='Roles',
    )

    # ========================
    # User-Role Association
    # ========================
    db.define_table(
        'auth_user_role',
        Field('user_id', 'reference auth_user', required=True, label='User',
              ondelete='CASCADE'),
        Field('role_id', 'reference auth_role', required=True, label='Role',
              ondelete='CASCADE'),
        Field('assigned_on', 'datetime', default=datetime.utcnow, writable=False,
              label='Assigned On'),
        singular='User Role',
        plural='User Roles',
    )

    # ========================
    # API Key Model (for programmatic access)
    # ========================
    db.define_table(
        'auth_api_key',
        Field('user_id', 'reference auth_user', required=True, label='User',
              ondelete='CASCADE'),
        Field('name', 'string', required=True, label='Name',
              comment='User-friendly name for this key'),
        Field('key_hash', 'string', required=True, unique=True, label='Key Hash',
              comment='SHA256 hash of the actual API key'),
        Field('permissions', 'json', default='[]', label='Permissions',
              comment='JSON array of granted permissions'),
        Field('is_active', 'boolean', default=True, label='Active'),
        Field('last_used', 'datetime', label='Last Used'),
        Field('expires_at', 'datetime', label='Expires At',
              comment='Automatic expiration date'),
        Field('ip_whitelist', 'json', default='[]', label='IP Whitelist',
              comment='JSON array of whitelisted IP addresses'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False,
              label='Created On'),
        Field('modified_on', 'datetime', update=datetime.utcnow, writable=False,
              label='Modified On'),
        format='%(name)s',
        singular='API Key',
        plural='API Keys',
    )

    # ========================
    # Temporary Access Token
    # ========================
    db.define_table(
        'auth_temp_token',
        Field('user_id', 'reference auth_user', required=True, label='User',
              ondelete='CASCADE'),
        Field('token_hash', 'string', required=True, unique=True, label='Token Hash',
              comment='SHA256 hash of the temporary token'),
        Field('scope', 'string', required=True, label='Scope',
              comment='Purpose/scope of this token'),
        Field('permissions', 'json', default='[]', label='Permissions',
              comment='JSON array of granted permissions'),
        Field('is_active', 'boolean', default=True, label='Active'),
        Field('max_uses', 'integer', default=1, label='Max Uses',
              comment='Maximum number of uses (-1 for unlimited)'),
        Field('usage_count', 'integer', default=0, label='Usage Count',
              comment='Current usage count'),
        Field('created_at', 'datetime', default=datetime.utcnow, writable=False,
              label='Created At'),
        Field('expires_at', 'datetime', required=True, label='Expires At'),
        Field('last_used', 'datetime', label='Last Used'),
        format='%(scope)s',
        singular='Temporary Token',
        plural='Temporary Tokens',
    )

    # ========================
    # User Session (for tracking active sessions)
    # ========================
    db.define_table(
        'auth_user_session',
        Field('user_id', 'reference auth_user', required=True, label='User',
              ondelete='CASCADE'),
        Field('session_id', 'string', required=True, unique=True, label='Session ID',
              comment='Session identifier'),
        Field('ip_address', 'string', required=True, label='IP Address'),
        Field('user_agent', 'string', label='User Agent'),
        Field('is_active', 'boolean', default=True, label='Active'),
        Field('created_on', 'datetime', default=datetime.utcnow, writable=False,
              label='Created On'),
        Field('expires_at', 'datetime', required=True, label='Expires At'),
        Field('last_activity', 'datetime', default=datetime.utcnow,
              label='Last Activity'),
        singular='User Session',
        plural='User Sessions',
    )

    db.commit()


def get_user_by_email(db: DAL, email: str):
    """
    Get user by email address.

    Args:
        db: PyDAL database instance
        email: User email address

    Returns:
        User record or None if not found
    """
    return db(db.auth_user.email == email).select().first()


def get_user_by_username(db: DAL, username: str):
    """
    Get user by username.

    Args:
        db: PyDAL database instance
        username: User username

    Returns:
        User record or None if not found
    """
    return db(db.auth_user.username == username).select().first()


def get_user_by_id(db: DAL, user_id: int):
    """
    Get user by ID.

    Args:
        db: PyDAL database instance
        user_id: User ID

    Returns:
        User record or None if not found
    """
    return db.auth_user[user_id]


def get_user_roles(db: DAL, user_id: int) -> list:
    """
    Get all roles for a user.

    Args:
        db: PyDAL database instance
        user_id: User ID

    Returns:
        List of role records
    """
    user_roles = db(
        (db.auth_user_role.user_id == user_id) &
        (db.auth_user_role.role_id == db.auth_role.id)
    ).select()
    return [role.auth_role for role in user_roles]


def check_user_permission(db: DAL, user_id: int, permission: str) -> bool:
    """
    Check if user has a specific permission.

    Args:
        db: PyDAL database instance
        user_id: User ID
        permission: Permission name to check

    Returns:
        True if user has permission, False otherwise
    """
    roles = get_user_roles(db, user_id)
    for role in roles:
        if role.permissions and permission in role.permissions:
            return True
    return False


def create_user(db: DAL, email: str, username: str, password: str,
                first_name: str = '', last_name: str = '') -> int:
    """
    Create a new user.

    Args:
        db: PyDAL database instance
        email: User email
        username: Username
        password: Password (will be hashed by CRYPT field)
        first_name: User's first name
        last_name: User's last name

    Returns:
        User ID of created user
    """
    user_id = db.auth_user.insert(
        email=email,
        username=username,
        password=password,
        first_name=first_name,
        last_name=last_name,
        is_active=True,
        fs_enabled=True,
    )
    db.commit()
    return user_id


def assign_role_to_user(db: DAL, user_id: int, role_id: int) -> int:
    """
    Assign a role to a user.

    Args:
        db: PyDAL database instance
        user_id: User ID
        role_id: Role ID

    Returns:
        User-role association ID
    """
    assoc_id = db.auth_user_role.insert(
        user_id=user_id,
        role_id=role_id,
    )
    db.commit()
    return assoc_id


def create_api_key(db: DAL, user_id: int, name: str, key_hash: str,
                   permissions: list = None, expires_at=None) -> int:
    """
    Create an API key for a user.

    Args:
        db: PyDAL database instance
        user_id: User ID
        name: Friendly name for the key
        key_hash: SHA256 hash of the API key
        permissions: List of permissions
        expires_at: Expiration datetime

    Returns:
        API key ID
    """
    if permissions is None:
        permissions = []

    api_key_id = db.auth_api_key.insert(
        user_id=user_id,
        name=name,
        key_hash=key_hash,
        permissions=permissions,
        is_active=True,
        expires_at=expires_at,
    )
    db.commit()
    return api_key_id


def get_api_key_by_hash(db: DAL, key_hash: str):
    """
    Get API key by its hash.

    Args:
        db: PyDAL database instance
        key_hash: API key hash

    Returns:
        API key record or None if not found
    """
    return db(
        (db.auth_api_key.key_hash == key_hash) &
        (db.auth_api_key.is_active == True)
    ).select().first()


def create_temp_token(db: DAL, user_id: int, token_hash: str, scope: str,
                      expires_at, permissions: list = None) -> int:
    """
    Create a temporary access token.

    Args:
        db: PyDAL database instance
        user_id: User ID
        token_hash: SHA256 hash of the token
        scope: Token scope/purpose
        expires_at: Expiration datetime
        permissions: List of permissions

    Returns:
        Temporary token ID
    """
    if permissions is None:
        permissions = []

    token_id = db.auth_temp_token.insert(
        user_id=user_id,
        token_hash=token_hash,
        scope=scope,
        permissions=permissions,
        is_active=True,
        expires_at=expires_at,
        max_uses=1,
    )
    db.commit()
    return token_id


def get_temp_token_by_hash(db: DAL, token_hash: str):
    """
    Get temporary token by hash.

    Args:
        db: PyDAL database instance
        token_hash: Token hash

    Returns:
        Temporary token record or None if not found
    """
    return db(
        (db.auth_temp_token.token_hash == token_hash) &
        (db.auth_temp_token.is_active == True)
    ).select().first()
