"""
Authentication Blueprint for ArticDBM Manager

Provides authentication endpoints including login, register, logout,
token validation, and API key management.
"""

import hashlib
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps

import jwt
import bcrypt
from flask import Blueprint, request, jsonify, current_app, g

from app.models.users import (
    get_user_by_email,
    get_user_by_username,
    get_user_by_id,
    get_user_roles,
    check_user_permission,
    create_user,
    assign_role_to_user,
    create_api_key,
    get_api_key_by_hash,
    create_temp_token,
    get_temp_token_by_hash,
)

auth_bp = Blueprint('auth', __name__, url_prefix='/api/v1/auth')


def get_pydal_db():
    """Get PyDAL database instance from app extensions."""
    from app.extensions import db as pydal_manager
    if pydal_manager is None:
        raise RuntimeError("PyDAL database not initialized")
    return pydal_manager.db


def _hash_key(key: str) -> str:
    """Hash a key using SHA256."""
    return hashlib.sha256(key.encode()).hexdigest()


def _hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()


def _verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def _generate_jwt_token(user_id: int, expires_in_hours: int = 24) -> str:
    """
    Generate a JWT token for a user.

    Args:
        user_id: User ID
        expires_in_hours: Token expiration in hours

    Returns:
        JWT token string
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=expires_in_hours),
        'iat': datetime.utcnow(),
    }
    token = jwt.encode(
        payload,
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return token


def _verify_jwt_token(token: str) -> dict:
    """
    Verify a JWT token.

    Args:
        token: JWT token string

    Returns:
        Token payload dict or None if invalid
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def token_required(f):
    """
    Decorator to require JWT token authentication.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401

        if not token:
            return jsonify({'error': 'Token required'}), 401

        payload = _verify_jwt_token(token)
        if payload is None:
            return jsonify({'error': 'Invalid or expired token'}), 401

        db = get_pydal_db()
        user = get_user_by_id(db, payload['user_id'])
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401

        g.user_id = payload['user_id']
        g.user = user
        return f(*args, **kwargs)

    return decorated


def api_key_required(f):
    """
    Decorator to require API key authentication.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')

        if not api_key:
            return jsonify({'error': 'API key required'}), 401

        key_hash = _hash_key(api_key)
        db = get_pydal_db()
        api_key_record = get_api_key_by_hash(db, key_hash)

        if not api_key_record:
            return jsonify({'error': 'Invalid API key'}), 401

        # Check expiration
        if api_key_record.expires_at and api_key_record.expires_at < datetime.utcnow():
            return jsonify({'error': 'API key expired'}), 401

        # Update last used
        api_key_record.update_record(last_used=datetime.utcnow())
        db.commit()

        g.user_id = api_key_record.user_id
        g.api_key_id = api_key_record.id
        return f(*args, **kwargs)

    return decorated


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user account.

    Request JSON:
        - email: User email (required)
        - username: Username (required)
        - password: Password (required)
        - first_name: First name (optional)
        - last_name: Last name (optional)

    Returns:
        JSON with user_id and jwt_token on success, error message on failure
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    # Validate required fields
    email = data.get('email', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    first_name = data.get('first_name', '').strip()
    last_name = data.get('last_name', '').strip()

    if not email or not username or not password:
        return jsonify({
            'error': 'email, username, and password are required'
        }), 400

    # Validate email format
    if '@' not in email or '.' not in email.split('@')[1]:
        return jsonify({'error': 'Invalid email format'}), 400

    # Validate password strength
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    db = get_pydal_db()

    # Check if user already exists
    if get_user_by_email(db, email):
        return jsonify({'error': 'Email already registered'}), 409

    if get_user_by_username(db, username):
        return jsonify({'error': 'Username already taken'}), 409

    try:
        # Hash password using bcrypt
        hashed_password = _hash_password(password)

        # Create user
        user_id = create_user(
            db,
            email=email,
            username=username,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
        )

        # Generate JWT token
        token = _generate_jwt_token(user_id, expires_in_hours=24)

        return jsonify({
            'message': 'User created successfully',
            'user_id': user_id,
            'email': email,
            'username': username,
            'jwt_token': token,
        }), 201

    except Exception as e:
        return jsonify({'error': f'Failed to create user: {str(e)}'}), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Login with email/username and password.

    Request JSON:
        - email_or_username: Email or username (required)
        - password: Password (required)

    Returns:
        JSON with user_id and jwt_token on success, error message on failure
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    email_or_username = data.get('email_or_username', '').strip()
    password = data.get('password', '')

    if not email_or_username or not password:
        return jsonify({
            'error': 'email_or_username and password are required'
        }), 400

    db = get_pydal_db()

    # Try to find user by email or username
    user = get_user_by_email(db, email_or_username)
    if not user:
        user = get_user_by_username(db, email_or_username)

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    if not user.is_active:
        return jsonify({'error': 'User account is inactive'}), 403

    # Verify password
    if not _verify_password(password, user.password):
        return jsonify({'error': 'Invalid credentials'}), 401

    try:
        # Update last login
        user.update_record(last_login=datetime.utcnow())
        db.commit()

        # Generate JWT token
        token = _generate_jwt_token(user.id, expires_in_hours=24)

        return jsonify({
            'message': 'Login successful',
            'user_id': user.id,
            'email': user.email,
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'jwt_token': token,
        }), 200

    except Exception as e:
        return jsonify({'error': f'Login failed: {str(e)}'}), 500


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout():
    """
    Logout user (invalidates session).

    Requires JWT token in Authorization header.

    Returns:
        JSON success message
    """
    return jsonify({
        'message': 'Logout successful',
        'user_id': g.user_id,
    }), 200


@auth_bp.route('/profile', methods=['GET'])
@token_required
def get_profile():
    """
    Get current user profile.

    Requires JWT token in Authorization header.

    Returns:
        JSON with user profile information
    """
    db = get_pydal_db()
    user = get_user_by_id(db, g.user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    roles = get_user_roles(db, g.user_id)
    role_list = [{'id': role.id, 'name': role.name} for role in roles]

    return jsonify({
        'user_id': user.id,
        'email': user.email,
        'username': user.username,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'is_active': user.is_active,
        'created_on': user.created_on.isoformat() if user.created_on else None,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'roles': role_list,
    }), 200


@auth_bp.route('/api-keys', methods=['GET'])
@token_required
def list_api_keys():
    """
    List all API keys for the current user.

    Requires JWT token in Authorization header.

    Returns:
        JSON array of API keys (without full key)
    """
    db = get_pydal_db()
    api_keys = db(db.auth_api_key.user_id == g.user_id).select()

    keys_list = []
    for key in api_keys:
        keys_list.append({
            'id': key.id,
            'name': key.name,
            'is_active': key.is_active,
            'created_on': key.created_on.isoformat() if key.created_on else None,
            'expires_at': key.expires_at.isoformat() if key.expires_at else None,
            'last_used': key.last_used.isoformat() if key.last_used else None,
            'permissions': key.permissions,
        })

    return jsonify({
        'api_keys': keys_list,
        'total': len(keys_list),
    }), 200


@auth_bp.route('/api-keys', methods=['POST'])
@token_required
def create_api_key_endpoint():
    """
    Create a new API key for the current user.

    Requires JWT token in Authorization header.

    Request JSON:
        - name: Friendly name for the key (required)
        - expires_in_days: Days until expiration (optional, default: 365)
        - permissions: Array of permissions (optional, default: [])

    Returns:
        JSON with generated API key (only shown once!)
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    name = data.get('name', '').strip()
    expires_in_days = data.get('expires_in_days', 365)
    permissions = data.get('permissions', [])

    if not name:
        return jsonify({'error': 'name is required'}), 400

    try:
        # Generate API key (32 bytes, base64-like)
        api_key = secrets.token_urlsafe(32)
        key_hash = _hash_key(api_key)

        # Calculate expiration
        expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        db = get_pydal_db()

        # Create API key record
        key_id = create_api_key(
            db,
            user_id=g.user_id,
            name=name,
            key_hash=key_hash,
            permissions=permissions,
            expires_at=expires_at,
        )

        return jsonify({
            'message': 'API key created successfully',
            'key_id': key_id,
            'api_key': api_key,  # Only shown once!
            'note': 'Save this key in a safe place. It will not be shown again.',
            'name': name,
            'expires_at': expires_at.isoformat(),
            'permissions': permissions,
        }), 201

    except Exception as e:
        return jsonify({'error': f'Failed to create API key: {str(e)}'}), 500


@auth_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@token_required
def delete_api_key(key_id):
    """
    Delete an API key.

    Requires JWT token in Authorization header.

    Args:
        key_id: API key ID to delete

    Returns:
        JSON success message
    """
    db = get_pydal_db()

    # Verify the key belongs to the user
    api_key = db.auth_api_key[key_id]
    if not api_key or api_key.user_id != g.user_id:
        return jsonify({'error': 'API key not found'}), 404

    try:
        api_key.delete_record()
        db.commit()

        return jsonify({
            'message': 'API key deleted successfully',
            'key_id': key_id,
        }), 200

    except Exception as e:
        return jsonify({'error': f'Failed to delete API key: {str(e)}'}), 500


@auth_bp.route('/validate-token', methods=['POST'])
def validate_token():
    """
    Validate a JWT token without requiring authentication.

    Request JSON:
        - token: JWT token to validate (required)

    Returns:
        JSON with validation result
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    token = data.get('token', '')

    if not token:
        return jsonify({'error': 'token is required'}), 400

    payload = _verify_jwt_token(token)

    if not payload:
        return jsonify({
            'valid': False,
            'message': 'Invalid or expired token',
        }), 200

    db = get_pydal_db()
    user = get_user_by_id(db, payload['user_id'])

    if not user or not user.is_active:
        return jsonify({
            'valid': False,
            'message': 'User not found or inactive',
        }), 200

    return jsonify({
        'valid': True,
        'user_id': payload['user_id'],
        'email': user.email,
        'username': user.username,
        'expires_at': datetime.fromtimestamp(payload['exp']).isoformat(),
    }), 200


@auth_bp.route('/refresh-token', methods=['POST'])
@token_required
def refresh_token():
    """
    Refresh JWT token for the current user.

    Requires JWT token in Authorization header.

    Returns:
        JSON with new JWT token
    """
    try:
        new_token = _generate_jwt_token(g.user_id, expires_in_hours=24)

        return jsonify({
            'message': 'Token refreshed successfully',
            'jwt_token': new_token,
            'user_id': g.user_id,
        }), 200

    except Exception as e:
        return jsonify({'error': f'Failed to refresh token: {str(e)}'}), 500


@auth_bp.route('/health', methods=['GET'])
def auth_health():
    """
    Health check for authentication service.

    Returns:
        JSON health status
    """
    return jsonify({
        'service': 'articdbm-auth',
        'status': 'healthy',
    }), 200
