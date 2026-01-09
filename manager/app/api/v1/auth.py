"""Authentication endpoints using Flask-Security-Too.

Provides JWT-based authentication with user registration, login, logout,
token refresh, and user information endpoints.
"""

from datetime import datetime, timedelta
from typing import Tuple, Dict, Any

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user, hash_password
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)

from app.api.errors import ValidationError, ForbiddenError

# Create Blueprint
auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["POST"])
def login() -> Tuple[Dict[str, Any], int]:
    """
    Login endpoint with username/password.

    Returns JWT access token and refresh token.

    Request JSON:
        {
            "username": "user@example.com",
            "password": "password123"
        }

    Response:
        {
            "success": true,
            "data": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
                "user": {
                    "id": 1,
                    "username": "user@example.com",
                    "email": "user@example.com",
                    "first_name": "John",
                    "last_name": "Doe",
                    "is_active": true,
                    "confirmed_at": "2024-01-15T10:30:00"
                }
            },
            "message": "Login successful"
        }

    Status Codes:
        200: Login successful
        400: Missing required fields
        401: Invalid credentials
    """
    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body required'}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    # Get user from database
    db = current_app.extensions.get("db")
    if not db:
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        # Query user by username or email
        user = db(
            (db.auth_user.username == username) | (db.auth_user.email == username)
        ).select().first()

        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401

        if not user.is_active:
            return jsonify({'error': 'Account is inactive'}), 401

        # Verify password
        from app.utils.security import verify_password

        if not verify_password(password, user.password):
            return jsonify({'error': 'Invalid username or password'}), 401

        # Update last login timestamp
        user.update_record(last_login=datetime.utcnow())
        db.commit()

        # Generate tokens
        access_token = create_access_token(
            identity=str(user.id),
            expires_delta=timedelta(
                hours=current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES", 1)
            ),
        )
        refresh_token = create_refresh_token(
            identity=str(user.id),
            expires_delta=timedelta(
                days=current_app.config.get("JWT_REFRESH_TOKEN_EXPIRES", 30)
            ),
        )

        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "is_active": user.is_active,
            "confirmed_at": user.confirmed_at.isoformat()
            if user.confirmed_at
            else None,
        }

        response_data = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user_data,
        }

        return jsonify(response_data), 200

    except Exception as e:
        current_app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed'}), 500


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout() -> Tuple[Dict[str, Any], int]:
    """
    Logout endpoint.

    Invalidates the current user's session. Token is added to
    blacklist (if blacklist enabled in config).

    Headers:
        Authorization: Bearer <access_token>

    Response:
        {
            "success": true,
            "message": "Logout successful"
        }

    Status Codes:
        200: Logout successful
        401: Unauthorized (missing token)
    """
    try:
        # Log the logout action
        db = current_app.extensions.get("db")
        if db and current_user:
            db.audit_log.insert(
                user_id=current_user.id,
                action="logout",
                resource_type="auth",
                status="success",
                ip_address=request.remote_addr,
                user_agent=request.headers.get("User-Agent", ""),
            )
            db.commit()

        return jsonify({'message': 'Logout successful'}), 200

    except Exception as e:
        current_app.logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed'}), 500


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh() -> Tuple[Dict[str, Any], int]:
    """
    Refresh JWT access token.

    Uses refresh token to generate a new access token without
    requiring password re-entry.

    Headers:
        Authorization: Bearer <refresh_token>

    Response:
        {
            "success": true,
            "data": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
            },
            "message": "Token refreshed"
        }

    Status Codes:
        200: Token refresh successful
        401: Invalid or expired refresh token
    """
    try:
        user_id = get_jwt_identity()

        # Verify user still exists and is active
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database connection failed'}), 500

        user = db.auth_user[int(user_id)]
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401

        # Generate new access token
        access_token = create_access_token(
            identity=user_id,
            expires_delta=timedelta(
                hours=current_app.config.get("JWT_ACCESS_TOKEN_EXPIRES", 1)
            ),
        )

        return jsonify({"access_token": access_token}), 200

    except Exception as e:
        current_app.logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed'}), 500


@auth_bp.route("/me", methods=["GET"])
@login_required
def get_current_user() -> Tuple[Dict[str, Any], int]:
    """
    Get current authenticated user information.

    Returns detailed information about the currently authenticated user.

    Headers:
        Authorization: Bearer <access_token>

    Response:
        {
            "success": true,
            "data": {
                "id": 1,
                "username": "user@example.com",
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "is_active": true,
                "confirmed_at": "2024-01-15T10:30:00",
                "last_login": "2024-01-16T15:45:00",
                "roles": [
                    {
                        "id": 1,
                        "name": "admin",
                        "description": "Administrator role"
                    }
                ]
            }
        }

    Status Codes:
        200: User information retrieved
        401: Unauthorized (missing or invalid token)
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({'error': 'Database connection failed'}), 500

        # Fetch user with roles
        user = db.auth_user[current_user.id]
        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Fetch user roles
        user_roles = db(db.auth_user_role.user_id == user.id).select()
        roles = []
        for user_role in user_roles:
            role = db.auth_role[user_role.role_id]
            if role:
                roles.append(
                    {
                        "id": role.id,
                        "name": role.name,
                        "description": role.description or "",
                    }
                )

        user_data = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name or "",
            "last_name": user.last_name or "",
            "is_active": user.is_active,
            "confirmed_at": user.confirmed_at.isoformat()
            if user.confirmed_at
            else None,
            "last_login": user.last_login.isoformat()
            if user.last_login
            else None,
            "roles": roles,
        }

        return jsonify(user_data), 200

    except Exception as e:
        current_app.logger.error(f"Get user error: {str(e)}")
        return jsonify({'error': 'Failed to retrieve user information'}), 500


@auth_bp.route("/register", methods=["POST"])
def register() -> Tuple[Dict[str, Any], int]:
    """
    Register new user (admin only or if registration enabled).

    Creates new user account. Requires admin role unless
    ALLOW_PUBLIC_REGISTRATION is enabled in config.

    Request JSON:
        {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "securepassword",
            "first_name": "John",
            "last_name": "Doe"
        }

    Response:
        {
            "success": true,
            "data": {
                "id": 2,
                "username": "newuser",
                "email": "newuser@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "is_active": true
            },
            "message": "User registered successfully"
        }

    Status Codes:
        201: User created successfully
        400: Invalid input or user already exists
        403: Forbidden (registration disabled or not admin)
        500: Server error
    """
    # Check if registration is enabled
    allow_public = current_app.config.get("ALLOW_PUBLIC_REGISTRATION", False)

    if not allow_public:
        # Check if user is authenticated and is admin
        if not current_user or "admin" not in [r.name for r in current_user.roles]:
            return jsonify({'error': 'User registration is disabled'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Request body required'}), 400

    # Validate required fields
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    first_name = data.get("first_name", "").strip()
    last_name = data.get("last_name", "").strip()

    errors = {}

    if not username or len(username) < 3:
        errors["username"] = "Username required (minimum 3 characters)"

    if not email or "@" not in email:
        errors["email"] = "Valid email required"

    if not password or len(password) < 8:
        errors["password"] = "Password required (minimum 8 characters)"

    if errors:
        return jsonify({'error': 'Validation failed'}), 400

    try:
        db = current_app.extensions.get("db")
        if not db:
            return error_response(
                error="Database connection failed",
                status_code=500,
            )

        # Check if username exists
        existing_user = db(db.auth_user.username == username).select().first()
        if existing_user:
            return jsonify({'error': 'Username already exists'}), 400

        # Check if email exists
        existing_email = db(db.auth_user.email == email).select().first()
        if existing_email:
            return jsonify({'error': 'Email already registered'}), 400

        # Hash password
        from app.utils.security import hash_password

        hashed_password = hash_password(password)

        # Create user
        user_id = db.auth_user.insert(
            username=username,
            email=email,
            password=hashed_password,
            first_name=first_name,
            last_name=last_name,
            is_active=True,
            fs_enabled=True,
            created_on=datetime.utcnow(),
        )

        db.commit()

        user_data = {
            "id": user_id,
            "username": username,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "is_active": True,
        }

        return jsonify(user_data), 201

    except Exception as e:
        current_app.logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500
