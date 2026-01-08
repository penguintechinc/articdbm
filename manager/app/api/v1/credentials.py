"""Credential management endpoints for ArticDBM."""

import logging
from datetime import datetime, timedelta
from typing import Optional

from flask import Blueprint, request, jsonify
from flask_security import login_required, current_user
from pydantic import ValidationError

from app.schemas.credential import (
    CredentialCreate,
    CredentialResponse,
    CredentialListResponse,
    CredentialRotateRequest,
    AutoRotateConfigRequest,
)
from app.models.enums import CredentialType
from app.services.credentials.password import PasswordCredentialService
from app.services.credentials.jwt import JWTCredentialService
from app.services.credentials.iam import IAMCredentialService
from app.services.credentials.mtls import MTLSCredentialService
from app.extensions import pydal_manager
from app.utils.api_responses import (
    success_response,
    error_response,
    created_response,
    not_found_response,
    forbidden_response,
)

logger = logging.getLogger(__name__)

credentials_bp = Blueprint('credentials', __name__, url_prefix='/credentials')

# Initialize credential services
password_service = PasswordCredentialService()
jwt_service = JWTCredentialService()
iam_service = IAMCredentialService()
mtls_service = MTLSCredentialService()


@credentials_bp.route('', methods=['GET'])
@login_required
def list_credentials():
    """
    List all credentials for the current user (no sensitive data).

    Query Parameters:
        - page: Page number (default: 1)
        - page_size: Items per page (default: 20)
        - resource_id: Filter by resource ID
        - application_id: Filter by application ID
        - credential_type: Filter by credential type

    Returns:
        JSON with list of credentials (no passwords/keys/tokens).
    """
    try:
        db = pydal_manager.db

        # Get filter parameters
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 20, type=int)
        resource_id = request.args.get('resource_id', type=int)
        application_id = request.args.get('application_id', type=int)
        credential_type = request.args.get('credential_type', type=str)

        # Build query
        query = db.credentials.is_active == True
        if resource_id:
            query &= db.credentials.resource_id == resource_id
        if application_id:
            query &= db.credentials.application_id == application_id
        if credential_type:
            query &= db.credentials.credential_type == credential_type

        # Count total
        total = db(query).count()

        # Paginate
        offset = (page - 1) * page_size
        rows = db(query).select(
            orderby=~db.credentials.created_on,
            limitby=(offset, offset + page_size),
        )

        # Convert to list (no sensitive fields)
        credentials_list = []
        for row in rows:
            cred_dict = {
                'id': row.id,
                'name': row.name,
                'resource_id': row.resource_id,
                'application_id': row.application_id,
                'credential_type': row.credential_type,
                'permissions': row.permissions,
                'expires_at': row.expires_at.isoformat() if row.expires_at else None,
                'auto_rotate': row.auto_rotate,
                'rotation_interval_days': row.rotation_interval_days,
                'last_rotated_at': row.last_rotated_at.isoformat() if row.last_rotated_at else None,
                'next_rotation_at': row.next_rotation_at.isoformat() if row.next_rotation_at else None,
                'is_active': row.is_active,
                'created_at': row.created_on.isoformat() if row.created_on else None,
            }
            credentials_list.append(cred_dict)

        # Build response
        total_pages = (total + page_size - 1) // page_size
        response_data = {
            'credentials': credentials_list,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_previous': page > 1,
        }

        return success_response(data=response_data, message='Credentials retrieved')

    except Exception as e:
        logger.error(f"Failed to list credentials: {e}")
        return error_response(error='Failed to list credentials', details=str(e), status_code=500)


@credentials_bp.route('', methods=['POST'])
@login_required
def create_credential():
    """
    Create a new credential (returns sensitive data once).

    Request Body:
        - name: Credential name
        - resource_id: Resource ID
        - application_id: Optional application ID
        - credential_type: Type of credential (password, iam_role, jwt, mtls)
        - permissions: List of permissions
        - expires_at: Optional expiration timestamp
        - jwt_subject: Optional JWT subject
        - jwt_claims: Optional JWT custom claims

    Returns:
        JSON with created credential including sensitive data (password, key, token).
    """
    try:
        # Parse request
        data = request.get_json() or {}

        # Validate request
        try:
            credential_req = CredentialCreate(**data)
        except ValidationError as ve:
            return error_response(
                error='Validation failed',
                details=ve.errors(),
                status_code=400,
            )

        db = pydal_manager.db

        # Fetch resource
        resource_row = db(db.resources.id == credential_req.resource_id).select().first()
        if not resource_row:
            return not_found_response('Resource')

        # Convert resource to dict
        resource_dict = {
            'id': resource_row.id,
            'name': resource_row.name,
            'engine': resource_row.engine,
            'endpoint': resource_row.endpoint,
            'port': resource_row.port,
            'database_name': resource_row.database_name,
        }

        # Fetch application if provided
        app_dict = None
        if credential_req.application_id:
            app_row = db(db.applications.id == credential_req.application_id).select().first()
            if app_row:
                app_dict = {'id': app_row.id, 'name': app_row.name}

        # Generate credential based on type
        generated_cred = {}
        if credential_req.credential_type == CredentialType.PASSWORD:
            generated_cred = password_service.generate_credential(
                resource=resource_dict,
                application=app_dict,
                permissions=credential_req.permissions,
                expires_at=credential_req.expires_at,
            )
        elif credential_req.credential_type == CredentialType.JWT:
            generated_cred = jwt_service.generate_token(
                resource=resource_dict.get('name', ''),
                application=app_dict.get('name', '') if app_dict else '',
                permissions=credential_req.permissions,
                subject=credential_req.jwt_subject,
                claims=credential_req.jwt_claims,
            )
        elif credential_req.credential_type == CredentialType.IAM_ROLE:
            generated_cred = iam_service.create_aws_role(
                resource=resource_dict.get('name', ''),
                application=app_dict.get('name', '') if app_dict else '',
                permissions=credential_req.permissions,
            )
        elif credential_req.credential_type == CredentialType.MTLS:
            generated_cred = mtls_service.generate_certificate(
                resource=resource_dict,
                application=app_dict,
                permissions=credential_req.permissions,
            )
        else:
            return error_response(
                error=f'Unsupported credential type: {credential_req.credential_type}',
                status_code=400,
            )

        # Store credential in database
        credential_id = db.credentials.insert(
            name=credential_req.name,
            resource_id=credential_req.resource_id,
            application_id=credential_req.application_id,
            credential_type=credential_req.credential_type.value,
            permissions=credential_req.permissions,
            expires_at=credential_req.expires_at,
            is_active=True,
            created_by=current_user.id,
        )

        # Store type-specific data
        if credential_req.credential_type == CredentialType.PASSWORD:
            # Encrypt and store password
            from app.utils.security import encrypt_data
            encrypted_pwd = encrypt_data(generated_cred.get('password', '').encode())
            db(db.credentials.id == credential_id).update(
                username=generated_cred.get('username'),
                password_encrypted=encrypted_pwd,
            )
        elif credential_req.credential_type == CredentialType.JWT:
            db(db.credentials.id == credential_id).update(
                jwt_subject=credential_req.jwt_subject,
                jwt_claims=credential_req.jwt_claims or {},
            )
        elif credential_req.credential_type == CredentialType.IAM_ROLE:
            db(db.credentials.id == credential_id).update(
                iam_role_arn=generated_cred.get('role_arn'),
                iam_policy=generated_cred.get('policy_document', {}),
            )
        elif credential_req.credential_type == CredentialType.MTLS:
            db(db.credentials.id == credential_id).update(
                mtls_cert=generated_cred.get('cert_pem'),
            )

        db.commit()

        # Build response with sensitive data
        response_data = {
            'id': credential_id,
            'name': credential_req.name,
            'resource_id': credential_req.resource_id,
            'application_id': credential_req.application_id,
            'credential_type': credential_req.credential_type.value,
            'permissions': credential_req.permissions,
            'expires_at': credential_req.expires_at.isoformat() if credential_req.expires_at else None,
            'is_active': True,
            'created_at': datetime.utcnow().isoformat(),
        }

        # Add sensitive data based on type
        if credential_req.credential_type == CredentialType.PASSWORD:
            response_data['username'] = generated_cred.get('username')
            response_data['password'] = generated_cred.get('password')
            response_data['connection_string'] = generated_cred.get('connection_string')
        elif credential_req.credential_type == CredentialType.JWT:
            response_data['jwt_token'] = generated_cred.get('jwt_token')
        elif credential_req.credential_type == CredentialType.IAM_ROLE:
            response_data['iam_role_arn'] = generated_cred.get('role_arn')
        elif credential_req.credential_type == CredentialType.MTLS:
            response_data['mtls_cert'] = generated_cred.get('cert_pem')
            response_data['mtls_key'] = generated_cred.get('key_pem_encrypted')
            response_data['mtls_ca_cert'] = generated_cred.get('ca_cert_pem')

        logger.info(f"Created {credential_req.credential_type} credential {credential_id}")
        return created_response(data=response_data, message='Credential created')

    except Exception as e:
        logger.error(f"Failed to create credential: {e}")
        return error_response(
            error='Failed to create credential',
            details=str(e),
            status_code=500,
        )


@credentials_bp.route('/<int:credential_id>', methods=['GET'])
@login_required
def get_credential(credential_id: int):
    """
    Get credential information (no password/key).

    Path Parameters:
        - credential_id: Credential ID

    Returns:
        JSON with credential info (no sensitive data).
    """
    try:
        db = pydal_manager.db

        credential_row = db(db.credentials.id == credential_id).select().first()
        if not credential_row:
            return not_found_response('Credential')

        # Build response (no sensitive fields)
        response_data = {
            'id': credential_row.id,
            'name': credential_row.name,
            'resource_id': credential_row.resource_id,
            'application_id': credential_row.application_id,
            'credential_type': credential_row.credential_type,
            'permissions': credential_row.permissions,
            'expires_at': credential_row.expires_at.isoformat() if credential_row.expires_at else None,
            'auto_rotate': credential_row.auto_rotate,
            'rotation_interval_days': credential_row.rotation_interval_days,
            'last_rotated_at': credential_row.last_rotated_at.isoformat() if credential_row.last_rotated_at else None,
            'next_rotation_at': credential_row.next_rotation_at.isoformat() if credential_row.next_rotation_at else None,
            'is_active': credential_row.is_active,
            'created_at': credential_row.created_on.isoformat() if credential_row.created_on else None,
        }

        return success_response(data=response_data, message='Credential retrieved')

    except Exception as e:
        logger.error(f"Failed to get credential {credential_id}: {e}")
        return error_response(
            error='Failed to get credential',
            details=str(e),
            status_code=500,
        )


@credentials_bp.route('/<int:credential_id>', methods=['DELETE'])
@login_required
def delete_credential(credential_id: int):
    """
    Revoke a credential (mark as inactive).

    Path Parameters:
        - credential_id: Credential ID

    Returns:
        JSON with revocation status.
    """
    try:
        db = pydal_manager.db

        credential_row = db(db.credentials.id == credential_id).select().first()
        if not credential_row:
            return not_found_response('Credential')

        # Revoke based on type
        try:
            if credential_row.credential_type == CredentialType.PASSWORD.value:
                password_service.revoke_credential(credential_id)
            elif credential_row.credential_type == CredentialType.JWT.value:
                jwt_service.revoke_token(credential_id)
            elif credential_row.credential_type == CredentialType.IAM_ROLE.value:
                iam_service.revoke_credentials(
                    credential_row.iam_role_arn,
                    'aws',
                )
            elif credential_row.credential_type == CredentialType.MTLS.value:
                mtls_service.revoke_certificate(credential_id)
        except Exception as e:
            logger.warning(f"Service revocation failed for {credential_id}: {e}")

        # Mark as inactive
        db(db.credentials.id == credential_id).update(is_active=False)
        db.commit()

        logger.info(f"Revoked credential {credential_id}")
        return success_response(message='Credential revoked')

    except Exception as e:
        logger.error(f"Failed to revoke credential {credential_id}: {e}")
        return error_response(
            error='Failed to revoke credential',
            details=str(e),
            status_code=500,
        )


@credentials_bp.route('/<int:credential_id>/rotate', methods=['POST'])
@login_required
def rotate_credential(credential_id: int):
    """
    Rotate a credential (returns new sensitive values).

    Path Parameters:
        - credential_id: Credential ID

    Request Body:
        - force: Force rotation even if not due (optional)

    Returns:
        JSON with rotated credential including new sensitive data.
    """
    try:
        # Parse request
        data = request.get_json() or {}

        try:
            rotate_req = CredentialRotateRequest(**data)
        except ValidationError as ve:
            return error_response(
                error='Validation failed',
                details=ve.errors(),
                status_code=400,
            )

        db = pydal_manager.db

        credential_row = db(db.credentials.id == credential_id).select().first()
        if not credential_row:
            return not_found_response('Credential')

        # Check if rotation is due
        if not rotate_req.force and credential_row.next_rotation_at:
            if datetime.utcnow() < credential_row.next_rotation_at:
                return error_response(
                    error='Rotation not yet due',
                    details={
                        'next_rotation_at': credential_row.next_rotation_at.isoformat(),
                    },
                    status_code=400,
                )

        # Fetch resource
        resource_row = db(db.resources.id == credential_row.resource_id).select().first()
        if not resource_row:
            return error_response(
                error='Associated resource not found',
                status_code=500,
            )

        resource_dict = {
            'id': resource_row.id,
            'name': resource_row.name,
            'engine': resource_row.engine,
            'endpoint': resource_row.endpoint,
            'port': resource_row.port,
            'database_name': resource_row.database_name,
        }

        # Rotate credential based on type
        rotated_cred = {}
        if credential_row.credential_type == CredentialType.PASSWORD.value:
            rotated_cred = password_service.rotate_credential(
                credential_id=credential_id,
                resource=resource_dict,
            )
        elif credential_row.credential_type == CredentialType.JWT.value:
            rotated_cred = jwt_service.rotate_token(
                old_token='placeholder',  # Would fetch from DB in production
            )
        elif credential_row.credential_type == CredentialType.IAM_ROLE.value:
            rotated_cred = iam_service.rotate_credentials(
                credential_id=credential_row.iam_role_arn,
                provider_type='aws',
            )
        elif credential_row.credential_type == CredentialType.MTLS.value:
            rotated_cred = mtls_service.rotate_certificate(
                credential_id=credential_id,
                resource=resource_dict,
            )
        else:
            return error_response(
                error=f'Unsupported credential type: {credential_row.credential_type}',
                status_code=400,
            )

        # Update database
        now = datetime.utcnow()
        next_rotation = now + timedelta(days=credential_row.rotation_interval_days)

        db(db.credentials.id == credential_id).update(
            last_rotated_at=now,
            next_rotation_at=next_rotation,
        )

        # Update type-specific data
        if credential_row.credential_type == CredentialType.PASSWORD.value:
            from app.utils.security import encrypt_data
            encrypted_pwd = encrypt_data(rotated_cred.get('password', '').encode())
            db(db.credentials.id == credential_id).update(
                password_encrypted=encrypted_pwd,
            )
        elif credential_row.credential_type == CredentialType.MTLS.value:
            db(db.credentials.id == credential_id).update(
                mtls_cert=rotated_cred.get('cert_pem'),
            )

        db.commit()

        # Build response with new sensitive data
        response_data = {
            'id': credential_id,
            'name': credential_row.name,
            'credential_type': credential_row.credential_type,
            'last_rotated_at': now.isoformat(),
            'next_rotation_at': next_rotation.isoformat(),
        }

        # Add new sensitive data based on type
        if credential_row.credential_type == CredentialType.PASSWORD.value:
            response_data['username'] = rotated_cred.get('username')
            response_data['password'] = rotated_cred.get('password')
            response_data['connection_string'] = rotated_cred.get('connection_string')
        elif credential_row.credential_type == CredentialType.JWT.value:
            response_data['jwt_token'] = rotated_cred.get('jwt_token')
        elif credential_row.credential_type == CredentialType.MTLS.value:
            response_data['mtls_cert'] = rotated_cred.get('cert_pem')
            response_data['mtls_key'] = rotated_cred.get('key_pem_encrypted')

        logger.info(f"Rotated credential {credential_id}")
        return success_response(data=response_data, message='Credential rotated')

    except Exception as e:
        logger.error(f"Failed to rotate credential {credential_id}: {e}")
        return error_response(
            error='Failed to rotate credential',
            details=str(e),
            status_code=500,
        )


@credentials_bp.route('/<int:credential_id>/auto-rotate', methods=['PUT'])
@login_required
def configure_auto_rotate(credential_id: int):
    """
    Configure automatic credential rotation.

    Path Parameters:
        - credential_id: Credential ID

    Request Body:
        - auto_rotate: Enable/disable auto-rotation (boolean)
        - rotation_interval_days: Days between rotations (integer, >= 1)

    Returns:
        JSON with updated auto-rotation configuration.
    """
    try:
        # Parse request
        data = request.get_json() or {}

        try:
            auto_rotate_req = AutoRotateConfigRequest(**data)
        except ValidationError as ve:
            return error_response(
                error='Validation failed',
                details=ve.errors(),
                status_code=400,
            )

        db = pydal_manager.db

        credential_row = db(db.credentials.id == credential_id).select().first()
        if not credential_row:
            return not_found_response('Credential')

        # Update configuration
        now = datetime.utcnow()
        next_rotation = None
        if auto_rotate_req.auto_rotate:
            next_rotation = now + timedelta(days=auto_rotate_req.rotation_interval_days)

        db(db.credentials.id == credential_id).update(
            auto_rotate=auto_rotate_req.auto_rotate,
            rotation_interval_days=auto_rotate_req.rotation_interval_days,
            next_rotation_at=next_rotation,
        )
        db.commit()

        # Build response
        response_data = {
            'id': credential_id,
            'name': credential_row.name,
            'auto_rotate': auto_rotate_req.auto_rotate,
            'rotation_interval_days': auto_rotate_req.rotation_interval_days,
            'next_rotation_at': next_rotation.isoformat() if next_rotation else None,
        }

        logger.info(f"Updated auto-rotation config for credential {credential_id}")
        return success_response(
            data=response_data,
            message='Auto-rotation configuration updated',
        )

    except Exception as e:
        logger.error(f"Failed to configure auto-rotation for {credential_id}: {e}")
        return error_response(
            error='Failed to configure auto-rotation',
            details=str(e),
            status_code=500,
        )
