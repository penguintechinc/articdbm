"""Cloud provider management endpoints for ArticDBM."""

import logging
from typing import Dict, Any, Optional

from flask import Blueprint, request, jsonify
from flask_security import login_required, current_user
from pydantic import ValidationError

from app.schemas.provider import (
    ProviderCreate,
    ProviderUpdate,
    ProviderResponse,
    ProviderListResponse,
    ProviderTestRequest,
    ProviderTestResponse,
)
from app.services.provisioning import get_provisioner, ProvisionerException
from app.extensions import pydal_manager
from app.utils.api_responses import (
    success_response,
    error_response,
    created_response,
    not_found_response,
    forbidden_response,
)

logger = logging.getLogger(__name__)

providers_bp = Blueprint('providers', __name__, url_prefix='/providers')


def sanitize_provider_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove sensitive data from provider configuration.

    Removes fields like passwords, API keys, tokens, and credentials.

    Args:
        config: Provider configuration dictionary

    Returns:
        Sanitized configuration with secrets removed
    """
    if not config:
        return {}

    sensitive_keys = {
        'password', 'api_key', 'secret_key', 'token', 'access_token',
        'secret_access_key', 'private_key', 'credentials', 'kubeconfig',
        'auth_token', 'bearer_token', 'client_secret', 'client_id',
    }

    sanitized = {}
    for key, value in config.items():
        if key.lower() not in sensitive_keys:
            if isinstance(value, dict):
                sanitized[key] = sanitize_provider_config(value)
            else:
                sanitized[key] = value

    return sanitized


def build_provider_response(provider_row) -> Dict[str, Any]:
    """
    Build a provider response with sanitized configuration.

    Args:
        provider_row: PyDAL provider record

    Returns:
        Dictionary with provider response
    """
    import json

    # Parse configuration JSON
    config = {}
    if provider_row.configuration:
        try:
            if isinstance(provider_row.configuration, str):
                config = json.loads(provider_row.configuration)
            else:
                config = provider_row.configuration
        except (json.JSONDecodeError, TypeError):
            config = {}

    return {
        'id': provider_row.id,
        'name': provider_row.name,
        'provider_type': provider_row.provider_type,
        'configuration': sanitize_provider_config(config),
        'is_default': provider_row.is_default,
        'is_active': provider_row.is_active,
        'status': provider_row.status,
        'last_health_check': provider_row.last_health_check.isoformat()
        if provider_row.last_health_check else None,
        'created_at': provider_row.created_on.isoformat()
        if provider_row.created_on else None,
        'updated_at': provider_row.modified_on.isoformat()
        if provider_row.modified_on else None,
    }


@providers_bp.route('', methods=['GET'])
@login_required
def list_providers():
    """
    List all cloud providers.

    Query Parameters:
        - page: Page number (default: 1)
        - page_size: Items per page (default: 20)
        - provider_type: Filter by provider type
        - is_active: Filter by active status

    Returns:
        JSON with list of providers (sanitized configuration).
    """
    try:
        db = pydal_manager.db

        # Get filter parameters
        page = request.args.get('page', 1, type=int)
        page_size = request.args.get('page_size', 20, type=int)
        provider_type = request.args.get('provider_type', type=str)
        is_active = request.args.get('is_active', type=lambda x: x.lower() == 'true')

        # Build query
        query = db.providers.id > 0
        if provider_type:
            query &= db.providers.provider_type == provider_type
        if is_active is not None:
            query &= db.providers.is_active == is_active

        # Count total
        total = db(query).count()

        # Paginate
        offset = (page - 1) * page_size
        rows = db(query).select(
            orderby=~db.providers.created_on,
            limitby=(offset, offset + page_size),
        )

        # Convert to list with sanitized configs
        providers_list = [build_provider_response(row) for row in rows]

        # Build response
        total_pages = (total + page_size - 1) // page_size
        response_data = {
            'providers': providers_list,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': total_pages,
            'has_next': page < total_pages,
            'has_previous': page > 1,
        }

        return success_response(data=response_data, message='Providers retrieved')

    except Exception as e:
        logger.error(f"Failed to list providers: {e}")
        return error_response(
            error='Failed to list providers',
            details=str(e),
            status_code=500,
        )


@providers_bp.route('', methods=['POST'])
@login_required
def create_provider():
    """
    Create a new cloud provider.

    Request Body:
        - name: Provider name (required)
        - provider_type: Type of provider (kubernetes, aws, gcp, azure, vultr)
        - configuration: Provider-specific configuration (dict)
        - credentials_secret_name: Reference to secret (optional)
        - is_default: Set as default provider (optional, default: false)

    Returns:
        JSON with created provider (sanitized configuration).
    """
    try:
        # Parse request
        data = request.get_json() or {}

        # Validate request
        try:
            provider_req = ProviderCreate(**data)
        except ValidationError as ve:
            return error_response(
                error='Validation failed',
                details=ve.errors(),
                status_code=400,
            )

        db = pydal_manager.db

        # If setting as default, unset any existing defaults
        if provider_req.is_default:
            db(db.providers.is_default == True).update(is_default=False)

        # Convert configuration to JSON string if needed
        import json
        config_json = json.dumps(provider_req.configuration)

        # Insert provider
        provider_id = db.providers.insert(
            name=provider_req.name,
            provider_type=provider_req.provider_type.value,
            configuration=config_json,
            credentials_secret_name=provider_req.credentials_secret_name,
            is_default=provider_req.is_default,
            is_active=True,
            status='unknown',
            created_by=current_user.id,
        )

        db.commit()

        # Fetch created provider
        provider_row = db(db.providers.id == provider_id).select().first()
        response_data = build_provider_response(provider_row)

        logger.info(f"Created provider {provider_id}: {provider_req.name}")
        return created_response(data=response_data, message='Provider created')

    except Exception as e:
        logger.error(f"Failed to create provider: {e}")
        return error_response(
            error='Failed to create provider',
            details=str(e),
            status_code=500,
        )


@providers_bp.route('/<int:provider_id>', methods=['GET'])
@login_required
def get_provider(provider_id: int):
    """
    Get provider details.

    Path Parameters:
        - provider_id: Provider ID

    Returns:
        JSON with provider information (sanitized configuration).
    """
    try:
        db = pydal_manager.db

        provider_row = db(db.providers.id == provider_id).select().first()
        if not provider_row:
            return not_found_response('Provider')

        response_data = build_provider_response(provider_row)
        return success_response(data=response_data, message='Provider retrieved')

    except Exception as e:
        logger.error(f"Failed to get provider {provider_id}: {e}")
        return error_response(
            error='Failed to get provider',
            details=str(e),
            status_code=500,
        )


@providers_bp.route('/<int:provider_id>', methods=['PUT'])
@login_required
def update_provider(provider_id: int):
    """
    Update a cloud provider.

    Path Parameters:
        - provider_id: Provider ID

    Request Body:
        - name: Provider name (optional)
        - configuration: Provider-specific configuration (optional)
        - credentials_secret_name: Reference to secret (optional)
        - is_default: Set as default provider (optional)
        - is_active: Activate/deactivate provider (optional)

    Returns:
        JSON with updated provider (sanitized configuration).
    """
    try:
        # Parse request
        data = request.get_json() or {}

        # Validate request
        try:
            provider_req = ProviderUpdate(**data)
        except ValidationError as ve:
            return error_response(
                error='Validation failed',
                details=ve.errors(),
                status_code=400,
            )

        db = pydal_manager.db

        provider_row = db(db.providers.id == provider_id).select().first()
        if not provider_row:
            return not_found_response('Provider')

        # If setting as default, unset any existing defaults
        if provider_req.is_default:
            db(db.providers.is_default == True).update(is_default=False)

        # Build update dict
        update_dict = {}

        if provider_req.name is not None:
            update_dict['name'] = provider_req.name

        if provider_req.configuration is not None:
            import json
            update_dict['configuration'] = json.dumps(provider_req.configuration)

        if provider_req.credentials_secret_name is not None:
            update_dict['credentials_secret_name'] = provider_req.credentials_secret_name

        if provider_req.is_default is not None:
            update_dict['is_default'] = provider_req.is_default

        if provider_req.is_active is not None:
            update_dict['is_active'] = provider_req.is_active

        # Update provider
        db(db.providers.id == provider_id).update(**update_dict)
        db.commit()

        # Fetch updated provider
        provider_row = db(db.providers.id == provider_id).select().first()
        response_data = build_provider_response(provider_row)

        logger.info(f"Updated provider {provider_id}")
        return success_response(
            data=response_data,
            message='Provider updated',
        )

    except Exception as e:
        logger.error(f"Failed to update provider {provider_id}: {e}")
        return error_response(
            error='Failed to update provider',
            details=str(e),
            status_code=500,
        )


@providers_bp.route('/<int:provider_id>', methods=['DELETE'])
@login_required
def delete_provider(provider_id: int):
    """
    Delete a cloud provider.

    Path Parameters:
        - provider_id: Provider ID

    Returns:
        JSON with deletion status.
    """
    try:
        db = pydal_manager.db

        provider_row = db(db.providers.id == provider_id).select().first()
        if not provider_row:
            return not_found_response('Provider')

        # Check if provider has associated resources
        resource_count = db(db.resources.provider_id == provider_id).count()
        if resource_count > 0:
            return error_response(
                error='Provider has associated resources',
                details=f'Cannot delete provider with {resource_count} resources',
                status_code=400,
            )

        # Delete provider
        db(db.providers.id == provider_id).delete()
        db.commit()

        logger.info(f"Deleted provider {provider_id}")
        return success_response(message='Provider deleted')

    except Exception as e:
        logger.error(f"Failed to delete provider {provider_id}: {e}")
        return error_response(
            error='Failed to delete provider',
            details=str(e),
            status_code=500,
        )


@providers_bp.route('/<int:provider_id>/test', methods=['POST'])
@login_required
def test_provider_connection(provider_id: int):
    """
    Test cloud provider connection.

    Path Parameters:
        - provider_id: Provider ID

    Returns:
        JSON with test result including success status, message, and details.
    """
    try:
        import asyncio
        import json
        from datetime import datetime

        db = pydal_manager.db

        provider_row = db(db.providers.id == provider_id).select().first()
        if not provider_row:
            return not_found_response('Provider')

        # Parse configuration
        config = {}
        if provider_row.configuration:
            try:
                if isinstance(provider_row.configuration, str):
                    config = json.loads(provider_row.configuration)
                else:
                    config = provider_row.configuration
            except (json.JSONDecodeError, TypeError):
                config = {}

        # Get provisioner for this provider type
        try:
            provisioner = get_provisioner(provider_row.provider_type, config)
        except ProvisionerException as pe:
            logger.warning(f"Failed to instantiate provisioner: {pe}")
            return error_response(
                error='Failed to instantiate provisioner',
                details=str(pe),
                status_code=500,
            )

        # Test connection (async)
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            success, message = loop.run_until_complete(
                provisioner.test_connection()
            )
            loop.close()
        except ProvisionerException as pe:
            logger.warning(f"Provider connection test failed: {pe}")
            success = False
            message = str(pe)
        except Exception as e:
            logger.warning(f"Provider connection test exception: {e}")
            success = False
            message = str(e)

        # Update provider status and last health check
        new_status = 'healthy' if success else 'unhealthy'
        db(db.providers.id == provider_id).update(
            status=new_status,
            last_health_check=datetime.utcnow(),
        )
        db.commit()

        # Build response
        response_data = {
            'success': success,
            'message': message,
            'details': {
                'provider_id': provider_id,
                'provider_type': provider_row.provider_type,
                'status': new_status,
                'timestamp': datetime.utcnow().isoformat(),
            }
        }

        status_code = 200 if success else 400

        logger.info(f"Provider {provider_id} connection test: {success}")
        return success_response(
            data=response_data,
            message=f'Connection test {"passed" if success else "failed"}',
            status_code=status_code,
        )

    except Exception as e:
        logger.error(f"Failed to test provider {provider_id}: {e}")
        return error_response(
            error='Failed to test provider connection',
            details=str(e),
            status_code=500,
        )
