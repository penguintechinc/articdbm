"""Protocol Buffer Message Converters

Converts between protobuf messages and internal PyDAL models.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydal import DAL


class ProtoConverter:
    """Converts between protobuf messages and internal models."""

    @staticmethod
    def resource_to_proto(row: Any) -> Dict[str, Any]:
        """Convert PyDAL resource row to proto-compatible dict.

        Args:
            row: PyDAL Row object from resources table

        Returns:
            Dictionary with proto-compatible field names and types
        """
        if not row:
            return {}

        return {
            'id': row.id,
            'name': row.name or '',
            'resource_type': row.resource_type or '',
            'engine': row.engine or '',
            'engine_version': row.engine_version or '',
            'provider_id': row.provider_id or 0,
            'application_id': row.application_id or 0,
            'cluster_id': row.cluster_id or 0,
            'endpoint': row.endpoint or '',
            'port': row.port or 0,
            'database_name': row.database_name or '',
            'instance_class': row.instance_class or '',
            'storage_size_gb': row.storage_size_gb or 0,
            'multi_az': row.multi_az or False,
            'replicas': row.replicas or 0,
            'tls_mode': row.tls_mode or 'required',
            'provider_resource_id': row.provider_resource_id or '',
            'status': row.status or 'unknown',
            'status_message': row.status_message or '',
            'tags': row.tags or {},
            'elder_entity_id': row.elder_entity_id or '',
            'created_by': row.created_by or 0,
            'created_on': row.created_on.isoformat() if row.created_on else '',
            'modified_on': row.modified_on.isoformat() if row.modified_on else '',
        }

    @staticmethod
    def application_to_proto(row: Any) -> Dict[str, Any]:
        """Convert PyDAL application row to proto-compatible dict.

        Args:
            row: PyDAL Row object from applications table

        Returns:
            Dictionary with proto-compatible field names and types
        """
        if not row:
            return {}

        return {
            'id': row.id,
            'name': row.name or '',
            'description': row.description or '',
            'deployment_model': row.deployment_model or 'shared',
            'organization_id': row.organization_id or 0,
            'elder_entity_id': row.elder_entity_id or '',
            'elder_service_id': row.elder_service_id or '',
            'tags': row.tags or {},
            'is_active': row.is_active or False,
            'created_by': row.created_by or 0,
            'created_on': row.created_on.isoformat() if row.created_on else '',
            'modified_on': row.modified_on.isoformat() if row.modified_on else '',
        }

    @staticmethod
    def credential_to_proto(row: Any) -> Dict[str, Any]:
        """Convert PyDAL credential row to proto-compatible dict.

        Args:
            row: PyDAL Row object from credentials table

        Returns:
            Dictionary with proto-compatible field names and types
        """
        if not row:
            return {}

        return {
            'id': row.id,
            'name': row.name or '',
            'resource_id': row.resource_id or 0,
            'application_id': row.application_id or 0,
            'credential_type': row.credential_type or '',
            'username': row.username or '',
            'iam_role_arn': row.iam_role_arn or '',
            'jwt_subject': row.jwt_subject or '',
            'permissions': row.permissions or [],
            'expires_at': row.expires_at.isoformat() if row.expires_at else '',
            'auto_rotate': row.auto_rotate or False,
            'rotation_interval_days': row.rotation_interval_days or 30,
            'last_rotated_at': row.last_rotated_at.isoformat() if row.last_rotated_at else '',
            'next_rotation_at': row.next_rotation_at.isoformat() if row.next_rotation_at else '',
            'is_active': row.is_active or False,
            'created_by': row.created_by or 0,
            'created_on': row.created_on.isoformat() if row.created_on else '',
            'modified_on': row.modified_on.isoformat() if row.modified_on else '',
        }

    @staticmethod
    def provider_to_proto(row: Any) -> Dict[str, Any]:
        """Convert PyDAL provider row to proto-compatible dict.

        Args:
            row: PyDAL Row object from providers table

        Returns:
            Dictionary with proto-compatible field names and types
        """
        if not row:
            return {}

        return {
            'id': row.id,
            'name': row.name or '',
            'provider_type': row.provider_type or '',
            'configuration': row.configuration or {},
            'credentials_secret_name': row.credentials_secret_name or '',
            'is_default': row.is_default or False,
            'is_active': row.is_active or False,
            'status': row.status or 'unknown',
            'last_health_check': row.last_health_check.isoformat() if row.last_health_check else '',
            'created_by': row.created_by or 0,
            'created_on': row.created_on.isoformat() if row.created_on else '',
            'modified_on': row.modified_on.isoformat() if row.modified_on else '',
        }

    @staticmethod
    def proto_to_resource_dict(proto_msg: Any) -> Dict[str, Any]:
        """Convert proto resource message to dict for PyDAL insert/update.

        Args:
            proto_msg: Protobuf message object

        Returns:
            Dictionary suitable for PyDAL operations
        """
        data = {}

        # Map proto fields to database fields
        if hasattr(proto_msg, 'name') and proto_msg.name:
            data['name'] = proto_msg.name
        if hasattr(proto_msg, 'resource_type') and proto_msg.resource_type:
            data['resource_type'] = proto_msg.resource_type
        if hasattr(proto_msg, 'engine') and proto_msg.engine:
            data['engine'] = proto_msg.engine
        if hasattr(proto_msg, 'engine_version') and proto_msg.engine_version:
            data['engine_version'] = proto_msg.engine_version
        if hasattr(proto_msg, 'provider_id') and proto_msg.provider_id:
            data['provider_id'] = proto_msg.provider_id
        if hasattr(proto_msg, 'application_id') and proto_msg.application_id:
            data['application_id'] = proto_msg.application_id
        if hasattr(proto_msg, 'endpoint') and proto_msg.endpoint:
            data['endpoint'] = proto_msg.endpoint
        if hasattr(proto_msg, 'port') and proto_msg.port:
            data['port'] = proto_msg.port
        if hasattr(proto_msg, 'database_name') and proto_msg.database_name:
            data['database_name'] = proto_msg.database_name
        if hasattr(proto_msg, 'instance_class') and proto_msg.instance_class:
            data['instance_class'] = proto_msg.instance_class
        if hasattr(proto_msg, 'storage_size_gb') and proto_msg.storage_size_gb:
            data['storage_size_gb'] = proto_msg.storage_size_gb
        if hasattr(proto_msg, 'tls_mode') and proto_msg.tls_mode:
            data['tls_mode'] = proto_msg.tls_mode
        if hasattr(proto_msg, 'tags'):
            data['tags'] = dict(proto_msg.tags) if proto_msg.tags else {}

        return data

    @staticmethod
    def proto_to_application_dict(proto_msg: Any) -> Dict[str, Any]:
        """Convert proto application message to dict for PyDAL insert/update.

        Args:
            proto_msg: Protobuf message object

        Returns:
            Dictionary suitable for PyDAL operations
        """
        data = {}

        if hasattr(proto_msg, 'name') and proto_msg.name:
            data['name'] = proto_msg.name
        if hasattr(proto_msg, 'description') and proto_msg.description:
            data['description'] = proto_msg.description
        if hasattr(proto_msg, 'deployment_model') and proto_msg.deployment_model:
            data['deployment_model'] = proto_msg.deployment_model
        if hasattr(proto_msg, 'organization_id') and proto_msg.organization_id:
            data['organization_id'] = proto_msg.organization_id
        if hasattr(proto_msg, 'tags'):
            data['tags'] = dict(proto_msg.tags) if proto_msg.tags else {}

        return data

    @staticmethod
    def proto_to_credential_dict(proto_msg: Any) -> Dict[str, Any]:
        """Convert proto credential message to dict for PyDAL insert/update.

        Args:
            proto_msg: Protobuf message object

        Returns:
            Dictionary suitable for PyDAL operations
        """
        data = {}

        if hasattr(proto_msg, 'name') and proto_msg.name:
            data['name'] = proto_msg.name
        if hasattr(proto_msg, 'resource_id') and proto_msg.resource_id:
            data['resource_id'] = proto_msg.resource_id
        if hasattr(proto_msg, 'application_id') and proto_msg.application_id:
            data['application_id'] = proto_msg.application_id
        if hasattr(proto_msg, 'credential_type') and proto_msg.credential_type:
            data['credential_type'] = proto_msg.credential_type
        if hasattr(proto_msg, 'username') and proto_msg.username:
            data['username'] = proto_msg.username
        if hasattr(proto_msg, 'permissions'):
            data['permissions'] = list(proto_msg.permissions) if proto_msg.permissions else []
        if hasattr(proto_msg, 'auto_rotate'):
            data['auto_rotate'] = proto_msg.auto_rotate
        if hasattr(proto_msg, 'rotation_interval_days') and proto_msg.rotation_interval_days:
            data['rotation_interval_days'] = proto_msg.rotation_interval_days

        return data
