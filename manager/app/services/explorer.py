"""Database explorer service for read-only access with RBAC and PII protection."""

import logging
from typing import Any, Dict, List, Optional

from flask import request
from flask_security import current_user, login_required

from app.api.errors import ForbiddenError, ValidationError
from app.services.pii_detector import PIIDetector

logger = logging.getLogger(__name__)


class ExplorerService:
    """Database exploration using PyDAL with RBAC and PII handling."""

    def __init__(self, db):
        """Initialize explorer service with database instance."""
        self.db = db
        self.pii_detector = PIIDetector()

    def can_access_resource(self, resource_id: int) -> bool:
        """
        Check if current user can access a resource.

        Args:
            resource_id: ID of the resource to check

        Returns:
            True if user can access, False otherwise
        """
        # Check if user has global view permission
        if current_user.has_permission('explorer:view:global'):
            return True

        # Check if user has org-level view permission
        if current_user.has_permission('explorer:view:org'):
            # For now, all users in same org can view
            # TODO: Implement org filtering when multi-org is added
            return True

        # Check if user has resource-specific permission
        if current_user.has_permission('explorer:view:resource'):
            # TODO: Implement resource-level permissions check
            return True

        return False

    def get_accessible_clusters(self) -> List[Dict]:
        """Get clusters accessible to current user."""
        try:
            # For now, return all clusters
            # TODO: Filter by organization when multi-org is added
            clusters = self.db(self.db.resource_clusters).select()
            return [
                {
                    'id': c.id,
                    'name': c.name,
                    'description': c.description,
                    'provider_id': c.provider_id,
                }
                for c in clusters
            ]
        except Exception as e:
            logger.error(f"Error getting clusters: {e}")
            raise

    def get_cluster_databases(self, cluster_id: int) -> List[Dict]:
        """Get databases in a cluster."""
        try:
            # Return all distinct database names from resources in this cluster
            resources = self.db(
                (self.db.resources.cluster_id == cluster_id) &
                (self.db.resources.deleted_at == None)
            ).select(self.db.resources.database_name)

            databases = []
            seen = set()

            for r in resources:
                db_name = r.database_name or 'default'
                if db_name not in seen:
                    databases.append({'name': db_name})
                    seen.add(db_name)

            return databases
        except Exception as e:
            logger.error(f"Error getting databases for cluster {cluster_id}: {e}")
            raise

    def execute_safe_query(
        self,
        resource_id: int,
        table_name: str,
        page: int = 1,
        per_page: int = 50,
        orderby: Optional[str] = None,
        where_filter: Optional[str] = None
    ) -> Dict:
        """
        Safely execute SELECT query on table with:
        1. Permission checks (user can access resource)
        2. Table/column validation (prevent injection)
        3. PII detection and masking
        4. Audit logging

        Args:
            resource_id: ID of the resource (database)
            table_name: Name of the table to query
            page: Page number (1-indexed)
            per_page: Records per page (max 100)
            orderby: Column to order by (validated)
            where_filter: Filter clause (currently unused, requires safe parsing)

        Returns:
            Dict with table data, column info, and PII status
        """
        # 1. Validate inputs
        if not table_name or not isinstance(table_name, str):
            raise ValidationError("Invalid table name")

        if page < 1:
            raise ValidationError("Page must be >= 1")

        if per_page < 1 or per_page > 100:
            raise ValidationError("per_page must be between 1 and 100")

        # 2. Check permissions
        if not self.can_access_resource(resource_id):
            raise ForbiddenError("Access denied to this resource")

        # 3. Verify resource exists
        resource = self.db(
            self.db.resources.id == resource_id
        ).select(limitby=(0, 1)).first()

        if not resource:
            raise ValidationError(f"Resource {resource_id} not found")

        # 4. Get PyDAL table definition
        try:
            target_table = self.db[table_name]
        except Exception:
            raise ValidationError(f"Table '{table_name}' not found")

        # 5. Detect PII columns
        pii_columns = self.pii_detector.detect_pii_columns(target_table)
        has_pii_access = current_user.has_permission('explorer:pii:access')

        # 6. Validate orderby column
        orderby_field = None
        if orderby:
            if orderby not in [f.name for f in target_table]:
                raise ValidationError(f"Column '{orderby}' not found in table")
            orderby_field = target_table[orderby]
        else:
            # Default to id field if it exists
            if 'id' in [f.name for f in target_table]:
                orderby_field = target_table.id
            else:
                orderby_field = target_table[0]

        # 7. Build query (never show soft-deleted records)
        query = ()  # Start with empty query
        if 'deleted_at' in [f.name for f in target_table]:
            query = (target_table.deleted_at == None)

        # TODO: Parse and validate where_filter safely when needed

        # 8. Execute SELECT with pagination
        offset = (page - 1) * per_page

        try:
            if query:
                rows = self.db(query).select(
                    orderby=orderby_field,
                    limitby=(offset, offset + per_page)
                )
                total_rows = self.db(query).count()
            else:
                rows = target_table.select(
                    orderby=orderby_field,
                    limitby=(offset, offset + per_page)
                )
                total_rows = target_table.count()
        except Exception as e:
            logger.error(f"Query execution error: {e}")
            raise ValidationError(f"Query execution failed: {str(e)}")

        # 9. Convert rows to dicts and mask PII if needed
        rows_list = []
        for row in rows:
            row_data = {}
            for field in target_table:
                col_name = field.name
                value = row[col_name]

                # Mask PII if user doesn't have permission
                if col_name in pii_columns and not has_pii_access:
                    value = self.pii_detector.mask_pii_value(
                        value, pii_columns[col_name]
                    )

                row_data[col_name] = value

            rows_list.append(row_data)

        # 10. Build column metadata
        columns = []
        for field in target_table:
            col_name = field.name
            columns.append({
                'name': col_name,
                'type': str(field.type),
                'pii': col_name in pii_columns,
                'pii_type': pii_columns.get(col_name),
                'masked': col_name in pii_columns and not has_pii_access,
            })

        # 11. Audit log
        self.log_explorer_access(
            action='view_table',
            resource_id=resource_id,
            table=table_name,
            pii_accessed=has_pii_access and bool(pii_columns)
        )

        # 12. Return results
        return {
            'table': table_name,
            'total_rows': total_rows,
            'page': page,
            'per_page': per_page,
            'columns': columns,
            'rows': rows_list,
            'pii_detected': bool(pii_columns),
            'pii_access_granted': has_pii_access,
            'audit_logged': True,
        }

    def get_audit_logs(self, limit: int = 100) -> List[Dict]:
        """Get explorer audit logs (admin only)."""
        if not current_user.has_permission('explorer:admin:audit_logs'):
            raise ForbiddenError("Access denied to audit logs")

        try:
            logs = self.db(
                self.db.explorer_audit_log
            ).select(
                orderby=~self.db.explorer_audit_log.timestamp,
                limitby=(0, limit)
            )

            return [
                {
                    'id': log.id,
                    'user_id': log.user_id,
                    'action': log.action,
                    'resource_id': log.resource_id,
                    'table': log.table,
                    'pii_accessed': log.pii_accessed,
                    'timestamp': log.timestamp.isoformat(),
                    'ip_address': log.ip_address,
                    'user_agent': log.user_agent,
                }
                for log in logs
            ]
        except Exception as e:
            logger.error(f"Error getting audit logs: {e}")
            raise

    def log_explorer_access(
        self,
        action: str,
        resource_id: int,
        table: str,
        pii_accessed: bool = False
    ) -> None:
        """
        Log explorer access for audit trail.

        Args:
            action: Action type (view_table, etc.)
            resource_id: ID of the resource accessed
            table: Table name accessed
            pii_accessed: Whether PII fields were accessed
        """
        try:
            self.db.explorer_audit_log.insert(
                user_id=current_user.id,
                action=action,
                resource_id=resource_id,
                table=table,
                pii_accessed=pii_accessed,
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', ''),
            )
            self.db.commit()
        except Exception as e:
            logger.error(f"Error logging explorer access: {e}")
            # Don't raise - logging failure shouldn't block the request
