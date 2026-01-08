"""
PyDAL utility helpers for ArticDBM.

Provides common utility functions for working with PyDAL:
- Row/Rows conversion to dicts/lists
- Pagination support
- CRUD operations
- Soft delete functionality
- License management utilities
"""

from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime
from pydal.objects import Row, Rows, Set
from flask import abort


def row_to_dict(row: Row) -> Dict[str, Any]:
    """
    Convert a PyDAL Row to a dictionary.

    Args:
        row: PyDAL Row object to convert

    Returns:
        Dictionary representation of the row with all fields
    """
    if row is None:
        return {}

    result = {}
    for field in row.keys():
        value = row[field]
        # Handle datetime objects
        if isinstance(value, datetime):
            result[field] = value.isoformat()
        else:
            result[field] = value
    return result


def rows_to_list(rows: Rows) -> List[Dict[str, Any]]:
    """
    Convert PyDAL Rows to a list of dictionaries.

    Args:
        rows: PyDAL Rows object to convert

    Returns:
        List of dictionaries, one per row
    """
    if not rows:
        return []

    return [row_to_dict(row) for row in rows]


def paginate_query(
    query: Set,
    page: int = 1,
    per_page: int = 20
) -> Tuple[Rows, Dict[str, Any]]:
    """
    Paginate a PyDAL query result.

    Args:
        query: PyDAL query (result of db(condition).select())
        page: Page number (1-indexed)
        per_page: Number of records per page

    Returns:
        Tuple of (paginated_rows, pagination_info_dict)
        Pagination info contains: total_count, page, per_page, total_pages, has_next, has_prev
    """
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 20

    # Get total count
    total_count = query.count() if hasattr(query, 'count') else len(query)

    # Calculate pagination
    total_pages = (total_count + per_page - 1) // per_page
    offset = (page - 1) * per_page

    # Get paginated rows
    if hasattr(query, 'select'):
        rows = query.select(limitby=(offset, offset + per_page))
    else:
        rows = query[offset:offset + per_page]

    pagination_info = {
        'total_count': total_count,
        'page': page,
        'per_page': per_page,
        'total_pages': total_pages,
        'has_next': page < total_pages,
        'has_prev': page > 1,
    }

    return rows, pagination_info


def get_or_404(table: Any, record_id: int) -> Row:
    """
    Retrieve a record by ID, returning 404 if not found.

    Args:
        table: PyDAL table object
        record_id: ID of record to retrieve

    Returns:
        PyDAL Row object

    Raises:
        404 abort if record not found
    """
    if not isinstance(record_id, int) or record_id < 1:
        abort(400, description="Invalid record ID")

    row = table[record_id]
    if row is None:
        abort(404, description=f"{table._tablename} record not found")

    return row


def create_record(table: Any, **data) -> Row:
    """
    Create a new record in a table.

    Args:
        table: PyDAL table object
        **data: Field values for the new record

    Returns:
        PyDAL Row object with the created record (includes generated ID)
    """
    try:
        record_id = table.insert(**data)
        if record_id is None:
            raise ValueError("Failed to insert record")
        return table[record_id]
    except Exception as e:
        raise ValueError(f"Error creating record: {str(e)}")


def update_record(table: Any, record_id: int, **data) -> Row:
    """
    Update an existing record.

    Args:
        table: PyDAL table object
        record_id: ID of record to update
        **data: Fields to update

    Returns:
        Updated PyDAL Row object

    Raises:
        404 if record not found
        ValueError if update fails
    """
    row = get_or_404(table, record_id)

    try:
        table[record_id] = data
        # Refresh the row to get updated values
        return table[record_id]
    except Exception as e:
        raise ValueError(f"Error updating record: {str(e)}")


def soft_delete(
    table: Any,
    record_id: int,
    status_field: str = 'status'
) -> bool:
    """
    Soft delete a record by updating a status field.

    Args:
        table: PyDAL table object
        record_id: ID of record to soft delete
        status_field: Field name to update (default: 'status')

    Returns:
        True if soft delete succeeded

    Raises:
        404 if record not found
        ValueError if field doesn't exist or update fails
    """
    row = get_or_404(table, record_id)

    # Check if the field exists
    if status_field not in table.fields:
        raise ValueError(f"Field '{status_field}' does not exist in table")

    try:
        table[record_id] = {status_field: 'deleted'}
        return True
    except Exception as e:
        raise ValueError(f"Error soft deleting record: {str(e)}")


def count_active_resources(db: Any) -> int:
    """
    Count active (non-deleted) resources for license checking.

    Counts resources from the 'resources' table where status is not 'deleted'.
    Used for license validation and feature gating.

    Args:
        db: PyDAL database instance

    Returns:
        Count of active resources
    """
    try:
        # Ensure resources table exists
        if 'resources' not in db.tables:
            return 0

        resources_table = db.resources
        # Count where status != 'deleted'
        count = resources_table.id.count()
        result = db(
            resources_table.status != 'deleted'
        ).select(count)

        if result and len(result) > 0:
            return result[0]._extra[count] or 0
        return 0
    except Exception as e:
        # Return 0 on error to avoid blocking license checks
        return 0
