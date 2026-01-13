"""Flask Blueprint for Apache Iceberg catalog and table management endpoints.

Provides comprehensive Iceberg operations including:
- Create, read, update, delete catalogs
- Table management (create, update, delete, list)
- Catalog configuration for multiple backends (Hive, Glue, REST, JDBC, Nessie)
- Table schema and metadata management
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from flask import Blueprint, request, jsonify, current_app
from flask_security import login_required, current_user
from pydantic import ValidationError as PydanticValidationError

from app.schemas.iceberg import (
    IcebergCatalogCreate,
    IcebergCatalogUpdate,
    IcebergCatalogResponse,
    IcebergCatalogListResponse,
    IcebergTableCreate,
    IcebergTableUpdate,
    IcebergTableResponse,
)

logger = logging.getLogger(__name__)

iceberg_bp = Blueprint(
    "iceberg",
    __name__,
    url_prefix="/iceberg",
    description="Apache Iceberg catalog and table management endpoints",
)


@iceberg_bp.route("", methods=["GET"])
@login_required
def list_iceberg_catalogs() -> Tuple[Dict[str, Any], int]:
    """
    List Iceberg catalogs with pagination and filtering.

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20, max: 100)
        catalog_type (str): Filter by catalog type
        sort_by (str): Sort field (created_at, name)
        sort_order (str): Sort order (asc, desc)

    Returns:
        JSON response with paginated catalog list
    """
    try:
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 20, type=int)
        catalog_type = request.args.get("catalog_type", type=str)
        sort_by = request.args.get("sort_by", "created_at", type=str)
        sort_order = request.args.get("sort_order", "desc", type=str)

        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 20

        valid_sort_fields = ["created_at", "name"]
        if sort_by not in valid_sort_fields:
            sort_by = "created_at"
        if sort_order not in ["asc", "desc"]:
            sort_order = "desc"

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        query = db.iceberg_catalogs.is_active == True

        if catalog_type:
            query = query & (db.iceberg_catalogs.catalog_type == catalog_type)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        catalogs = db(query).select(
            orderby=getattr(db.iceberg_catalogs, sort_by)
            if sort_order == "asc"
            else ~getattr(db.iceberg_catalogs, sort_by),
            limitby=(offset, offset + page_size),
        )

        catalog_list = [_catalog_row_to_response(c) for c in catalogs]

        response_data = {
            "catalogs": catalog_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error listing Iceberg catalogs: {e}")
        return jsonify({"error": "Failed to list catalogs"}), 500


@iceberg_bp.route("", methods=["POST"])
@login_required
def create_iceberg_catalog() -> Tuple[Dict[str, Any], int]:
    """
    Create a new Iceberg catalog.

    Request Body (JSON):
        name (str): Catalog name
        catalog_type (str): Catalog type (hive, glue, rest, jdbc, nessie)
        warehouse_location (str): Warehouse path
        description (str, optional): Catalog description
        hive_metastore_uri (str, optional): Hive metastore URI
        glue_catalog_id (str, optional): AWS Glue catalog ID
        rest_catalog_uri (str, optional): REST catalog URI
        compression_codec (str, optional): Compression codec
        enable_statistics (bool): Enable column statistics
        tags (dict, optional): Catalog tags

    Returns:
        201 Created response with catalog details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            catalog_create = IcebergCatalogCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Services not initialized"}), 500

        catalog_id = db.iceberg_catalogs.insert(
            name=catalog_create.name,
            catalog_type=catalog_create.catalog_type.value,
            warehouse_location=catalog_create.warehouse_location,
            description=catalog_create.description,
            hive_metastore_uri=catalog_create.hive_metastore_uri,
            glue_catalog_id=catalog_create.glue_catalog_id,
            glue_region=catalog_create.glue_region,
            rest_catalog_uri=catalog_create.rest_catalog_uri,
            rest_catalog_auth_type=catalog_create.rest_catalog_auth_type,
            jdbc_driver_class=catalog_create.jdbc_driver_class,
            jdbc_connection_url=catalog_create.jdbc_connection_url,
            nessie_server_uri=catalog_create.nessie_server_uri,
            nessie_auth_type=catalog_create.nessie_auth_type,
            storage_type=catalog_create.storage_type,
            storage_endpoint=catalog_create.storage_endpoint,
            io_impl=catalog_create.io_impl,
            compression_codec=catalog_create.compression_codec,
            enable_statistics=catalog_create.enable_statistics,
            enable_parquet_bloom_filter=catalog_create.enable_parquet_bloom_filter,
            enable_s3_access_grants=catalog_create.enable_s3_access_grants,
            enable_manifest_caching=catalog_create.enable_manifest_caching,
            manifest_cache_ttl_minutes=catalog_create.manifest_cache_ttl_minutes,
            tls_enabled=catalog_create.tls_enabled,
            tls_verify=catalog_create.tls_verify,
            tags=catalog_create.tags,
            is_active=True,
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        catalog = db(db.iceberg_catalogs.id == catalog_id).select().first()
        response_data = _catalog_row_to_response(catalog)

        logger.info(
            f"Iceberg catalog created: {catalog_create.name} "
            f"(id: {catalog_id}, user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating Iceberg catalog: {e}")
        return jsonify({"error": "Failed to create catalog"}), 500


@iceberg_bp.route("/<catalog_id>", methods=["GET"])
@login_required
def get_iceberg_catalog(catalog_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get Iceberg catalog details.

    Path Parameters:
        catalog_id (str): Catalog ID

    Returns:
        JSON response with catalog details
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        response_data = _catalog_row_to_response(catalog)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting Iceberg catalog {catalog_id}: {e}")
        return jsonify({"error": "Failed to get catalog"}), 500


@iceberg_bp.route("/<catalog_id>", methods=["PUT"])
@login_required
def update_iceberg_catalog(catalog_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update Iceberg catalog configuration.

    Path Parameters:
        catalog_id (str): Catalog ID

    Request Body (JSON):
        warehouse_location (str, optional): New warehouse location
        description (str, optional): Updated description
        compression_codec (str, optional): New compression codec
        enable_statistics (bool, optional): Update statistics
        tags (dict, optional): Updated tags

    Returns:
        JSON response with updated catalog details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            catalog_update = IcebergCatalogUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        update_data = {"updated_at": datetime.utcnow()}

        if catalog_update.warehouse_location is not None:
            update_data["warehouse_location"] = catalog_update.warehouse_location

        if catalog_update.description is not None:
            update_data["description"] = catalog_update.description

        if catalog_update.storage_endpoint is not None:
            update_data["storage_endpoint"] = catalog_update.storage_endpoint

        if catalog_update.compression_codec is not None:
            update_data["compression_codec"] = catalog_update.compression_codec

        if catalog_update.enable_statistics is not None:
            update_data["enable_statistics"] = catalog_update.enable_statistics

        if catalog_update.enable_parquet_bloom_filter is not None:
            update_data["enable_parquet_bloom_filter"] = catalog_update.enable_parquet_bloom_filter

        if catalog_update.tags is not None:
            update_data["tags"] = catalog_update.tags

        db(db.iceberg_catalogs.id == catalog_id).update(**update_data)
        db.commit()

        updated_catalog = db(db.iceberg_catalogs.id == catalog_id).select().first()
        response_data = _catalog_row_to_response(updated_catalog)

        logger.info(f"Iceberg catalog updated: {catalog_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating Iceberg catalog {catalog_id}: {e}")
        return jsonify({"error": "Failed to update catalog"}), 500


@iceberg_bp.route("/<catalog_id>", methods=["DELETE"])
@login_required
def delete_iceberg_catalog(catalog_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete Iceberg catalog (soft delete - mark as inactive).

    Path Parameters:
        catalog_id (str): Catalog ID

    Returns:
        JSON response with deletion status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        db(db.iceberg_catalogs.id == catalog_id).update(
            is_active=False,
            updated_at=datetime.utcnow(),
        )
        db.commit()

        logger.info(f"Iceberg catalog deleted: {catalog_id} (user: {current_user.email})")

        return jsonify({"id": catalog_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting Iceberg catalog {catalog_id}: {e}")
        return jsonify({"error": "Failed to delete catalog"}), 500


@iceberg_bp.route("/<catalog_id>/tables", methods=["GET"])
@login_required
def list_iceberg_tables(catalog_id: str) -> Tuple[Dict[str, Any], int]:
    """
    List Iceberg tables in a catalog.

    Path Parameters:
        catalog_id (str): Catalog ID

    Query Parameters:
        page (int): Page number (default: 1)
        page_size (int): Items per page (default: 20)
        database (str): Filter by database name

    Returns:
        JSON response with paginated table list
    """
    try:
        page = request.args.get("page", 1, type=int)
        page_size = request.args.get("page_size", 20, type=int)
        database = request.args.get("database", type=str)

        if page < 1:
            page = 1
        if page_size < 1 or page_size > 100:
            page_size = 20

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        query = db.iceberg_tables.catalog_id == catalog_id

        if database:
            query = query & (db.iceberg_tables.database == database)

        total = db(query).count()
        total_pages = (total + page_size - 1) // page_size
        offset = (page - 1) * page_size

        tables = db(query).select(
            orderby=~db.iceberg_tables.created_at,
            limitby=(offset, offset + page_size),
        )

        table_list = [_table_row_to_response(t) for t in tables]

        response_data = {
            "tables": table_list,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_previous": page > 1,
        }

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error listing Iceberg tables for catalog {catalog_id}: {e}")
        return jsonify({"error": "Failed to list tables"}), 500


@iceberg_bp.route("/<catalog_id>/tables", methods=["POST"])
@login_required
def create_iceberg_table(catalog_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Create a new Iceberg table in a catalog.

    Path Parameters:
        catalog_id (str): Catalog ID

    Request Body (JSON):
        table_name (str): Table name
        database (str): Database name
        schema (dict): Table schema (column definitions)
        location (str, optional): Table location path
        format (str, optional): Data format (parquet, avro, orc)
        partitioning (list, optional): Partitioning spec
        properties (dict, optional): Table properties

    Returns:
        201 Created response with table details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            table_create = IcebergTableCreate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        table_id = db.iceberg_tables.insert(
            catalog_id=catalog_id,
            table_name=table_create.table_name,
            database=table_create.database,
            schema_definition=table_create.schema,
            location=table_create.location,
            format=table_create.format or "parquet",
            partitioning=table_create.partitioning,
            properties=table_create.properties,
            created_by=current_user.id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.commit()

        table = db(db.iceberg_tables.id == table_id).select().first()
        response_data = _table_row_to_response(table)

        logger.info(
            f"Iceberg table created: {table_create.table_name} "
            f"in catalog {catalog_id} (user: {current_user.email})"
        )

        return jsonify(response_data), 201

    except Exception as e:
        logger.error(f"Error creating Iceberg table in catalog {catalog_id}: {e}")
        return jsonify({"error": "Failed to create table"}), 500


@iceberg_bp.route("/<catalog_id>/tables/<table_id>", methods=["GET"])
@login_required
def get_iceberg_table(catalog_id: str, table_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Get Iceberg table details.

    Path Parameters:
        catalog_id (str): Catalog ID
        table_id (str): Table ID

    Returns:
        JSON response with table details and schema
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        table = db(
            (db.iceberg_tables.id == table_id)
            & (db.iceberg_tables.catalog_id == catalog_id)
        ).select().first()

        if not table:
            return jsonify({"error": "Table not found"}), 404

        response_data = _table_row_to_response(table)
        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error getting Iceberg table {table_id}: {e}")
        return jsonify({"error": "Failed to get table"}), 500


@iceberg_bp.route("/<catalog_id>/tables/<table_id>", methods=["PUT"])
@login_required
def update_iceberg_table(catalog_id: str, table_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Update Iceberg table configuration.

    Path Parameters:
        catalog_id (str): Catalog ID
        table_id (str): Table ID

    Request Body (JSON):
        properties (dict, optional): Updated table properties

    Returns:
        JSON response with updated table details
    """
    try:
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 400

        request_data = request.get_json()

        try:
            table_update = IcebergTableUpdate(**request_data)
        except PydanticValidationError as e:
            logger.warning(f"Validation error: {e}")
            return jsonify({"error": "Validation failed"}), 422

        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        table = db(
            (db.iceberg_tables.id == table_id)
            & (db.iceberg_tables.catalog_id == catalog_id)
        ).select().first()

        if not table:
            return jsonify({"error": "Table not found"}), 404

        update_data = {"updated_at": datetime.utcnow()}

        if table_update.properties is not None:
            update_data["properties"] = table_update.properties

        db(db.iceberg_tables.id == table_id).update(**update_data)
        db.commit()

        updated_table = db(db.iceberg_tables.id == table_id).select().first()
        response_data = _table_row_to_response(updated_table)

        logger.info(f"Iceberg table updated: {table_id} (user: {current_user.email})")

        return jsonify(response_data), 200

    except Exception as e:
        logger.error(f"Error updating Iceberg table {table_id}: {e}")
        return jsonify({"error": "Failed to update table"}), 500


@iceberg_bp.route("/<catalog_id>/tables/<table_id>", methods=["DELETE"])
@login_required
def delete_iceberg_table(catalog_id: str, table_id: str) -> Tuple[Dict[str, Any], int]:
    """
    Delete an Iceberg table from a catalog.

    Path Parameters:
        catalog_id (str): Catalog ID
        table_id (str): Table ID

    Returns:
        JSON response with deletion status
    """
    try:
        db = current_app.extensions.get("db")
        if not db:
            return jsonify({"error": "Database not initialized"}), 500

        catalog = db(
            (db.iceberg_catalogs.id == catalog_id) & (db.iceberg_catalogs.is_active == True)
        ).select().first()

        if not catalog:
            return jsonify({"error": "Catalog not found"}), 404

        table = db(
            (db.iceberg_tables.id == table_id)
            & (db.iceberg_tables.catalog_id == catalog_id)
        ).select().first()

        if not table:
            return jsonify({"error": "Table not found"}), 404

        db(db.iceberg_tables.id == table_id).delete()
        db.commit()

        logger.info(f"Iceberg table deleted: {table_id} (user: {current_user.email})")

        return jsonify({"id": table_id, "status": "deleted"}), 200

    except Exception as e:
        logger.error(f"Error deleting Iceberg table {table_id}: {e}")
        return jsonify({"error": "Failed to delete table"}), 500


def _catalog_row_to_response(catalog_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL catalog row to response format.

    Args:
        catalog_row: PyDAL database row

    Returns:
        Dictionary matching IcebergCatalogResponse schema
    """
    return {
        "id": catalog_row.id,
        "name": catalog_row.name,
        "catalog_type": catalog_row.catalog_type,
        "warehouse_location": catalog_row.warehouse_location,
        "description": catalog_row.description,
        "hive_metastore_uri": getattr(catalog_row, "hive_metastore_uri", None),
        "glue_catalog_id": getattr(catalog_row, "glue_catalog_id", None),
        "rest_catalog_uri": getattr(catalog_row, "rest_catalog_uri", None),
        "storage_type": getattr(catalog_row, "storage_type", None),
        "compression_codec": catalog_row.compression_codec,
        "enable_statistics": catalog_row.enable_statistics,
        "enable_parquet_bloom_filter": catalog_row.enable_parquet_bloom_filter,
        "enable_s3_access_grants": catalog_row.enable_s3_access_grants,
        "enable_manifest_caching": catalog_row.enable_manifest_caching,
        "manifest_cache_ttl_minutes": catalog_row.manifest_cache_ttl_minutes,
        "tls_enabled": catalog_row.tls_enabled,
        "tls_verify": catalog_row.tls_verify,
        "tags": catalog_row.tags or {},
        "is_active": catalog_row.is_active,
        "created_at": catalog_row.created_at.isoformat()
        if hasattr(catalog_row.created_at, "isoformat")
        else catalog_row.created_at,
        "updated_at": catalog_row.updated_at.isoformat()
        if hasattr(catalog_row.updated_at, "isoformat")
        else catalog_row.updated_at,
    }


def _table_row_to_response(table_row: Any) -> Dict[str, Any]:
    """
    Convert a PyDAL table row to response format.

    Args:
        table_row: PyDAL database row

    Returns:
        Dictionary matching IcebergTableResponse schema
    """
    return {
        "id": table_row.id,
        "catalog_id": table_row.catalog_id,
        "table_name": table_row.table_name,
        "database": table_row.database,
        "schema": getattr(table_row, "schema_definition", {}),
        "location": table_row.location,
        "format": table_row.format,
        "partitioning": table_row.partitioning or [],
        "properties": table_row.properties or {},
        "created_at": table_row.created_at.isoformat()
        if hasattr(table_row.created_at, "isoformat")
        else table_row.created_at,
        "updated_at": table_row.updated_at.isoformat()
        if hasattr(table_row.updated_at, "isoformat")
        else table_row.updated_at,
    }
