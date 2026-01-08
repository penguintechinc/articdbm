#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration from environment
POSTGRES_HOST=${POSTGRES_HOST:-postgres}
POSTGRES_PORT=${POSTGRES_PORT:-5432}
POSTGRES_DB=${POSTGRES_DB:-articdbm}
POSTGRES_USER=${POSTGRES_USER:-postgres}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-}

REDIS_HOST=${REDIS_HOST:-redis}
REDIS_PORT=${REDIS_PORT:-6379}
REDIS_PASSWORD=${REDIS_PASSWORD:-}

MAX_RETRIES=${MAX_RETRIES:-30}
RETRY_DELAY=${RETRY_DELAY:-2}

# Wait for PostgreSQL
log_info "Waiting for PostgreSQL at $POSTGRES_HOST:$POSTGRES_PORT..."
RETRIES=0
while [ $RETRIES -lt $MAX_RETRIES ]; do
    if pg_isready -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U "$POSTGRES_USER" >/dev/null 2>&1; then
        log_info "PostgreSQL is ready!"
        break
    fi
    RETRIES=$((RETRIES + 1))
    if [ $RETRIES -eq $MAX_RETRIES ]; then
        log_error "PostgreSQL did not become ready after $((MAX_RETRIES * RETRY_DELAY)) seconds"
        exit 1
    fi
    log_warn "PostgreSQL not ready yet (attempt $RETRIES/$MAX_RETRIES), retrying in ${RETRY_DELAY}s..."
    sleep "$RETRY_DELAY"
done

# Wait for Redis
log_info "Waiting for Redis at $REDIS_HOST:$REDIS_PORT..."
RETRIES=0
while [ $RETRIES -lt $MAX_RETRIES ]; do
    if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" $([ -n "$REDIS_PASSWORD" ] && echo "-a $REDIS_PASSWORD") ping >/dev/null 2>&1; then
        log_info "Redis is ready!"
        break
    fi
    RETRIES=$((RETRIES + 1))
    if [ $RETRIES -eq $MAX_RETRIES ]; then
        log_error "Redis did not become ready after $((MAX_RETRIES * RETRY_DELAY)) seconds"
        exit 1
    fi
    log_warn "Redis not ready yet (attempt $RETRIES/$MAX_RETRIES), retrying in ${RETRY_DELAY}s..."
    sleep "$RETRY_DELAY"
done

# Run database migrations if needed
log_info "Running database migrations..."
if [ -f "/app/migrate.py" ]; then
    python /app/migrate.py || log_warn "Migration script not found or failed, continuing..."
else
    log_warn "No migration script found at /app/migrate.py, skipping migrations"
fi

# Start gRPC server in background (if applicable)
log_info "Starting gRPC server in background..."
if [ -f "/app/grpc_server.py" ]; then
    python /app/grpc_server.py &
    GRPC_PID=$!
    log_info "gRPC server started with PID $GRPC_PID"
else
    log_warn "No gRPC server found at /app/grpc_server.py, skipping"
fi

# Start Flask application with gunicorn
log_info "Starting Flask application with gunicorn..."
WORKERS=${WORKERS:-4}
THREADS=${THREADS:-2}
TIMEOUT=${TIMEOUT:-120}
BIND=${BIND:-0.0.0.0:8000}

exec gunicorn \
    --workers "$WORKERS" \
    --threads "$THREADS" \
    --worker-class gthread \
    --bind "$BIND" \
    --timeout "$TIMEOUT" \
    --access-logfile - \
    --error-logfile - \
    --log-level info \
    wsgi:app
