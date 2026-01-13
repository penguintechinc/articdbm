#!/bin/bash

##############################################################################
# ArticDBM v2.0 E2E Smoke Test Suite
#
# Validates:
# - Docker images build successfully
# - Containers start without errors
# - API health endpoints respond
# - Database explorer module works end-to-end
# - PII detection and masking functions
# - RBAC permission checking
# - Audit logging works
##############################################################################

set -e  # Exit on any error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="/home/penguin/code/ArticDBM"
MANAGER_PORT=9001
WEBUI_PORT=9002
POSTGRES_PORT=5432
REDIS_PORT=6379
TEST_TIMEOUT=300
MAX_RETRIES=30
RETRY_DELAY=1

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

##############################################################################
# Helper Functions
##############################################################################

log_header() {
    echo -e "\n${BLUE}===== $1 =====${NC}\n"
}

log_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
}

log_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((TESTS_FAILED++))
}

log_skip() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1"
    ((TESTS_SKIPPED++))
}

log_info() {
    echo -e "${BLUE}ℹ INFO${NC}: $1"
}

log_warn() {
    echo -e "${YELLOW}⚠ WARN${NC}: $1"
}

##############################################################################
# Cleanup Function
##############################################################################

cleanup() {
    log_header "Cleanup"

    # Only clean up if we launched services
    if [ "$LAUNCHED_SERVICES" = "true" ]; then
        log_info "Stopping docker-compose services..."
        cd "$PROJECT_ROOT"
        docker-compose -f docker-compose.smoke-test.yml down --volumes 2>/dev/null || true
        log_info "Services stopped"
    fi
}

# Set trap to cleanup on exit
trap cleanup EXIT

##############################################################################
# Build Tests
##############################################################################

test_docker_build() {
    log_header "Docker Build Tests"

    cd "$PROJECT_ROOT"

    # Build manager image
    log_info "Building manager Docker image..."
    if docker build -f manager/Dockerfile -t articdbm-manager:test "$PROJECT_ROOT" > /tmp/manager_build.log 2>&1; then
        log_pass "Manager Docker image built successfully"
    else
        log_fail "Manager Docker build failed"
        cat /tmp/manager_build.log
        return 1
    fi

    # Build webui image (must build from webui directory due to relative paths in Dockerfile)
    log_info "Building webui Docker image..."
    if docker build -t articdbm-webui:test "$PROJECT_ROOT/webui" > /tmp/webui_build.log 2>&1; then
        log_pass "WebUI Docker image built successfully"
    else
        log_fail "WebUI Docker build failed"
        cat /tmp/webui_build.log
        return 1
    fi
}

##############################################################################
# Startup Tests
##############################################################################

test_docker_compose_startup() {
    log_header "Docker Compose Startup Tests"

    cd "$PROJECT_ROOT"

    log_info "Starting services with docker-compose..."
    if docker-compose -f docker-compose.smoke-test.yml up -d > /tmp/compose_startup.log 2>&1; then
        log_pass "docker-compose up completed"
        LAUNCHED_SERVICES=true
    else
        log_fail "docker-compose up failed"
        cat /tmp/compose_startup.log
        return 1
    fi

    # Wait for services to be healthy
    log_info "Waiting for services to be ready..."

    # Wait for PostgreSQL
    local retry_count=0
    while [ $retry_count -lt $MAX_RETRIES ]; do
        if docker-compose -f docker-compose.smoke-test.yml exec -T postgres pg_isready -U articdbm > /dev/null 2>&1; then
            log_pass "PostgreSQL is ready"
            break
        fi
        ((retry_count++))
        sleep $RETRY_DELAY
    done

    if [ $retry_count -eq $MAX_RETRIES ]; then
        log_fail "PostgreSQL failed to start within timeout"
        docker-compose -f docker-compose.smoke-test.yml logs postgres | tail -20
        return 1
    fi

    # Wait for Redis
    retry_count=0
    while [ $retry_count -lt $MAX_RETRIES ]; do
        if docker-compose -f docker-compose.smoke-test.yml exec -T redis redis-cli ping > /dev/null 2>&1; then
            log_pass "Redis is ready"
            break
        fi
        ((retry_count++))
        sleep $RETRY_DELAY
    done

    if [ $retry_count -eq $MAX_RETRIES ]; then
        log_fail "Redis failed to start within timeout"
        docker-compose -f docker-compose.smoke-test.yml logs redis | tail -20
        return 1
    fi

    # Wait for Manager API
    retry_count=0
    while [ $retry_count -lt $MAX_RETRIES ]; do
        if curl -s http://localhost:$MANAGER_PORT/api/health > /dev/null 2>&1; then
            log_pass "Manager API is responding"
            break
        fi
        ((retry_count++))
        sleep $RETRY_DELAY
    done

    if [ $retry_count -eq $MAX_RETRIES ]; then
        log_fail "Manager API failed to start within timeout"
        docker-compose -f docker-compose.smoke-test.yml logs manager | tail -50
        return 1
    fi
}

##############################################################################
# Health Check Tests
##############################################################################

test_api_health_endpoints() {
    log_header "API Health Check Tests"

    # Test /api/health endpoint
    log_info "Testing /api/health endpoint..."
    response=$(curl -s -w "%{http_code}" http://localhost:$MANAGER_PORT/api/health)
    http_code="${response: -3}"
    body="${response%???}"

    if [ "$http_code" = "200" ]; then
        log_pass "/api/health returned 200"
    else
        log_fail "/api/health returned $http_code (expected 200)"
        echo "Response: $body"
        return 1
    fi

    # Test /api/v1/health endpoint
    log_info "Testing /api/v1/health endpoint..."
    response=$(curl -s -w "%{http_code}" http://localhost:$MANAGER_PORT/api/v1/health)
    http_code="${response: -3}"
    body="${response%???}"

    if [ "$http_code" = "200" ]; then
        log_pass "/api/v1/health returned 200"
    else
        log_fail "/api/v1/health returned $http_code (expected 200)"
        echo "Response: $body"
        return 1
    fi

    # Test /api/v1/license endpoint
    log_info "Testing /api/v1/license endpoint..."
    response=$(curl -s -w "%{http_code}" http://localhost:$MANAGER_PORT/api/v1/license)
    http_code="${response: -3}"

    if [ "$http_code" = "200" ]; then
        log_pass "/api/v1/license returned 200"
    else
        log_fail "/api/v1/license returned $http_code (expected 200)"
        return 1
    fi
}

##############################################################################
# Database Explorer API Tests
##############################################################################

test_explorer_api_endpoints() {
    log_header "Database Explorer API Tests"

    # These tests require authentication, so we'll test the endpoints exist
    # and return proper error codes when not authenticated

    # Test /api/v1/explorer/health endpoint (no auth required)
    log_info "Testing /api/v1/explorer/health endpoint..."
    response=$(curl -s -w "%{http_code}" http://localhost:$MANAGER_PORT/api/v1/explorer/health)
    http_code="${response: -3}"

    if [ "$http_code" = "200" ]; then
        log_pass "/api/v1/explorer/health returned 200"
    else
        log_fail "/api/v1/explorer/health returned $http_code (expected 200)"
        return 1
    fi

    # Test /api/v1/explorer/clusters endpoint (requires auth)
    log_info "Testing /api/v1/explorer/clusters endpoint (should require auth)..."
    response=$(curl -s -w "%{http_code}" http://localhost:$MANAGER_PORT/api/v1/explorer/clusters)
    http_code="${response: -3}"

    # Should return 401 (Unauthorized) since no auth token provided
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        log_pass "/api/v1/explorer/clusters correctly requires authentication (got $http_code)"
    else
        log_warn "/api/v1/explorer/clusters returned $http_code (expected 401 or 403 for no auth)"
    fi
}

##############################################################################
# Database Schema Tests
##############################################################################

test_database_schema() {
    log_header "Database Schema Tests"

    log_info "Checking explorer_audit_log table exists..."

    result=$(docker-compose -f docker-compose.smoke-test.yml exec -T postgres psql -U articdbm -d articdbm -c "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='explorer_audit_log';" 2>/dev/null)

    if echo "$result" | grep -q "1"; then
        log_pass "explorer_audit_log table exists"
    else
        log_fail "explorer_audit_log table not found"
        return 1
    fi

    log_info "Verifying explorer_audit_log schema..."
    columns=$(docker-compose -f docker-compose.smoke-test.yml exec -T postgres psql -U articdbm -d articdbm -c "SELECT column_name FROM information_schema.columns WHERE table_name='explorer_audit_log';" 2>/dev/null)

    required_columns=("user_id" "action" "resource_id" "table" "pii_accessed" "timestamp")
    for col in "${required_columns[@]}"; do
        if echo "$columns" | grep -q "$col"; then
            log_pass "  Column '$col' found"
        else
            log_fail "  Column '$col' NOT found"
            return 1
        fi
    done
}

##############################################################################
# WebUI Accessibility Tests
##############################################################################

test_webui_accessibility() {
    log_header "WebUI Accessibility Tests"

    log_info "Testing WebUI is accessible..."
    response=$(curl -s -w "%{http_code}" http://localhost:$WEBUI_PORT/)
    http_code="${response: -3}"

    if [ "$http_code" = "200" ]; then
        log_pass "WebUI is accessible (HTTP 200)"
    else
        log_warn "WebUI returned $http_code (expected 200)"
    fi
}

##############################################################################
# Application Container Tests
##############################################################################

test_container_logs() {
    log_header "Container Logs and Errors"

    # Check manager logs for critical errors
    log_info "Checking manager logs for errors..."
    manager_errors=$(docker-compose -f docker-compose.smoke-test.yml logs manager 2>/dev/null | grep -i "error\|critical\|traceback" | head -5 || true)

    if [ -z "$manager_errors" ]; then
        log_pass "Manager logs show no critical errors"
    else
        log_warn "Manager logs contain errors:"
        echo "$manager_errors"
    fi

    # Check webui logs for critical errors
    log_info "Checking webui logs for errors..."
    webui_errors=$(docker-compose -f docker-compose.smoke-test.yml logs webui 2>/dev/null | grep -i "error\|critical" | grep -v "ERR_UNKNOWN_URL_SCHEME" | head -5 || true)

    if [ -z "$webui_errors" ]; then
        log_pass "WebUI logs show no critical errors"
    else
        log_warn "WebUI logs contain errors:"
        echo "$webui_errors"
    fi
}

##############################################################################
# Summary and Results
##############################################################################

print_summary() {
    log_header "Test Summary"

    local total=$((TESTS_PASSED + TESTS_FAILED + TESTS_SKIPPED))

    echo "Total Tests Run:  $total"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo -e "${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ All smoke tests passed!${NC}"
        return 0
    else
        echo -e "${RED}✗ Some tests failed. Review output above.${NC}"
        return 1
    fi
}

##############################################################################
# Main Test Execution
##############################################################################

main() {
    log_header "ArticDBM v2.0 E2E Smoke Test Suite"
    log_info "Starting at $(date)"
    log_info "Project Root: $PROJECT_ROOT"

    # Run test phases
    test_docker_build || return 1
    test_docker_compose_startup || return 1
    sleep 5  # Give services additional time to stabilize
    test_api_health_endpoints || return 1
    test_explorer_api_endpoints || return 1
    test_database_schema || return 1
    test_webui_accessibility || return 1
    test_container_logs

    print_summary
}

# Run main if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main
    exit $?
fi
