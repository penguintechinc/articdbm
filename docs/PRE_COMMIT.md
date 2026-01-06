# ArticDBM Pre-Commit Checklist

This checklist MUST be completed before every git commit. ArticDBM's hybrid Go proxy + Python manager architecture requires validation across both components.

## Quick Reference

```bash
# Run complete pre-commit validation
./scripts/pre-commit/pre-commit.sh

# Or execute step-by-step for debugging
make lint
make security-scan
make smoke-test
make test-unit
```

## Detailed Checklist

### Step 1: Linting (2-3 minutes)

Ensure ALL code passes linting standards. NO exceptions.

#### Go Proxy Linting

```bash
cd proxy
golangci-lint run ./...
# Must have zero warnings/errors
```

**Check**:
- ✅ No gofmt issues
- ✅ No staticcheck violations
- ✅ No gosec security warnings
- ✅ No unused imports or variables
- ✅ Comment formatting correct
- ✅ No ineffectual assignments

**Common Issues**:
```go
// Bad: unused variable
var unused string = "value"

// Good: remove if not used
value := "data"
_ = value  // if genuinely needed

// Bad: missing error handling
database := doSomething()

// Good: handle all errors
database, err := doSomething()
if err != nil {
    return fmt.Errorf("failed: %w", err)
}
```

#### Python Manager Linting

```bash
cd manager
# Code style
black . --check
isort . --check-only

# Complexity and style
flake8 . --max-line-length=100

# Type checking
mypy . --strict

# Security
bandit -r . -ll  # Only report issues
```

**Check**:
- ✅ Black formatting correct (88 char lines)
- ✅ isort import order correct
- ✅ flake8 no violations
- ✅ mypy all types annotated
- ✅ bandit no security issues
- ✅ PEP 8 compliance
- ✅ Docstrings present and formatted (PEP 257)

**Common Issues**:
```python
# Bad: missing type hints
def validate_query(q):
    return True

# Good: full type hints
def validate_query(q: str) -> bool:
    """Validate SQL query syntax.

    Args:
        q: SQL query string

    Returns:
        True if valid, False otherwise
    """
    return True

# Bad: unused import
import os
import sys  # not used
import json

# Good: clean imports
import json
import os
```

#### Docker Linting

```bash
hadolint proxy/Dockerfile manager/Dockerfile
```

**Check**:
- ✅ No invalid FROM statements
- ✅ Using debian-slim base (NOT alpine)
- ✅ Multi-stage builds where applicable
- ✅ No using latest tags

#### YAML & Markdown Linting

```bash
yamllint . -d relaxed
markdownlint docs/ --ignore docs/stylesheets
```

### Step 2: Security Scanning (3-5 minutes)

Scan ALL dependencies and code for vulnerabilities. Fix BEFORE committing.

#### Go Security Audit

```bash
cd proxy
gosec ./...
go list -json -m all | nancy sleuth  # or: go mod audit
```

**Check**:
- ✅ No G2xx (memory, SQL injection) violations
- ✅ No G5xx (command/code execution) violations
- ✅ All dependencies vulnerability-free
- ✅ No hardcoded credentials

**Common Issues**:
```go
// Bad: SQL injection vulnerability
query := "SELECT * FROM users WHERE id=" + userId

// Good: prepared statement
query := "SELECT * FROM users WHERE id=?"
result := db.Query(query, userId)

// Bad: hardcoded secret
password := "super_secret_123"

// Good: environment variable
password := os.Getenv("DATABASE_PASSWORD")
```

#### Python Security Audit

```bash
cd manager
bandit -r . -f json -o bandit-report.json
safety check
pip-audit
```

**Check**:
- ✅ No B2xx (SQL injection) violations
- ✅ No B5xx (process execution) violations
- ✅ All dependencies vulnerability-free
- ✅ No hardcoded passwords or API keys

**Common Issues**:
```python
# Bad: SQL injection
query = f"SELECT * FROM users WHERE email='{user_email}'"

# Good: parameterized query
query = "SELECT * FROM users WHERE email=?"
cursor.execute(query, (user_email,))

# Bad: hardcoded credentials
api_key = "sk-proj-1234567890"

# Good: environment variable
api_key = os.getenv("OPENAI_API_KEY")
```

#### Dependency Vulnerability Check

```bash
# Go dependencies
go list -json -m all | nancy sleuth

# Python dependencies
pip list --outdated
```

### Step 3: No Secrets or Credentials (1 minute)

Verify NO credentials committed to repository.

```bash
# Scan for common patterns
git diff --cached | grep -E "password|api_key|secret|token|credential"

# Use specialized scanner
git-secrets scan
```

**Check**:
- ✅ No DATABASE_PASSWORD values
- ✅ No API keys (OpenAI, AWS, etc.)
- ✅ No JWT tokens or session IDs
- ✅ No email credentials
- ✅ No license keys (except examples)
- ✅ No private SSH keys

**If Found**: Do NOT commit. Remove and use environment variables instead.

### Step 4: Build & Containerization (5-10 minutes)

Verify all containers build successfully in Docker.

#### Build All Containers

```bash
# Clean build
docker-compose down -v
docker-compose build --no-cache

# Expected: Build complete for all services
```

**Check**:
- ✅ Proxy (Go) builds without errors
- ✅ Manager (Python) builds without errors
- ✅ All Dockerfiles use debian-slim base
- ✅ No build warnings
- ✅ Final image sizes reasonable

**Common Issues**:
```dockerfile
# Bad: Alpine base (not supported)
FROM alpine:latest

# Good: Debian slim base
FROM debian:bookworm-slim

# Bad: Latest tag (floating)
FROM python:latest

# Good: Pinned version
FROM python:3.12-slim
```

#### Verify Containers Start

```bash
docker-compose up -d
sleep 5
docker-compose ps

# Expected: All services "Up" and healthy
```

### Step 5: Smoke Tests (2-3 minutes)

Run mandatory smoke tests to verify core functionality.

```bash
make smoke-test
# Or run manually:
./tests/smoke/run-all.sh
```

**Tests Include**:
- [ ] **Build Verification**: Containers build successfully
- [ ] **Container Startup**: Services start and stay running
- [ ] **Proxy Health**: MySQL and PostgreSQL protocols respond
- [ ] **Manager API Health**: REST API responds to health check
- [ ] **Metrics Availability**: Prometheus metrics endpoint works
- [ ] **Database Connectivity**: Can query all supported DB types

**Expected Output**:
```
✓ Build smoke tests passed
✓ Container startup verified
✓ Proxy health check passed
✓ Manager API health check passed
✓ Metrics endpoint responding
✓ All smoke tests passed!
```

### Step 6: Unit & Integration Tests (5-10 minutes)

Run test suite for modified services only.

#### If modified: Proxy (Go)

```bash
cd proxy
go test ./... -v -race -cover
# Expected: All tests pass, coverage >80%
```

#### If modified: Manager (Python)

```bash
cd manager
pytest tests/unit/ -v --tb=short
pytest tests/integration/ -v --tb=short
# Expected: All tests pass, coverage >80%
```

#### Cross-Database Testing (if database code modified)

```bash
for db in postgres mysql sqlite galera; do
  DB_TYPE=$db make test-integration
done
# Expected: All tests pass on all 4 database types
```

### Step 7: API Testing (if endpoints modified)

Create and run API test scripts for modified endpoints.

**Location**: `tests/api/manager/` or `tests/api/proxy/`

**Example Test** (Manager API):
```bash
#!/bin/bash
# tests/api/manager/test_users_api.sh

echo "Testing POST /api/v1/users..."
curl -X POST http://localhost:8000/api/v1/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"email":"test@example.com","role":"viewer"}' \
  | jq .

echo "Testing GET /api/v1/users..."
curl -X GET http://localhost:8000/api/v1/users \
  -H "Authorization: Bearer $TOKEN" \
  | jq .
```

**Run All API Tests**:
```bash
tests/api/manager/test_users_api.sh
tests/api/manager/test_databases_api.sh
tests/api/proxy/test_proxy_health.sh
```

### Step 8: Version Update (1 minute)

Update version file if this is a release commit.

**Check**:
- ✅ Release commit: Update `.version` file
- ✅ Regular commit: Do NOT update version
- ✅ Version format correct: `vMajor.Minor.Patch`

**Update Version**:
```bash
# Increment build timestamp only
./scripts/version/update-version.sh

# Or increment specific component
./scripts/version/update-version.sh patch
./scripts/version/update-version.sh minor
./scripts/version/update-version.sh major
```

### Step 9: Documentation Check (2 minutes)

Verify documentation is complete and accurate.

**Check**:
- ✅ Code changes documented in relevant docs/*.md files
- ✅ API changes documented in docs/API_REFERENCE.md
- ✅ Architecture changes documented in docs/ARCHITECTURE.md
- ✅ CLAUDE.md updated if significant changes
- ✅ Markdown files spell-checked
- ✅ Links in docs are valid

## Pre-Commit Script

Run the automated pre-commit script:

```bash
./scripts/pre-commit/pre-commit.sh
```

**Script Actions**:
1. Runs linters (golangci-lint, flake8, hadolint, yamllint)
2. Scans for secrets (git-secrets, custom patterns)
3. Verifies no committed credentials
4. Builds all containers
5. Runs smoke tests
6. Executes unit tests
7. Checks version file changes
8. Validates Docker base images

**Output**: Summary log saved to `/tmp/pre-commit-articdbm-<epoch>/summary.log`

## Common Issues & Solutions

### Issue: Tests fail due to database connection

**Solution**:
```bash
# Ensure docker-compose running
docker-compose up -d

# Check database status
docker-compose ps | grep postgres
docker-compose logs postgres  # Check for errors

# Wait for database to be ready
sleep 10
```

### Issue: Port conflicts (3306, 5432, 8000, 9090 already in use)

**Solution**:
```bash
# Find what's using the port
lsof -i :3306  # Replace with actual port

# Kill the process (or use different port in docker-compose.override.yml)
kill -9 <PID>
```

### Issue: Python module import errors

**Solution**:
```bash
cd manager
pip install -r requirements.txt
# Or if using virtual env:
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Issue: Go module issues

**Solution**:
```bash
cd proxy
go clean -modcache
go mod download
go mod tidy
```

## Final Verification

Before running `git commit`:

```bash
# 1. Run pre-commit script
./scripts/pre-commit/pre-commit.sh

# 2. Verify all checks passed
cat /tmp/pre-commit-articdbm-*/summary.log

# 3. Stage changes (if all tests pass)
git add .

# 4. Commit with meaningful message
git commit -m "Your commit message

Detailed explanation of changes made.

- Feature 1
- Bug fix 2
- Security improvement 3"

# 5. Wait for CI/CD pipeline to pass
```

## When to Skip Linting (NEVER)

There are NO exceptions. ALL commits must pass:
- ✅ Linting
- ✅ Security scanning
- ✅ Smoke tests
- ✅ Unit tests

If something doesn't pass, FIX IT. Don't commit around it.

---

**Last Updated**: 2026-01-06
**Maintained by**: Penguin Tech Inc
**Template**: Penguin Tech Inc Project Template v1.3.0
