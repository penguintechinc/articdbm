# ArticDBM Testing & Validation Guide

This document outlines testing strategies, mock data injection, and validation procedures for ArticDBM's hybrid Go proxy + Python manager architecture.

## Testing Architecture

ArticDBM testing spans two independent services with different testing approaches:

### Go Proxy Testing
- Protocol-level testing (MySQL/PostgreSQL wire protocols)
- Connection pooling under load
- SQL injection detection accuracy
- Query routing and load balancing
- Threat intelligence integration

### Python Manager Testing
- REST API functionality
- User management and authentication
- Configuration management and distribution
- Audit logging and compliance
- License validation

### Integration Testing
- Proxy-Manager communication (gRPC/HTTP3)
- End-to-end query processing
- Multi-database consistency
- Threat intelligence feed processing
- Metrics and monitoring

## Mock Data & Test Fixtures

### Manager Mock Data (3-4 items per entity)

**Databases**:
```python
# test_databases.py
test_databases = [
    {"name": "prod_mysql", "type": "mysql", "host": "db1.internal", "port": 3306},
    {"name": "dev_postgres", "type": "postgres", "host": "localhost", "port": 5432},
    {"name": "cache_sqlite", "type": "sqlite", "path": "/data/cache.db"},
]
```

**Users**:
```python
# test_users.py
test_users = [
    {"email": "admin@example.com", "role": "admin", "active": True},
    {"email": "operator@example.com", "role": "operator", "active": True},
    {"email": "readonly@example.com", "role": "viewer", "active": True},
    {"email": "disabled@example.com", "role": "viewer", "active": False},
]
```

**API Keys**:
```python
# test_api_keys.py
test_api_keys = [
    {"user_id": 1, "name": "prod_key", "expiry": "2025-12-31"},
    {"user_id": 2, "name": "dev_key", "expiry": "2026-06-30"},
    {"user_id": 3, "name": "temp_token", "expiry": "2026-01-07"},
]
```

**Threat Intelligence Rules**:
```python
# test_threat_rules.py
test_threat_rules = [
    {"pattern": "UNION.*SELECT", "source": "custom", "severity": "HIGH"},
    {"pattern": "DROP.*TABLE", "source": "stix_feed", "severity": "CRITICAL"},
    {"ioc": "malware-c2.local", "source": "misp", "threat_type": "C2"},
    {"pattern": "xp_cmdshell", "source": "custom", "severity": "CRITICAL"},
]
```

## Unit Testing

### Go Proxy Unit Tests

**Location**: `proxy/internal/*/test.go`

**Required Coverage**:
- SQL injection detection patterns (40+ patterns)
- Connection pool lifecycle
- Query routing logic
- Metric collection
- Configuration reloading

**Example Test**:
```go
func TestSQLInjectionDetection(t *testing.T) {
    tests := []struct {
        query    string
        expected bool
    }{
        {"SELECT * FROM users WHERE id=1", false},
        {"SELECT * FROM users WHERE id=1 OR 1=1", true},
        {"SELECT * FROM users; DROP TABLE users;--", true},
    }
    // Run tests against all 40+ patterns
}
```

**Run Unit Tests**:
```bash
cd proxy
go test ./... -v -cover
golangci-lint run
gosec ./...
```

### Python Manager Unit Tests

**Location**: `manager/tests/unit/`

**Required Coverage**:
- API endpoint authentication
- User and API key management
- Database configuration validation
- Threat intelligence rule processing
- Audit log recording

**Example Test**:
```python
def test_user_creation_with_role():
    user = User.create(email="test@example.com", role="viewer")
    assert user.email == "test@example.com"
    assert user.role == "viewer"

def test_api_key_expiration():
    key = APIKey.create(user_id=1, expiry_date=datetime.now())
    assert key.is_expired() == False
```

**Run Unit Tests**:
```bash
cd manager
pytest tests/unit/ -v --cov=. --cov-report=html
bandit -r .
safety check
```

## Integration Testing

### Proxy-to-Database Integration

**Test Scenarios**:
1. **Multi-Database Consistency**
   - Same query on postgres, mysql, sqlite, galera
   - Verify identical results across all DB_TYPE values
   - Test with 4 sample records

2. **Connection Pooling**
   - Pool reaches 80% idle connections
   - Warmup pre-establishes 30% on startup
   - 3-minute connection lifetime enforced

3. **SQL Injection Blocking**
   - STIX feed patterns blocked in real-time
   - Custom threat rules applied
   - Safe queries pass through

4. **Query Routing**
   - Read operations route to read replicas
   - Write operations route to primary
   - Load balanced across multiple backends

**Run Integration Tests**:
```bash
make test-integration
# Runs proxy + manager + all 4 database types
```

### Manager REST API Integration

**Test Endpoints**:
- `POST /api/v1/auth/login` - User authentication
- `GET /api/v1/databases` - List managed databases
- `POST /api/v1/users` - Create user
- `POST /api/v1/api-keys` - Generate API key
- `PUT /api/v1/threat-rules/{id}` - Update threat rule
- `GET /api/v1/audit-logs` - Retrieve audit entries

**Example Test**:
```python
def test_api_database_listing():
    response = client.get(
        "/api/v1/databases",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert len(response.json) >= 3  # At least 3 test databases
```

## Smoke Tests (Mandatory)

**Purpose**: Verify basic functionality before full test suite

**Test Checklist**:
- [ ] **Build Verification**
  ```bash
  docker-compose build
  # Verify no build errors for proxy and manager
  ```

- [ ] **Container Startup**
  ```bash
  docker-compose up -d
  sleep 5
  docker-compose ps
  # Verify all services in "Up" state
  ```

- [ ] **Proxy Health**
  ```bash
  # Test MySQL protocol
  mysql -h localhost -P 3306 -u proxy_user -p"password" -e "SELECT 1"
  # Test PostgreSQL protocol
  psql -h localhost -U proxy_user -d postgres -c "SELECT 1"
  ```

- [ ] **Manager API Health**
  ```bash
  curl http://localhost:8000/api/health
  # Expect: {"status": "healthy"}
  ```

- [ ] **Metrics Availability**
  ```bash
  curl http://localhost:9090/metrics | grep articdbm_
  # Expect: articdbm_active_connections, articdbm_total_queries, etc.
  ```

**Run Smoke Tests**:
```bash
make smoke-test
# Or manually run all checks above
```

## Performance Testing

### Load Testing Proxy

**Tool**: `tests/performance/load_proxy.go`

**Scenarios**:
- 100 concurrent connections
- 1000 queries per second sustained
- Monitor CPU, memory, connection count
- Verify query latency < 10ms p99

```bash
go run tests/performance/load_proxy.go \
  -connections 100 \
  -duration 60s \
  -db postgres
```

### Stress Testing Manager

**Tool**: `tests/performance/stress_manager.py`

**Scenarios**:
- Rapid user creation (50/sec)
- Bulk threat rule updates (100 rules)
- Concurrent API key generation
- Verify response time < 500ms p99

```bash
python tests/performance/stress_manager.py \
  --users 100 \
  --duration 60 \
  --threat-rules 50
```

## Cross-Database Testing

**Critical**: All features MUST work identically across all DB_TYPE values

### Test Matrix

| Feature | PostgreSQL | MySQL | SQLite | Galera |
|---------|-----------|-------|--------|--------|
| User Management | ✅ | ✅ | ✅ | ✅ |
| API Key Storage | ✅ | ✅ | ✅ | ✅ |
| Audit Logging | ✅ | ✅ | ✅ | ✅ |
| Threat Rules | ✅ | ✅ | ✅ | ✅ |
| Configuration | ✅ | ✅ | ✅ | ✅ |

**Run Tests for All Databases**:
```bash
for db in postgres mysql sqlite galera; do
  echo "Testing DB_TYPE=$db"
  DB_TYPE=$db make test-integration
done
```

## Multi-Architecture Testing

Before final commit, test on alternate architecture using QEMU:

**If developing on amd64**:
```bash
docker buildx build --platform linux/arm64 \
  -t articdbm:arm64-test \
  --load .
docker run articdbm:arm64-test make smoke-test
```

**If developing on arm64**:
```bash
docker buildx build --platform linux/amd64 \
  -t articdbm:amd64-test \
  --load .
docker run articdbm:amd64-test make smoke-test
```

**Multi-Architecture Build** (before release):
```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t articdbm:latest \
  --push .
```

## Test Execution Order (Pre-Commit)

1. **Unit Tests** (Go + Python) - < 30 seconds
   ```bash
   make test-unit
   ```

2. **Linting & Security** (No tests required, instant)
   ```bash
   make lint
   make security-scan
   ```

3. **Smoke Tests** - < 2 minutes
   ```bash
   make smoke-test
   ```

4. **Integration Tests** - < 5 minutes
   ```bash
   make test-integration
   ```

5. **E2E Tests** (optional, longer)
   ```bash
   make test-e2e
   ```

**Total Pre-Commit Time**: ~10 minutes

## Continuous Testing

**CI/CD Pipeline**:
- GitHub Actions runs full test suite on every PR
- All tests must pass before merge to main
- Smoke tests run on every commit
- Nightly performance tests verify stability

**Local Development**:
```bash
# Watch for changes and auto-test
make watch-test

# Or manually re-run after changes
make test
```

---

**Last Updated**: 2026-01-06
**Maintained by**: Penguin Tech Inc
