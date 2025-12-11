# ArticDBM Development Standards

Comprehensive development, testing, and deployment standards for ArticDBM project.

## Table of Contents

1. [Code Quality Standards](#code-quality-standards)
2. [CI/CD Pipeline](#cicd-pipeline)
3. [Security Requirements](#security-requirements)
4. [Testing Standards](#testing-standards)
5. [Documentation Standards](#documentation-standards)
6. [Deployment Requirements](#deployment-requirements)

---

## Code Quality Standards

### Go (Proxy Service)

**Language Version:** Go 1.23.x (latest patch)

**Required Linting:**
```bash
cd proxy
golangci-lint run --deadline=5m
```

**Linter Configurations:**
- staticcheck (enables multiple checks)
- gosec (security analyzer)
- govet (Go vet)
- errcheck (error checking)
- ineffassign (ineffective assignments)
- unused (unused identifiers)
- shadow (variable shadowing)

**Code Style:**
- Format with `gofmt` (enforced by golangci-lint)
- Use CamelCase for exported symbols
- Document exported functions and types
- Use interfaces for abstraction
- Handle errors explicitly (no silent failures)

**Common Issues:**
- Unhandled error returns: FAIL build
- SQL injection in dynamic queries: Use prepared statements
- Hardcoded credentials: Use environment variables
- Insecure TLS: Enforce TLS 1.2+

### Python (Manager Service)

**Language Version:** Python 3.12+

**Required Linting:**
```bash
cd manager
flake8 . --max-line-length=120
black --check .
isort --check-only .
mypy . --strict
bandit -r . -ll
```

**Code Style (PEP 8):**
- Line length: 120 characters max
- Use 4 spaces for indentation
- Import order: stdlib, third-party, local
- Use type hints for all functions
- Docstrings for all modules, classes, functions

**Type Hints Requirement:**
```python
def process_query(sql: str, timeout: int = 30) -> dict[str, Any]:
    """Process database query."""
    ...
```

**Docstrings (PEP 257):**
```python
def calculate_hash(data: bytes) -> str:
    """Calculate SHA256 hash of data.

    Args:
        data: Input bytes to hash

    Returns:
        Hexadecimal hash string

    Raises:
        ValueError: If data is empty
    """
    ...
```

**Common Issues:**
- Missing type hints: FAIL build
- Line too long: Use line continuation
- Import order incorrect: Run `isort .`
- SQL injection: Use parameterized queries
- Hardcoded secrets: Use environment variables

### Docker (All Services)

**Base Images:**
- Proxy: golang:1.23-debian-slim (build), debian:bookworm-slim (runtime)
- Manager: python:3.12-slim

**Multi-Architecture:**
- Always build for linux/amd64 and linux/arm64
- Use buildx for multi-arch: `docker buildx build --platform linux/amd64,linux/arm64`

**Security Requirements:**
- Non-root user for container runtime
- Health check endpoint required
- No hardcoded credentials
- Latest base images (auto-update)
- Minimal image size

**Dockerfile Best Practices:**
```dockerfile
FROM python:3.12-slim AS base

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 appuser

FROM base AS runtime
COPY --from=base / /
COPY --chown=appuser:appuser . /app
WORKDIR /app
USER appuser
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["python", "-m", "py4web", "run", "/app"]
```

---

## CI/CD Pipeline

### Workflow Triggers

**build-containers.yml:**
- Branches: all branches
- Paths: proxy/**, manager/**, DB-Manager/**, .version, workflow file
- Events: push, pull_request (main), release, workflow_dispatch

**proxy-build.yml:**
- Branches: main, develop
- Paths: proxy/**, .version, workflow file
- Events: push, pull_request, workflow_dispatch

**manager-build.yml:**
- Branches: main, develop
- Paths: manager/**, .version, workflow file
- Events: push, pull_request, workflow_dispatch

**version-release.yml:**
- Branches: main only
- Paths: .version
- Events: push only

### Build Process

#### Lint Stage
```
Sequential execution per service:
- Source analysis (golangci-lint or flake8+black+isort)
- Security scanning (gosec or bandit)
- Results uploaded to GitHub Security tab
- Build fails if lint errors found
```

#### Test Stage
```
Parallel execution:
- Unit tests (go test or pytest)
- Coverage reporting (codecov)
- Test databases (PostgreSQL for manager)
- Build fails if tests fail
```

#### Build Stage
```
Docker build steps:
1. Version detection (semver + epoch64)
2. Tag generation (conditional based on branch/version)
3. Multi-arch build (amd64, arm64)
4. Registry push (non-PR builds only)
5. Vulnerability scanning (Trivy)
6. SARIF results upload (CodeQL)
```

### Version Management

**Format:** `vMajor.Minor.Patch`

**Update Process:**
```bash
# Edit .version file
echo "v1.2.4" > .version

# Commit
git add .version
git commit -m "Release v1.2.4"

# Push
git push origin main
```

**Automatic Actions:**
1. build-containers.yml triggered
2. Containers tagged: v1.2.4-beta (main), v1.2.4-alpha (feature branches)
3. version-release.yml creates GitHub pre-release
4. Build summary generated

### Image Tagging

**Epoch64 Builds:**
```
Regular build on main: beta-<unix-timestamp>
Regular build on feature: alpha-<unix-timestamp>
Example: beta-1733949234, alpha-1733949234
```

**Version Builds:**
```
Version release on main: v<semver>-beta
Version release on feature: v<semver>-alpha
Example: v1.2.4-beta, v1.2.4-alpha
```

**Release Tags:**
```
Git release tag: v<semver> + latest
Example: v1.2.4, latest
```

### Artifact Management

**Container Registry:** GitHub Container Registry (GHCR)

**Image Paths:**
```
Proxy: ghcr.io/penguintechinc/articdbm/proxy:<tag>
Manager: ghcr.io/penguintechinc/articdbm/manager:<tag>
```

**Retention:**
- Keep all versioned releases (vX.X.X)
- Keep latest 10 alpha/beta builds per branch
- Clean up untagged images monthly

---

## Security Requirements

### Source Code Security

**Mandatory Scans:**
- golangci-lint (includes staticcheck, gosec, etc.) for Go
- flake8 + bandit for Python
- CodeQL for all code (automatic)

**Failure Criteria:**
- gosec findings (high/medium confidence)
- bandit findings (low severity) - log/document required
- CodeQL critical issues
- Known vulnerabilities in dependencies

**Results Location:**
- GitHub repo → Security tab → Code scanning
- Results auto-updated on each push
- SARIF format for tool integration

### Container Security

**Trivy Scanning:**
- Automatic on all builds (non-PR)
- Scans base images and dependencies
- Results in SARIF format
- Uploaded to GitHub Security tab

**Base Image Requirements:**
- Official images only (golang, python)
- Latest tag acceptable (auto-updated)
- Debian-slim preferred over alpine
- No hardcoded credentials

**Runtime Security:**
- Non-root user required
- Read-only filesystem where possible
- Network policies (if K8s deployed)
- Secrets via environment variables only

### Dependency Management

**Go Modules:**
```bash
cd proxy
go mod audit          # Check for vulnerabilities
go get -u ./...       # Update dependencies
go mod tidy           # Clean up
```

**Python Dependencies:**
```bash
cd manager
pip audit             # Check for vulnerabilities
pip-sync requirements.txt  # Install exact versions
```

**Policy:**
- No use of deprecated packages
- Security updates within 24 hours
- Regular audits (monthly minimum)
- Update base images when new patch released

### Credentials & Secrets

**Forbidden in Code:**
- Database passwords
- API keys
- Private keys
- License keys
- Auth tokens

**Correct Pattern:**
```go
// Go example
password := os.Getenv("DB_PASSWORD")
if password == "" {
    return errors.New("DB_PASSWORD not set")
}
```

```python
# Python example
import os
db_host = os.getenv("DB_HOST")
db_port = os.getenv("DB_PORT", "5432")
```

---

## Testing Standards

### Unit Testing

**Go Tests:**
```bash
cd proxy
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

**Coverage Requirements:**
- Minimum 70% code coverage
- All exported functions tested
- Error paths covered
- Edge cases tested

**Test Format:**
```go
func TestProcessQuery(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    interface{}
        wantErr bool
    }{
        {"valid query", "SELECT 1", 1, false},
        {"empty query", "", nil, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ProcessQuery(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
            }
            if got != tt.want {
                t.Errorf("got = %v, want = %v", got, tt.want)
            }
        })
    }
}
```

**Python Tests:**
```bash
cd manager
pytest --cov=. --cov-report=html
```

**Coverage Requirements:**
- Minimum 70% code coverage
- All endpoints tested
- Error handling tested
- Database interactions tested

**Test Format:**
```python
import pytest
from app import create_app

@pytest.fixture
def app():
    app = create_app()
    app.config['TESTING'] = True
    return app

@pytest.fixture
def client(app):
    return app.test_client()

def test_health_check(client):
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json['status'] == 'healthy'

def test_invalid_query(client):
    response = client.post('/query', json={'sql': ''})
    assert response.status_code == 400
```

### Integration Testing

**Requirements:**
- Test with real databases (test instances)
- Test multi-service interactions
- Test error recovery paths
- Automated in CI/CD pipeline

**Test Environment:**
- PostgreSQL 16-alpine for manager tests
- MySQL 8.0 for proxy compatibility tests
- Redis for cache testing

### Performance Testing

**Load Testing:**
- Use for performance-critical paths
- Baseline metrics required
- Test with different data sizes
- Monitor resource usage

---

## Documentation Standards

### Markdown Files

**File Naming:** UPPERCASE.md (except index.md)

**Examples:**
- ARCHITECTURE.md
- SECURITY-CENTER.md
- WORKFLOWS.md
- USER-MANAGEMENT.md

**Structure:**
```markdown
# Title

## Introduction

## Section 1
Content with examples

### Subsection
More detailed content

## Related Documentation
- [Link Name](path)
- [Another Link](path)

---
Last Updated: YYYY-MM-DD
```

**Maximum File Size:** 25,000 characters
- Split large docs into separate files
- Use clear linking between related docs
- Exception: CLAUDE.md max 39,000 characters

### Code Documentation

**Go:**
- Comment all exported functions
- Use standard comment format
- Example comments for complex functions
- Update comments with code changes

**Python:**
- Docstrings (PEP 257) for all modules, classes, functions
- Type hints in function signatures
- Return value documentation
- Exception documentation

**Docker:**
- Dockerfile comments explaining complex steps
- README.md in service directories
- Environment variables documented

---

## Deployment Requirements

### Pre-Deployment Checklist

- [ ] All tests passing (unit + integration)
- [ ] Security scans passing (gosec, bandit, Trivy)
- [ ] Linting passes (golangci-lint, flake8, black)
- [ ] Coverage meets minimum thresholds (70%)
- [ ] Code review approved
- [ ] Documentation updated
- [ ] CHANGELOG/RELEASE-NOTES updated
- [ ] .version file updated (for release)
- [ ] No hardcoded secrets in code

### Deployment Process

**Development Environment:**
```bash
docker-compose up -d
# Services available at:
# Proxy: localhost:3306
# Manager: localhost:8000
```

**Staging/Production:**
```bash
# Using versioned images
docker pull ghcr.io/penguintechinc/articdbm/proxy:v1.2.4
docker pull ghcr.io/penguintechinc/articdbm/manager:v1.2.4

# Or latest release
docker pull ghcr.io/penguintechinc/articdbm/proxy:latest
docker pull ghcr.io/penguintechinc/articdbm/manager:latest
```

### Health Checks

**Proxy Health:**
```bash
curl http://localhost:3306/health
# Expected: Connection refused (proxy doesn't expose health endpoint)
# Use liveness probe in Kubernetes
```

**Manager Health:**
```bash
curl http://localhost:8000/health
# Expected: {"status": "healthy"}
```

### Rollback Plan

1. Keep previous version containers available
2. Update docker-compose.yml to previous version
3. Restart services: `docker-compose up -d`
4. Verify health checks pass
5. Document rollback reason

---

## Related Documentation

- [WORKFLOWS.md](WORKFLOWS.md) - CI/CD workflow details
- [DEVELOPMENT.md](DEVELOPMENT.md) - Development guidelines
- [SECURITY-CENTER.md](SECURITY-CENTER.md) - Security policies
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture

---

**Last Updated:** 2025-12-11
**Maintained by:** Penguin Tech Inc
**License Server:** https://license.penguintech.io
