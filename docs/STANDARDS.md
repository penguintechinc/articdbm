# Development Standards

This document consolidates all development standards, patterns, and requirements for ArticDBM project.

## Table of Contents

1. [Code Quality Standards](#code-quality-standards)
2. [Language Selection](#language-selection-criteria)
3. [Flask-Security-Too Integration](#flask-security-too-integration)
4. [Database Standards](#database-standards)
5. [Protocol Support](#protocol-support)
6. [API Versioning](#api-versioning)
7. [Performance Best Practices](#performance-best-practices)
8. [Microservices Architecture](#microservices-architecture)
9. [Docker Standards](#docker-standards)
10. [Testing Requirements](#testing-requirements)
11. [Security Standards](#security-standards)
12. [Documentation Standards](#documentation-standards)
13. [CI/CD Standards](#cicd-standards)
14. [Licensing and Feature Gating](#licensing-and-feature-gating)

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

---

## Language Selection Criteria

**Evaluate on a case-by-case basis which language to use for each project or service:**

### Python 3.12+ (Manager Application)
**Use Python for most applications:**
- Web applications and REST APIs
- Business logic and data processing
- Integration services and connectors
- CRUD applications
- Admin panels and internal tools
- Low to moderate traffic applications (<10K req/sec)

### Go 1.23.x (Proxy - High-Performance Only)
**Use Go ONLY for high-traffic, performance-critical applications:**
- Applications handling >10K requests/second
- Network-intensive services requiring low latency
- Services with latency requirements <10ms
- CPU-bound operations requiring maximum throughput
- Systems requiring minimal memory footprint
- Real-time processing pipelines

**Traffic Threshold Decision Matrix:**
| Requests/Second | Language Choice | Rationale |
|-----------------|-----------------|-----------|
| < 1K req/sec    | Python 3.12+    | Development speed priority |
| 1K - 10K req/sec| Python 3.12+    | Python can handle with optimization |
| 10K - 50K req/sec| Evaluate both  | Consider complexity vs performance needs |
| > 50K req/sec   | Go 1.23.x       | Performance becomes critical |

---

## Flask-Security-Too Integration

**MANDATORY for ALL Flask applications - provides comprehensive security framework**

### Core Features
- User authentication and session management
- Role-based access control (RBAC)
- Password hashing with bcrypt
- Email confirmation and password reset
- Two-factor authentication (2FA)
- Token-based authentication for APIs
- Login tracking and session management

### Integration with PyDAL

Flask-Security-Too integrates with PyDAL for database operations. See CLAUDE.md for detailed integration patterns.

### Environment Variables

Required environment variables for Flask-Security-Too:

```bash
# Flask-Security-Too core
SECRET_KEY=your-secret-key-here
SECURITY_PASSWORD_SALT=your-password-salt
SECURITY_REGISTERABLE=true
SECURITY_SEND_REGISTER_EMAIL=false

# SSO (Enterprise only - license-gated)
SAML_IDP_METADATA_URL=https://idp.example.com/metadata
GOOGLE_CLIENT_ID=google-oauth-client-id
GOOGLE_CLIENT_SECRET=google-oauth-client-secret
```

---

## Database Standards

### PyDAL Configuration - MANDATORY for ALL Python Applications

ALL Python applications (web or non-web) MUST implement PyDAL database access.

**Hybrid Database Approach:**
- **SQLAlchemy**: Used for database **initialization only** (schema creation)
- **PyDAL**: Used for **migrations and day-to-day operations** (mandatory)
- **Go**: GORM or sqlx (mandatory for cross-database support)

### Environment Variables

Applications MUST accept these Docker environment variables:
- `DB_TYPE`: Database type (postgresql, mysql, sqlite)
- `DB_HOST`: Database host/IP address
- `DB_PORT`: Database port
- `DB_NAME`: Database name
- `DB_USER`: Database username
- `DB_PASS`: Database password
- `DB_POOL_SIZE`: Connection pool size (default: 10)
- `DB_MAX_RETRIES`: Maximum connection retry attempts (default: 5)
- `DB_RETRY_DELAY`: Delay between retry attempts in seconds (default: 5)

### Database Connection Requirements

1. **Wait for Database Initialization**: Application MUST wait for database to be ready
2. **Connection Pooling**: MUST use PyDAL's built-in connection pooling
3. **Database URI Construction**: Build connection string from environment variables
4. **Thread Safety**: Each thread MUST have its own DAL instance

---

## Protocol Support

**ALL applications MUST support multiple communication protocols:**

### Required Protocol Support

1. **REST API**: RESTful HTTP endpoints (GET, POST, PUT, DELETE, PATCH)
2. **gRPC**: High-performance RPC protocol
3. **HTTP/1.1**: Standard HTTP protocol support
4. **HTTP/2**: Modern HTTP protocol
5. **HTTP/3 (QUIC)**: Next-generation HTTP protocol

### Protocol Configuration via Environment Variables

Applications must accept these environment variables:
- `HTTP1_ENABLED`: Enable HTTP/1.1 (default: true)
- `HTTP2_ENABLED`: Enable HTTP/2 (default: true)
- `HTTP3_ENABLED`: Enable HTTP/3/QUIC (default: false)
- `GRPC_ENABLED`: Enable gRPC (default: true)
- `HTTP_PORT`: HTTP/REST API port (default: 8080)
- `GRPC_PORT`: gRPC port (default: 50051)

---

## API Versioning

**ALL REST APIs MUST use versioning in the URL path**

### URL Structure

**Required Format:** `/api/v{major}/endpoint`

**Examples:**
- `/api/v1/users` - User management
- `/api/v1/auth/login` - Authentication
- `/api/v2/analytics` - Version 2 of analytics endpoint

**Key Rules:**
1. **Always include version prefix** in URL path - NEVER use query parameters for versioning
2. **Semantic versioning** for API versions: `v1`, `v2`, `v3`, etc.
3. **Major version only** in URL - minor/patch versions are NOT in the URL
4. **Consistent prefix** across all endpoints in a service

### Version Lifecycle

**Version Strategy:**
- **Current Version**: Active development and fully supported
- **Previous Version (N-1)**: Supported with bug fixes and security patches
- **Older Versions (N-2+)**: Deprecated with deprecation warning headers

---

## Performance Best Practices

**ALWAYS prioritize performance and stability through modern concurrency patterns**

### Python Performance Requirements

#### Concurrency Patterns - Choose Based on Use Case

1. **asyncio** - For I/O-bound operations:
   - Database queries and connections
   - HTTP/REST API calls
   - File I/O operations
   - Network communication

2. **threading.Thread** - For I/O-bound operations with blocking libraries:
   - Legacy libraries without async support
   - Blocking I/O operations
   - Moderate parallelism (10-100 threads)

3. **multiprocessing** - For CPU-bound operations:
   - Data processing and transformations
   - Cryptographic operations
   - Image/video processing
   - Heavy computational tasks

#### Dataclasses with Slots - MANDATORY

**ALL data structures MUST use dataclasses with slots for memory efficiency:**

```python
from dataclasses import dataclass

@dataclass(slots=True, frozen=True)
class User:
    """User model with slots for 30-50% memory reduction"""
    id: int
    name: str
    email: str
    created_at: str
```

#### Type Hints - MANDATORY

**Comprehensive type hints are REQUIRED for all Python code.**

### Go Performance Requirements
- **Goroutines**: Leverage goroutines and channels for concurrent operations
- **Sync primitives**: Use sync.Pool, sync.Map for concurrent data structures
- **Context**: Proper context propagation for cancellation and timeouts

---

## Microservices Architecture

**ALWAYS use microservices architecture for application development**

### Two-Service Architecture (ArticDBM)

ArticDBM uses two primary microservices:

| Service | Technology | Purpose |
|---------|-----------|---------|
| **Proxy** | Go 1.23.x | Database protocol handling, query routing, security checks |
| **Manager** | Python 3.12+ Flask | REST API, user management, configuration, audit logging |

### Design Principles

- **Single Responsibility**: Each service has one clear purpose
- **Independent Deployment**: Services can be updated independently
- **API-First Design**: All inter-service communication via well-defined APIs
- **Data Isolation**: Each service owns its data
- **Fault Isolation**: Failure in one service doesn't cascade
- **Scalability**: Scale individual services based on demand

### Service Communication Patterns

- **Synchronous**: REST API, gRPC for request/response
- **Asynchronous**: Message queues (Kafka, RabbitMQ) for events
- **Service Discovery**: Docker networking or service mesh
- **Circuit Breakers**: Fallback mechanisms for failures

---

## Docker Standards

### Build Standards

**All builds MUST be executed within Docker containers**

**Use multi-stage builds with debian-slim:**
```dockerfile
FROM golang:1.23-slim AS builder
FROM debian:stable-slim AS runtime

FROM python:3.12-slim AS builder
FROM debian:stable-slim AS runtime
```

### Docker Compose Standards

**ALWAYS create docker-compose.dev.yml for local development**

**Prefer Docker networks over host ports:**
- Minimize host port exposure
- Only expose ports for developer access
- Use named Docker networks for service-to-service communication

---

## Testing Requirements

### Unit Testing

**All applications MUST have comprehensive unit tests:**

- **Network isolation**: Unit tests must NOT require external network connections
- **No external dependencies**: Cannot reach databases, APIs, or external services
- **Use mocks/stubs**: Mock all external dependencies and I/O operations
- **KISS principle**: Keep unit tests simple, focused, and fast
- **Test isolation**: Each test should be independent and repeatable
- **Fast execution**: Unit tests should complete in milliseconds

### Integration Testing

- Test component interactions
- Use test databases and services
- Verify API contracts
- Test authentication and authorization

### End-to-End Testing

- Test critical user workflows
- Use staging environment
- Verify full system integration

### Performance Testing

- Benchmark critical operations
- Load testing for scalability
- Regression testing for performance

---

## Security Standards

### Input Validation

- ALL inputs MUST have appropriate validators
- Use framework-native validation (PyDAL validators, Go libraries)
- Implement XSS and SQL injection prevention
- Server-side validation for all client input
- CSRF protection using framework native features

### Authentication & Authorization

- Multi-factor authentication support
- Role-based access control (RBAC)
- API key management with rotation
- JWT token validation with proper expiration
- Session management with secure cookies

### TLS/Encryption

- **TLS enforcement**: TLS 1.2 minimum, prefer TLS 1.3
- **Connection security**: Use HTTPS where possible
- **Modern protocols**: HTTP3/QUIC for high-performance
- **Standard security**: JWT, MFA, mTLS where applicable
- **Enterprise SSO**: SAML/OAuth2 as enterprise features

### Dependency Security

- **ALWAYS check for Dependabot alerts** before commits
- **Monitor vulnerabilities** via Socket.dev
- **Mandatory security scanning** before dependency changes
- **Fix all security alerts immediately**
- **Version pinning**: Exact versions for security-critical dependencies

### Vulnerability Response Process

1. Identify affected packages and severity
2. Update to patched versions immediately
3. Test updated dependencies thoroughly
4. Document security fixes in commit messages
5. Verify no new vulnerabilities introduced

---

## Documentation Standards

### README.md Standards

**ALWAYS include build status badges:**
- CI/CD pipeline status (GitHub Actions)
- Test coverage status (Codecov)
- Go Report Card (for Go projects)
- Version badge
- License badge (Limited AGPL3)

**ALWAYS include catchy ASCII art** below badges

**Company homepage**: Point to **www.penguintech.io**

### CLAUDE.md File Management

- **Maximum**: 39,000 characters
- **High-level approach**: Reference detailed docs
- **Documentation strategy**: Create detailed docs in `docs/` folder
- **Keep focused**: Critical context and workflow instructions only

### API Documentation

- Comprehensive endpoint documentation
- Request/response examples
- Error codes and handling
- Authentication requirements
- Rate limiting information

### Markdown Files

**File Naming:** UPPERCASE.md (except index.md)

**Examples:**
- ARCHITECTURE.md
- SECURITY-CENTER.md
- WORKFLOWS.md
- USER-MANAGEMENT.md

**Maximum File Size:** 25,000 characters
- Split large docs into separate files
- Use clear linking between related docs
- Exception: CLAUDE.md max 39,000 characters

---

## CI/CD Standards

### Overview

This section documents comprehensive CI/CD standards and requirements for ArticDBM. These standards ensure consistent, secure, and efficient build pipelines while maintaining compliance with workflow specifications.

**Key Principles:**
- Efficient execution with parallel builds where possible
- Mandatory security scanning for all code
- Consistent naming conventions across all projects
- Version management integration in all workflows
- Comprehensive documentation requirements

### Workflow Triggers

**build-containers.yml:**
- Branches: all branches
- Paths: proxy/**, manager/**, .version, workflow file
- Events: push, pull_request, workflow_dispatch

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

### Security Scanning Standards

**ALL workflows must include security scanning and fail on HIGH/CRITICAL findings.**

#### Go Projects: gosec Scanning

**Required in all Go build workflows**

#### Python Projects: bandit Verification

**Required in all Python build workflows**

#### All Projects: Trivy Container Scanning

**Required for all Docker build workflows**

#### All Projects: CodeQL Analysis

**Required for all projects with code**

### Version Management

**Format:** `vMajor.Minor.Patch`

**Update Process:**
```bash
echo "v1.2.4" > .version
git add .version
git commit -m "Release v1.2.4"
git push origin main
```

### Image Tagging

**Regular Builds** (no `.version` change):
- Main branch: `beta-<unix-timestamp>`
- Feature branches: `alpha-<unix-timestamp>`

**Version Releases** (`.version` changed):
- Main branch: `v<semver>-beta`
- Feature branches: `v<semver>-alpha`

**Release Tags**: `v<semver>` + `latest`

---

## Licensing and Feature Gating

### License Enforcement Timing

**IMPORTANT: License enforcement is enabled ONLY when project is release-ready**

**Development Phase (Pre-Release):**
- License checking code is present but not enforced
- All features available during development
- Focus on feature development and testing
- No license validation failures

**Release Phase (Production):**
- User explicitly marks project as "release ready"
- License enforcement is enabled
- Feature gating becomes active
- License validation required for startup

### Enterprise Features

**ALWAYS license-gate these features as enterprise-only:**
- SSO (SAML, OAuth2, OIDC)
- Advanced AI capabilities
- Multi-tenancy
- Audit logging and compliance
- Advanced analytics
- Custom integrations
- Priority support

---

## Quality Checklist

Before marking any task complete, verify:
- ✅ All error cases handled properly
- ✅ Unit tests cover all code paths
- ✅ Integration tests verify component interactions
- ✅ Security requirements fully implemented
- ✅ Performance meets acceptable standards
- ✅ Documentation complete and accurate
- ✅ Code review standards met
- ✅ No hardcoded secrets or credentials
- ✅ Logging and monitoring in place
- ✅ Build passes in containerized environment
- ✅ No security vulnerabilities in dependencies
- ✅ Edge cases and boundary conditions tested
- ✅ License enforcement configured correctly (if release-ready)

---

## Related Documentation

- [WORKFLOWS.md](WORKFLOWS.md) - CI/CD workflow details
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [SECURITY-CENTER.md](SECURITY-CENTER.md) - Security policies
- [CLAUDE.md](../CLAUDE.md) - Project context

---

**Last Updated:** 2025-12-18
**Maintained by:** Penguin Tech Inc
**License Server:** https://license.penguintech.io
