# ArticDBM - Claude Code Context

## Project Overview

**ArticDBM (Arctic Database Manager)** is a comprehensive enterprise-grade database proxy solution that provides:

- **Multi-database support**: PostgreSQL, MySQL, SQLite (with MariaDB Galera cluster support)
- **Advanced Security**: SQL injection detection, threat intelligence integration, authentication, authorization
- **Performance**: Optimized connection pooling, read/write splitting, load balancing, warmup
- **Enterprise Auth**: API keys, temporary access tokens, IP whitelisting, rate limiting, TLS enforcement
- **Threat Intelligence**: STIX/TAXII feeds, OpenIOC support, MISP integration, real-time blocking
- **Monitoring**: Prometheus metrics, comprehensive audit logging, usage tracking
- **High availability**: Cluster mode with shared configuration
- **MSP Ready**: Multi-tenant support, usage-based billing, white-label capabilities

**Template Features:**
- Multi-language support (Go 1.23.x proxy, Python 3.12+ manager)
- Enterprise security and licensing integration
- Comprehensive CI/CD pipeline
- Production-ready containerization
- Monitoring and observability
- Version management system
- PenguinTech License Server integration

## Technology Stack

### Languages & Frameworks

**Go Stack (Proxy - High-Performance)**:
- **Go**: 1.23.x (latest patch version)
- **Database Drivers**: lib/pq (PostgreSQL), go-sql-driver/mysql, mattn/go-sqlite3
- **Config**: spf13/viper
- **Logging**: go.uber.org/zap
- **Metrics**: prometheus/client_golang
- **Use Case**: Database protocol handling, query routing, security checks, connection pooling

**Python Stack (Manager)**:
- **Python**: 3.12+ for manager application
- **Web Framework**: Flask + Flask-Security-Too (mandatory)
- **Database**:
  - **SQLAlchemy**: Database initialization (schema creation)
  - **PyDAL**: Migrations and day-to-day operations (mandatory)
- **Cache**: Redis (aioredis)
- **Auth**: Flask-Security-Too with multi-factor support
- **Use Case**: REST API endpoints, user management, configuration, audit logging

### Infrastructure & DevOps
- **Containers**: Docker with multi-stage builds, Docker Compose
- **Orchestration**: Kubernetes with Helm charts (production)
- **Configuration Management**: Ansible for infrastructure automation
- **CI/CD**: GitHub Actions with comprehensive pipelines
- **Monitoring**: Prometheus metrics, Grafana dashboards
- **Logging**: Structured logging with configurable levels

### Databases & Storage
- **Primary**: PostgreSQL (default), MySQL, SQLite (configurable via `DB_TYPE`)
- **Cache**: Redis/Valkey with optional TLS and authentication
- **Database Strategy (Hybrid Approach)**:
  - **SQLAlchemy**: Used for database **initialization only** (schema creation)
  - **PyDAL**: Used for **migrations and day-to-day operations** (mandatory)
  - **Go**: GORM or sqlx (mandatory for cross-database support)
- **MariaDB Galera Support**: Handle Galera-specific requirements (WSREP, auto-increment, transactions)

**Supported DB_TYPE Values**:
```bash
DB_TYPE=postgres    # PostgreSQL (default)
DB_TYPE=mysql       # MySQL/MariaDB/Galera
DB_TYPE=sqlite      # SQLite (development/testing)
GALERA_MODE=true    # Enable MariaDB Galera cluster mode (optional)
```

### Security & Authentication
- **Flask-Security-Too**: Mandatory for all Flask applications
  - Role-based access control (RBAC)
  - User authentication and session management
  - Password hashing with bcrypt
  - Email confirmation and password reset
  - Two-factor authentication (2FA)
- **TLS**: Enforce TLS 1.2 minimum, prefer TLS 1.3
- **HTTP3/QUIC**: Utilize UDP with TLS for high-performance connections where possible
- **Authentication**: JWT and MFA (standard), mTLS where applicable
- **SSO**: SAML/OAuth2 SSO as enterprise-only features
- **Secrets**: Environment variable management
- **Scanning**: Trivy vulnerability scanning, CodeQL analysis
- **Code Quality**: All code must pass CodeQL security analysis

## PenguinTech License Server Integration

All projects integrate with the centralized PenguinTech License Server at `https://license.penguintech.io` for feature gating and enterprise functionality.

**IMPORTANT: License enforcement is ONLY enabled when project is marked as release-ready**
- Development phase: All features available, no license checks
- Release phase: License validation required, feature gating active

**License Key Format**: `PENG-XXXX-XXXX-XXXX-XXXX-ABCD`

**Core Endpoints**:
- `POST /api/v2/validate` - Validate license
- `POST /api/v2/features` - Check feature entitlements
- `POST /api/v2/keepalive` - Report usage statistics

**Environment Variables**:
```bash
# License configuration
LICENSE_KEY=PENG-XXXX-XXXX-XXXX-XXXX-ABCD
LICENSE_SERVER_URL=https://license.penguintech.io
PRODUCT_NAME=articdbm

# Release mode (enables license enforcement)
RELEASE_MODE=false  # Development (default)
RELEASE_MODE=true   # Production (explicitly set)
```

📚 **Detailed Documentation**: [Development Standards](docs/STANDARDS.md)

## WaddleAI Integration (Optional)

For projects requiring AI capabilities, integrate with WaddleAI located at `~/code/WaddleAI`.

**When to Use WaddleAI with ArticDBM:**
- AI-powered query optimization suggestions
- Intelligent threat pattern detection
- Natural language query parsing
- Anomaly detection in database access patterns
- Automated performance recommendations

**Integration Pattern (ArticDBM):**
- WaddleAI runs as separate microservice container
- Manager service communicates via REST API or gRPC
- AI threat analysis runs alongside STIX/TAXII feeds
- License-gate AI features as enterprise functionality
- Query optimization suggestions in manager dashboard

📚 **WaddleAI Documentation**: See WaddleAI project at `~/code/WaddleAI` for integration details

## Project Structure

```
ArticDBM/
├── proxy/                    # Go-based database proxy
│   ├── main.go              # Main proxy application
│   ├── internal/            # Internal packages
│   │   ├── config/          # Configuration management
│   │   ├── handlers/        # Database protocol handlers
│   │   ├── security/        # SQL injection detection
│   │   ├── auth/            # Authentication/authorization
│   │   ├── metrics/         # Prometheus metrics
│   │   └── pool/            # Connection pooling
│   ├── Dockerfile           # Proxy container
│   └── go.mod              # Go dependencies
├── manager/                 # Python Flask manager
│   ├── app.py              # Main manager application
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Manager container
├── docs/                   # Documentation
│   ├── index.md           # Documentation homepage (lowercase exception)
│   ├── USAGE.md           # Usage guide
│   ├── ARCHITECTURE.md    # Architecture details
│   ├── STANDARDS.md       # Development standards
│   └── WORKFLOWS.md       # CI/CD workflows
├── k8s/                    # Kubernetes deployment templates
├── scripts/                # Utility scripts
├── tests/                  # Test suites
├── docker-compose.yml      # Production environment
├── docker-compose.dev.yml  # Local development
├── Makefile               # Build automation
├── .version               # Version tracking
└── CLAUDE.md             # This file
```

## Container Architecture

### Three-Service Architecture

ArticDBM uses a microservices architecture with separated concerns:

| Service | Technology | Purpose | Port |
|---------|-----------|---------|------|
| **proxy** | Go 1.23.x | Database protocol handling, query routing, security checks | 3306, 5432 |
| **manager** | Python 3.12+ Flask | REST API, user management, configuration, audit logging | 8000 |
| **Supporting** | PostgreSQL/Redis | Data persistence, caching, configuration distribution | 5432, 6379 |

### Deployment Topology

```
┌─────────────────────────────────────┐
│        Load Balancer / Ingress       │
└─┬───────────────────┬─────────────┬─┘
  │                   │             │
  ▼                   ▼             ▼
┌─────────────┐ ┌──────────┐ ┌──────────┐
│  Manager (x2)│ │  Proxy (x2) │
└─────────────┘ └──────────┘
       │              │
       └──────┬───────┘
              ▼
       ┌─────────────┐
       │   Redis     │
       └─────────────┘
              ▼
       ┌─────────────┐
       │   Database  │
       └─────────────┘
```

## Kubernetes Deployment

All services are Kubernetes-ready with Helm charts and raw manifests in `k8s/`:

### Helm Charts (`k8s/helm/`)
```bash
# Deploy proxy to development namespace
helm install proxy k8s/helm/proxy \
  --namespace dev \
  --values k8s/helm/proxy/values-dev.yaml

# Deploy manager
helm install manager k8s/helm/manager --namespace dev
```

### Raw Manifests (`k8s/manifests/`)
```bash
# Apply namespace and RBAC
kubectl apply -f k8s/manifests/namespace.yaml
kubectl apply -f k8s/manifests/rbac.yaml

# Deploy services
kubectl apply -f k8s/manifests/proxy/
kubectl apply -f k8s/manifests/manager/
```

📚 **Kubernetes Documentation**: [k8s/README.md](k8s/README.md)

## Version Management System

**Format**: `vMajor.Minor.Patch.build`
- **Major**: Breaking changes, API changes, removed features
- **Minor**: Significant new features and functionality additions
- **Patch**: Minor updates, bug fixes, security patches
- **Build**: Epoch64 timestamp of build time

**Update Commands**:
```bash
./scripts/version/update-version.sh          # Increment build timestamp
./scripts/version/update-version.sh patch    # Increment patch version
./scripts/version/update-version.sh minor    # Increment minor version
./scripts/version/update-version.sh major    # Increment major version
```

## Development Workflow

### Local Development Setup
```bash
git clone <repository-url>
cd ArticDBM
docker-compose up -d
```

### Essential Commands
```bash
# Development
make dev                      # Start development services
make test                     # Run all tests
make lint                     # Run linting
make build                    # Build all services
make clean                    # Clean build artifacts

# Production
make docker-build             # Build containers
make docker-push              # Push to registry
make deploy-dev               # Deploy to development
make deploy-prod              # Deploy to production

# Testing
make test-unit               # Run unit tests
make test-integration        # Run integration tests

# License Management
make license-validate        # Validate license
make license-check-features  # Check available features
```

## Critical Development Rules

### Development Philosophy: Safe, Stable, and Feature-Complete

**NEVER take shortcuts or the "easy route" - ALWAYS prioritize safety, stability, and feature completeness**

#### Core Principles (ArticDBM)
- **Database Proxy Integrity**: Query validation, threat intelligence integration, zero data loss
- **Multi-Database Support**: PostgreSQL, MySQL, SQLite, MariaDB Galera must work identically
- **Security Enforcement**: SQL injection detection, auth/authz, audit logging are mandatory
- **No Quick Fixes**: Resist quick workarounds or partial solutions
- **Complete Features**: Fully implemented with proper error handling and validation
- **Safety First**: Security, data integrity, and fault tolerance are non-negotiable
- **Stable Foundations**: Build on solid, tested components
- **Future-Proof Design**: Consider long-term maintainability and scalability
- **No Technical Debt**: Address issues properly the first time

#### Red Flags (Never Do These)
- ❌ Skipping input validation "just this once"
- ❌ Hardcoding credentials or configuration
- ❌ Ignoring error returns or exceptions
- ❌ Commenting out failing tests to make CI pass
- ❌ Deploying without proper testing
- ❌ Using deprecated or unmaintained dependencies
- ❌ Implementing partial features with "TODO" placeholders
- ❌ Bypassing security checks for convenience
- ❌ Assuming data is valid without verification
- ❌ Leaving debug code or backdoors in production
- ❌ Skipping threat intelligence validation for performance
- ❌ Allowing mixed database behavior across DB_TYPE values
- ❌ Disabling SQL injection detection in "trusted" environments
- ❌ Hardcoding database connection strings

#### Quality Checklist Before Completion
- ✅ All error cases handled properly
- ✅ Unit tests cover all code paths
- ✅ Integration tests verify component interactions
- ✅ Smoke tests verify build, run, API health, and proxy stability
- ✅ Security requirements fully implemented
- ✅ Performance meets acceptable standards
- ✅ Documentation complete and accurate
- ✅ Code review standards met
- ✅ No hardcoded secrets or credentials
- ✅ Logging and monitoring in place
- ✅ Build passes in containerized environment
- ✅ No security vulnerabilities in dependencies
- ✅ Edge cases and boundary conditions tested
- ✅ All DB_TYPE values tested (postgres, mysql, sqlite, galera)
- ✅ Threat intelligence integration tested
- ✅ Multi-database behavioral consistency verified

### Git Workflow
- **NEVER commit automatically** unless explicitly requested by the user
- **NEVER push to remote repositories** under any circumstances
- **ONLY commit when explicitly asked** - never assume commit permission
- Always use feature branches for development
- Require pull request reviews for main branch
- Automated testing must pass before merge

**Before Every Commit - Security Scanning**:
- **Run security audits on all modified packages**:
  - **Go packages**: Run `gosec ./...` on modified Go services
  - **Python packages**: Run `bandit -r .` and `safety check` on modified Python services
- **Do NOT commit if security vulnerabilities are found** - fix all issues first
- **Document vulnerability fixes** in commit message if applicable

**Before Every Commit - API Testing**:
- **Create and run API testing scripts** for each modified service
- **Testing scope**: All new endpoints and modified functionality
- **Test files location**: `tests/api/` directory with service-specific subdirectories
- **Run before commit**: Each test script should be executable and pass completely

**Before Every Commit - Screenshots** (if applicable):
- **Run screenshot tool to update UI screenshots in documentation**
  - Run `cd manager && npm run screenshots` to capture current UI state
  - Commit updated screenshots with relevant feature/documentation changes

### Local State Management (Crash Recovery)
- **ALWAYS maintain local .PLAN and .TODO files** for crash recovery
- **Keep .PLAN file updated** with current implementation plans and progress
- **Keep .TODO file updated** with task lists and completion status
- **Update these files in real-time** as work progresses
- **Add to .gitignore**: Both .PLAN and .TODO files must be in .gitignore
- **File format**: Use simple text format for easy recovery
- **Automatic recovery**: Upon restart, check for existing files to resume work

### Dependency Security Requirements
- **ALWAYS check for Dependabot alerts** before every commit
- **Monitor vulnerabilities via Socket.dev** for all dependencies
- **Mandatory security scanning** before any dependency changes
- **Fix all security alerts immediately** - no commits with outstanding vulnerabilities
- **Regular security audits**: `npm audit`, `go mod audit`, `safety check`

### Linting & Code Quality Requirements
- **ALL code must pass linting** before commit - no exceptions
- **Python**: flake8, black, isort, pytest, pytest-cov, mypy (type checking), bandit (security)
- **Go**: golangci-lint (includes staticcheck, gosec, etc.)
- **Docker**: hadolint, trivy
- **YAML**: yamllint
- **Markdown**: markdownlint
- **Shell**: shellcheck
- **CodeQL**: All code must pass CodeQL security analysis
- **PEP Compliance**: Python code must follow PEP 8, PEP 257 (docstrings), PEP 484 (type hints)

### Build & Deployment Requirements
- **NEVER mark tasks as completed until successful build verification**
- All Go and Python builds MUST be executed within Docker containers
- Use containerized builds for local development and CI/CD pipelines
- Build failures must be resolved before task completion

### Documentation Standards
- **Markdown file locations** (STRICT):
  - `{PROJECT_ROOT}/README.md` - Project overview only
  - `{PROJECT_ROOT}/CLAUDE.md` - Claude Code context only
  - `{PROJECT_ROOT}/docs/` - ALL other markdown documentation
  - **NEVER nest markdown files in subdirectories** outside of `docs/`
- **README.md**: Keep as overview and pointer to comprehensive docs/ folder
- **docs/ folder**: Create comprehensive documentation for all aspects
- **RELEASE-NOTES.md**: Maintain in docs/ folder, prepend new version releases to top
- Update CLAUDE.md when adding significant context
- **Build status badges**: Always include in README.md
- **ASCII art**: Include catchy, project-appropriate ASCII art in README
- **Company homepage**: Point to www.penguintech.io
- **License**: All projects use Limited AGPL3 with preamble for fair use

### File Size Limits
- **Maximum file size**: 25,000 characters for ALL code and markdown files
- **Split large files**: Decompose into modules, libraries, or separate documents
- **CLAUDE.md exception**: Maximum 39,000 characters (only exception to 25K rule)
- **High-level approach**: CLAUDE.md contains high-level context and references detailed docs
- **Documentation strategy**: Create detailed documentation in `docs/` folder and link to them from CLAUDE.md
- **Keep focused**: Critical context, architectural decisions, and workflow instructions only

## Development Standards

Comprehensive development standards are documented separately to keep this file concise.

📚 **Complete Standards Documentation**: [Development Standards](docs/STANDARDS.md)

## Application Architecture

**ALWAYS use microservices architecture** - decompose into specialized, independently deployable containers:

1. **Proxy Service**: Go application for database protocol handling and query routing
2. **Manager Service**: Flask + Flask-Security-Too backend for REST API and management

**Default Container Separation**: Proxy and Manager are ALWAYS separate containers. This provides:
- Independent scaling of services
- Different resource allocation per service
- Separate deployment lifecycles
- Technology-specific optimization

**Benefits**:
- Independent scaling
- Technology diversity
- Team autonomy
- Resilience
- Continuous deployment

📚 **Detailed Architecture Patterns**: See [Development Standards - Microservices Architecture](docs/STANDARDS.md)

## Common Integration Patterns

### Go Proxy + Python Manager Architecture

ArticDBM uses a specialized hybrid architecture optimized for database proxy operations:

**Go Proxy (High-Performance Layer)**:
- Protocol handling: MySQL wire protocol, PostgreSQL wire protocol
- Connection pooling and lifecycle management
- Real-time SQL injection detection and threat blocking
- Query routing and load balancing to backend databases
- Metrics collection and health monitoring
- Zero-copy packet processing with XDP support (optional)

**Python Manager (Management & Configuration Layer)**:
- REST API for configuration management
- User and API key management with Flask-Security-Too
- Threat intelligence feed integration (STIX/TAXII, OpenIOC, MISP)
- Audit logging and usage tracking
- License validation and feature gating
- Dashboard and analytics

**Communication Pattern**:
- Manager → Proxy: Configuration updates via gRPC or HTTP/3 (QUIC)
- Proxy → Manager: Metrics and events via Prometheus scrape or push
- Both → Database: Standard database protocol (MySQL/PostgreSQL wire protocol)
- Both → Redis: Configuration distribution and caching

**Database Type Handling**:
- Go Proxy: Handles multiple DB_TYPE connections transparently
  - PostgreSQL (lib/pq) - Default wire protocol
  - MySQL/MariaDB (go-sql-driver/mysql) - MySQL wire protocol
  - SQLite (mattn/go-sqlite3) - Embedded support
  - Galera - MySQL protocol with WSREP awareness
- Python Manager: Manages schemas and migrations via PyDAL
  - Database initialization: SQLAlchemy only
  - Day-to-day operations: PyDAL exclusively
  - DB_TYPE environment variable drives connection strings

**Key Patterns**:
1. **Multi-Database Abstraction**: Proxy handles protocol translation, Manager handles schema consistency
2. **Threat Intelligence Pipeline**: STIX feeds → Manager → Proxy cache → Real-time detection
3. **Performance-Safety Balance**: Go handles speed, Python handles correctness
4. **Configuration Distribution**: Redis-backed config prevents proxy restarts on updates

📚 **Complete Integration Examples**: [Development Standards](docs/STANDARDS.md)

## Template Customization

ArticDBM follows the Penguin Tech Inc project template with important restrictions:

**DO NOT modify**:
- Language requirements (Go 1.23.x for proxy, Python 3.12+ for manager)
- DB_TYPE support (must support all 4 database types identically)
- Microservices separation (proxy and manager always separate containers)
- Security requirements (SQL injection detection, threat intelligence, auth/authz mandatory)
- License integration with PenguinTech License Server

**CAN customize**:
- Additional threat intelligence sources beyond STIX/TAXII/OpenIOC/MISP
- Custom metric collection for specific use cases
- Performance tuning parameters (connection pool sizing, warmup percentages)
- Logging verbosity and audit retention policies
- Dashboard layouts in manager UI

**Database Type Restrictions**:
- All DB_TYPE values (postgres, mysql, sqlite, galera) MUST be supported
- Behavior must be identical across all database types
- Connection strings MUST follow PyDAL conventions for Python manager
- Proxy protocol handling MUST support all database wire protocols
- NO database-specific optimizations that break other databases

**WARNING**: Removing database support or allowing divergent behavior breaks the core ArticDBM value proposition. Template customization is secondary to maintaining proxy integrity across all supported databases.

📚 **Customization Guidelines**: [Development Standards](docs/STANDARDS.md)

## ArticDBM-Specific Features

### SQL Injection Detection
- Pattern-based detection in `proxy/internal/security/checker.go`
- 40+ attack patterns including SQL injection, shell commands, and default resource blocking
- Real-time threat prevention with detailed analysis
- Configurable security rules via manager

### Threat Intelligence Integration
- **STIX/TAXII Feeds**: Industry-standard threat intelligence formats
- **OpenIOC Support**: XML-based indicators of compromise
- **MISP Integration**: Real-time threat intelligence platform integration
- **Per-Database Security Policies**: Configurable threat response per database
- **Advanced Threat Detection**: Pattern matching with confidence scoring
- **Threat Intelligence Bypass Rules**: Custom override capabilities

### Enhanced Authentication/Authorization
- **Multi-Factor Authentication**: Username/password + API keys + temporary tokens
- **API Key Management**: 32-byte cryptographically secure tokens for programmatic access
- **Temporary Access**: One-time tokens with automatic expiration and usage limits
- **Per-User Security Controls**: TLS enforcement, IP whitelisting, rate limiting
- **Account Expiration**: Time-limited access with automatic cleanup
- **Permission Granularity**: Database, table, and action-level permissions with time limits
- **Usage Tracking**: Query counts, connection monitoring, security event logging

### Performance Optimizations
- **Enhanced Connection Pooling**: 80% idle connections for faster reuse
- **Connection Warmup**: Pre-establishes 30% of max connections on startup
- **Smart Lifecycle Management**: 3-minute connection lifetime, 60-second idle timeout
- **Read/Write Splitting**: Automatic query routing based on operation type
- **Load Balancing**: Thread-safe backend selection with health monitoring
- **Hot Path Optimizations**: String optimization, buffer pool reuse, cache efficiency

### Monitoring & Metrics
**Prometheus Metrics** (available at `:9090/metrics`):
- `articdbm_active_connections` - Active connection count
- `articdbm_total_queries` - Total queries processed
- `articdbm_query_duration_seconds` - Query execution time
- `articdbm_auth_failures_total` - Authentication failures
- `articdbm_sql_injection_attempts_total` - Blocked injections

**Audit Logging**:
- All queries logged to `audit_log` table
- User activity tracking
- IP address recording

## Troubleshooting & Support

### Common Issues
1. **Connection Issues**: Check port bindings, verify backend database connectivity
2. **Performance Issues**: Monitor connection pool utilization, review query patterns
3. **Security Issues**: Review SQL injection patterns, check user permissions

### Debug Commands
```bash
# Container debugging
docker-compose logs -f proxy
docker-compose logs -f manager

# Check proxy metrics
curl http://localhost:9090/metrics

# Access manager API
curl http://localhost:8000/api/health

# License debugging
make license-debug            # Test license server connectivity
make license-validate         # Validate current license
```

### Support Resources
- **Technical Documentation**: See `docs/` folder
- **Integration Support**: support@penguintech.io
- **Sales Inquiries**: sales@penguintech.io
- **License Server Status**: https://status.penguintech.io

## CI/CD & Workflows

### Documentation
- **Complete workflow documentation**: See [`docs/WORKFLOWS.md`](docs/WORKFLOWS.md)
- **CI/CD standards and requirements**: See [`docs/STANDARDS.md`](docs/STANDARDS.md)

### Build Naming Conventions

All container images follow automatic naming based on branch and version changes:

| Scenario | Main Branch | Other Branches |
|----------|------------|-----------------|
| Regular build (no `.version` change) | `beta-<epoch64>` | `alpha-<epoch64>` |
| Version release (`.version` changed) | `vX.X.X-beta` | `vX.X.X-alpha` |
| Tagged release | `vX.X.X` + `latest` | N/A |

**Example**: Updating `.version` to `1.2.0` on main branch triggers builds tagged `v1.2.0-beta` (and auto-creates a GitHub pre-release).

### Pre-Commit Checklist

Before committing, run in this order:

- [ ] **Linters**: `golangci-lint run` or `flake8 .` or equivalent
- [ ] **Security scans**: `gosec ./...`, `bandit -r .`, etc. (per language)
- [ ] **Tests**: `go test ./...`, `pytest`, etc. (unit tests only)
- [ ] **Version updates**: Update `.version` if releasing new version
- [ ] **Documentation**: Update docs if adding/changing workflows
- [ ] **No secrets**: Verify no credentials, API keys, or tokens in code
- [ ] **Docker builds**: Verify Dockerfile uses debian-slim base (no alpine)

**Only commit when asked** — follow the pre-commit checklist above, then wait for approval before `git commit`.

---

**Project Version**: See `.version` file
**Last Updated**: 2025-12-18
**Maintained by**: Penguin Tech Inc
**License Server**: https://license.penguintech.io

*This document should be updated as the project evolves. Keep it current with any architectural changes or new features.*
