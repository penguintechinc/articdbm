# ArticDBM - Claude Code Context

## Project Overview

**ArticDBM (Arctic Database Manager)** is a comprehensive enterprise-grade database management platform that provides:

- **Multi-database support**: PostgreSQL, MySQL, SQLite (with MariaDB Galera cluster support)
- **Advanced Security**: SQL injection detection, threat intelligence integration, authentication, authorization
- **Performance**: Optimized connection pooling, read/write splitting, load balancing, warmup
- **Enterprise Auth**: API keys, temporary access tokens, IP whitelisting, rate limiting, TLS enforcement
- **Threat Intelligence**: STIX/TAXII feeds, OpenIOC support, MISP integration, real-time blocking
- **Monitoring**: Prometheus metrics, comprehensive audit logging, usage tracking
- **High availability**: Cluster mode with shared configuration
- **MSP Ready**: Multi-tenant support, usage-based billing, white-label capabilities

**Template Features:**
- Multi-language support (Python 3.12+ backend, React frontend)
- Enterprise security and licensing integration
- Comprehensive CI/CD pipeline
- Production-ready containerization
- Monitoring and observability
- Version management system
- PenguinTech License Server integration

## Technology Stack

### Languages & Frameworks

**Python Stack (Backend)**:
- **Python**: 3.12+ for backend application
- **Web Framework**: Flask + Flask-Security-Too (mandatory)
- **Database**:
  - **SQLAlchemy**: Database initialization (schema creation)
  - **PyDAL**: Migrations and day-to-day operations (mandatory)
- **Cache**: Redis (aioredis)
- **Auth**: Flask-Security-Too with multi-factor support
- **Use Case**: REST API endpoints, user management, configuration, audit logging

**React Stack (WebUI)**:
- **React**: Latest LTS version with TypeScript
- **State Management**: Redux or Context API
- **UI Framework**: Material-UI or similar component library
- **HTTP Client**: axios or fetch API
- **Build Tool**: Vite or Create React App
- **Use Case**: Dashboard, configuration interface, user management, real-time monitoring

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

## MarchProxy Integration

ArticDBM integrates with MarchProxy for advanced database proxy capabilities when deployed in high-performance environments.

**When to Use MarchProxy with ArticDBM:**
- High-throughput database access requirements (>10k queries/sec)
- Ultra-low latency networking constraints
- Advanced connection pooling and multiplexing
- Protocol-level query optimization
- Real-time query performance monitoring

**Integration Pattern (ArticDBM):**
- MarchProxy runs as transparent proxy layer between clients and Manager
- Manager delegates protocol handling to MarchProxy
- MarchProxy provides statistics collection for dashboard display
- License-gate MarchProxy features as enterprise functionality
- Performance optimizations visible in WebUI monitoring

**Connection Flow**:
- Client → MarchProxy (proxy layer)
- MarchProxy → Manager (REST API for config)
- Manager → Backend Database (via PyDAL)

📚 **MarchProxy Documentation**: Refer to MarchProxy project documentation for advanced configuration

## Elder Integration

ArticDBM integrates with Elder for distributed logging and observability across multi-node deployments.

**When to Use Elder with ArticDBM:**
- Multi-datacenter deployments requiring centralized logging
- Complex audit trail requirements for compliance
- Distributed tracing across Manager and WebUI services
- Long-term log retention and analysis
- Real-time log aggregation and searching

**Integration Pattern (ArticDBM):**
- Manager service sends logs to Elder aggregator
- WebUI logs captured via browser-based logging client
- Elder provides centralized log querying API
- Manager dashboard integrates Elder log search UI
- License-gate advanced logging features

**Log Collection**:
- Manager → Elder: Application and audit logs
- WebUI → Elder: Client-side events and performance metrics
- Audit Trail: Structured logging of all security-relevant events

📚 **Elder Documentation**: Refer to Elder project documentation for deployment and configuration

## Project Structure

```
ArticDBM/
├── manager/                 # Python Flask backend
│   ├── app.py              # Main manager application
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Manager container
├── webui/                   # React frontend application
│   ├── public/             # Static assets
│   ├── src/                # React source code
│   │   ├── components/     # React components
│   │   ├── pages/          # Page components
│   │   ├── services/       # API clients
│   │   ├── App.tsx         # Main app component
│   │   └── index.tsx       # Entry point
│   ├── package.json        # Dependencies
│   └── Dockerfile          # WebUI container
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
| **manager** | Python 3.12+ Flask | REST API, user management, configuration, audit logging | 8000 |
| **webui** | React + TypeScript | Dashboard, configuration interface, monitoring, real-time updates | 3000 |
| **Supporting** | PostgreSQL/Redis | Data persistence, caching, configuration distribution | 5432, 6379 |

### Deployment Topology

```
┌─────────────────────────────────────┐
│        Load Balancer / Ingress       │
└─┬───────────────────┬─────────────┬─┘
  │                   │             │
  ▼                   ▼             ▼
┌─────────────┐ ┌──────────────┐ ┌────────────┐
│  Manager (x2)│ │  WebUI (x2) │
└─────────────┘ └──────────────┘
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
# Deploy manager to development namespace
helm install manager k8s/helm/manager \
  --namespace dev \
  --values k8s/helm/manager/values-dev.yaml

# Deploy webui
helm install webui k8s/helm/webui --namespace dev
```

### Raw Manifests (`k8s/manifests/`)
```bash
# Apply namespace and RBAC
kubectl apply -f k8s/manifests/namespace.yaml
kubectl apply -f k8s/manifests/rbac.yaml

# Deploy services
kubectl apply -f k8s/manifests/manager/
kubectl apply -f k8s/manifests/webui/
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
- **Manager Integrity**: Query validation, threat intelligence integration, zero data loss
- **Multi-Database Support**: PostgreSQL, MySQL, SQLite, MariaDB Galera must work identically
- **Security Enforcement**: Auth/authz, audit logging, Flask-Security-Too are mandatory
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
- ❌ Bypassing Flask-Security-Too authentication requirements
- ❌ Hardcoding database connection strings

#### Quality Checklist Before Completion
- ✅ All error cases handled properly
- ✅ Unit tests cover all code paths
- ✅ Integration tests verify component interactions
- ✅ Smoke tests verify build, run, API health, and manager stability
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
- ✅ WebUI integration tests passing

### Git Workflow
- **NEVER commit automatically** unless explicitly requested by the user
- **NEVER push to remote repositories** under any circumstances
- **ONLY commit when explicitly asked** - never assume commit permission
- Always use feature branches for development
- Require pull request reviews for main branch
- Automated testing must pass before merge

**Before Every Commit - Security Scanning**:
- **Run security audits on all modified packages**:
  - **Python packages**: Run `bandit -r .` and `safety check` on modified services
  - **Node packages**: Run `npm audit` on WebUI modifications
- **Do NOT commit if security vulnerabilities are found** - fix all issues first
- **Document vulnerability fixes** in commit message if applicable

**Before Every Commit - API Testing**:
- **Create and run API testing scripts** for each modified service
- **Testing scope**: All new endpoints and modified functionality
- **Test files location**: `tests/api/` directory with service-specific subdirectories
- **Run before commit**: Each test script should be executable and pass completely

**Before Every Commit - Screenshots** (if applicable):
- **Run screenshot tool to update UI screenshots in documentation**
  - Run `cd webui && npm run screenshots` to capture current UI state
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
- **JavaScript/TypeScript**: eslint, prettier, jest, ts-jest (for React WebUI)
- **Docker**: hadolint, trivy
- **YAML**: yamllint
- **Markdown**: markdownlint
- **Shell**: shellcheck
- **CodeQL**: All code must pass CodeQL security analysis
- **PEP Compliance**: Python code must follow PEP 8, PEP 257 (docstrings), PEP 484 (type hints)
- **React Standards**: React best practices, hooks rules, accessibility (a11y) compliance

### Build & Deployment Requirements
- **NEVER mark tasks as completed until successful build verification**
- All Python and Node.js builds MUST be executed within Docker containers
- Use containerized builds for local development and CI/CD pipelines
- Build failures must be resolved before task completion
- React WebUI must build without warnings in production mode

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

1. **Manager Service**: Flask + Flask-Security-Too backend for REST API and management
2. **WebUI Service**: React frontend for dashboard and user interface

**Default Container Separation**: Manager and WebUI are ALWAYS separate containers. This provides:
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

### Python Manager + React WebUI Architecture

ArticDBM uses a specialized hybrid architecture optimized for database management platform operations:

**Python Manager (Backend & API Layer)**:
- REST API for configuration management and data access
- User and API key management with Flask-Security-Too
- Threat intelligence feed integration (STIX/TAXII, OpenIOC, MISP)
- Audit logging and usage tracking
- License validation and feature gating
- Database schema management via PyDAL

**React WebUI (Frontend & Dashboard Layer)**:
- Interactive dashboard and real-time monitoring
- User management interface
- Configuration management UI
- Query execution and result visualization
- Threat intelligence policy management
- Usage analytics and reporting

**Communication Pattern**:
- WebUI → Manager: REST API calls via axios/fetch
- WebUI ↔ Manager: Real-time updates via WebSocket connections
- Manager → Database: Standard database access via PyDAL and SQLAlchemy
- Manager → Redis: Configuration distribution and caching

**Database Type Handling**:
- Python Manager: Manages multiple DB_TYPE connections transparently
  - PostgreSQL - Primary supported database
  - MySQL/MariaDB - Full support with Galera awareness
  - SQLite - Development and testing support
  - Galera - MySQL protocol with WSREP awareness
- Database initialization: SQLAlchemy only
- Day-to-day operations: PyDAL exclusively
- DB_TYPE environment variable drives connection strings

**Key Patterns**:
1. **Client-Server Architecture**: WebUI handles presentation, Manager handles business logic
2. **Threat Intelligence Pipeline**: STIX feeds → Manager → WebUI → Real-time alerts
3. **Data Consistency**: Manager enforces consistency, WebUI displays real-time state
4. **Configuration Distribution**: Redis-backed config for distributed deployments

📚 **Complete Integration Examples**: [Development Standards](docs/STANDARDS.md)

## Template Customization

ArticDBM follows the Penguin Tech Inc project template with important restrictions:

**DO NOT modify**:
- Language requirements (Python 3.12+ for manager, React for WebUI)
- DB_TYPE support (must support all 4 database types identically)
- Microservices separation (manager and webui always separate containers)
- Security requirements (threat intelligence, auth/authz, Flask-Security-Too mandatory)
- License integration with PenguinTech License Server

**CAN customize**:
- Additional threat intelligence sources beyond STIX/TAXII/OpenIOC/MISP
- Custom metric collection and visualization in WebUI
- Performance tuning parameters and optimization settings
- Logging verbosity and audit retention policies
- Dashboard layouts and UI components in WebUI
- React component library and styling framework choices

**Database Type Restrictions**:
- All DB_TYPE values (postgres, mysql, sqlite, galera) MUST be supported
- Behavior must be identical across all database types
- Connection strings MUST follow PyDAL conventions for Python manager
- Database access layer MUST support all database wire protocols
- NO database-specific optimizations that break other databases

**WARNING**: Removing database support or allowing divergent behavior breaks the core ArticDBM value proposition. Template customization is secondary to maintaining manager integrity across all supported databases.

📚 **Customization Guidelines**: [Development Standards](docs/STANDARDS.md)

## ArticDBM-Specific Features

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
**Application Metrics**:
- Request counts and response times
- Database operation metrics
- User activity and session tracking
- API endpoint performance
- Real-time dashboard updates

**Audit Logging**:
- All user actions logged to `audit_log` table
- Database operation history
- Administrative actions tracking
- Security event logging
- IP address and session recording

## Troubleshooting & Support

### Common Issues
1. **Connection Issues**: Check port bindings, verify backend database connectivity
2. **Performance Issues**: Monitor connection pool utilization, review query patterns
3. **Security Issues**: Review SQL injection patterns, check user permissions

### Debug Commands
```bash
# Container debugging
docker-compose logs -f manager
docker-compose logs -f webui

# Access manager API
curl http://localhost:8000/api/health

# Access WebUI
open http://localhost:3000

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

- [ ] **Linters**: `flake8 .`, `eslint .`, `prettier --check .` or equivalent
- [ ] **Security scans**: `bandit -r .`, `npm audit`, `safety check` (per language)
- [ ] **Tests**: `pytest`, `npm test` (unit tests only)
- [ ] **Version updates**: Update `.version` if releasing new version
- [ ] **Documentation**: Update docs if adding/changing workflows
- [ ] **No secrets**: Verify no credentials, API keys, or tokens in code
- [ ] **Docker builds**: Verify Dockerfile uses debian-slim base (no alpine)

**Only commit when asked** — follow the pre-commit checklist above, then wait for approval before `git commit`.

## License & Legal

**License File**: `LICENSE.md` (located at project root)

**License Type**: Limited AGPL-3.0 with commercial use restrictions and Contributor Employer Exception

The `LICENSE.md` file is located at the project root following industry standards. This project uses a modified AGPL-3.0 license with additional exceptions for commercial use and special provisions for companies employing contributors.
---

**Project Version**: See `.version` file
**Last Updated**: 2025-12-18
**Maintained by**: Penguin Tech Inc
**License Server**: https://license.penguintech.io

*This document should be updated as the project evolves. Keep it current with any architectural changes or new features.*
