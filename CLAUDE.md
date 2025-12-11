# ArticDBM - Claude Code Context

This document provides context and information for Claude Code when working with the ArticDBM project.

## Project Overview

**ArticDBM (Arctic Database Manager)** is a comprehensive enterprise-grade database proxy solution that provides:

- **Multi-database support**: MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- **Advanced Security**: SQL injection detection, threat intelligence integration, authentication, authorization
- **Performance**: Optimized connection pooling, read/write splitting, load balancing, warmup
- **Enterprise Auth**: API keys, temporary access tokens, IP whitelisting, rate limiting, TLS enforcement
- **Threat Intelligence**: STIX/TAXII feeds, OpenIOC support, MISP integration, real-time blocking
- **Monitoring**: Prometheus metrics, comprehensive audit logging, usage tracking
- **High availability**: Cluster mode with shared configuration
- **MSP Ready**: Multi-tenant support, usage-based billing, white-label capabilities

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
├── manager/                 # Python py4web manager
│   ├── app.py              # Main manager application
│   ├── requirements.txt    # Python dependencies
│   └── Dockerfile          # Manager container
├── docs/                   # Documentation
│   ├── index.md           # Documentation homepage (lowercase exception)
│   ├── USAGE.md           # Usage guide
│   ├── ARCHITECTURE.md    # Architecture details
│   ├── THREAT-INTELLIGENCE.md  # Threat intelligence guide
│   ├── USER-MANAGEMENT.md # Enhanced user management
│   ├── API_REFERENCE.md   # API documentation
│   ├── RELEASE-NOTES.md   # Release notes
│   └── ...
├── website/               # Website for Cloudflare Pages
├── docker-compose.yml     # Development environment
├── README.md             # Project readme
├── .TODO                 # Project requirements (original)
├── .PLAN                 # Implementation plans and progress
└── CLAUDE.md            # This file
```

## Technology Stack

### Proxy (Go)
- **Language**: Go 1.23.x (latest patch version)
- **Database Drivers**:
  - MySQL: `github.com/go-sql-driver/mysql`
  - PostgreSQL: `github.com/lib/pq`
  - MSSQL: `github.com/denisenkom/go-mssqldb`
  - MongoDB: `go.mongodb.org/mongo-driver`
- **Redis**: `github.com/go-redis/redis/v8`
- **Config**: `github.com/spf13/viper`
- **Logging**: `go.uber.org/zap`
- **Metrics**: `github.com/prometheus/client_golang`

### Manager (Python)
- **Framework**: py4web
- **Database**: PyDAL with PostgreSQL backend
- **Cache**: Redis via `redis` and `aioredis`
- **API**: RESTful endpoints with JSON
- **Auth**: py4web built-in authentication

### Infrastructure
- **Containers**: Docker with multi-stage builds
- **Orchestration**: docker-compose for development
- **Cache/Config**: Redis
- **Database**: PostgreSQL for manager data

## Critical Development Rules

### Development Philosophy: Safe, Stable, and Feature-Complete

**NEVER take shortcuts or the "easy route" - ALWAYS prioritize safety, stability, and feature completeness**

#### Core Principles
- **No Quick Fixes**: Resist quick workarounds or partial solutions
- **Complete Features**: Fully implemented with proper error handling and validation
- **Safety First**: Security, data integrity, and fault tolerance are non-negotiable
- **Stable Foundations**: Build on solid, tested components
- **Future-Proof Design**: Consider long-term maintainability and scalability
- **No Technical Debt**: Address issues properly the first time

#### Red Flags (Never Do These)
- Skipping input validation "just this once"
- Hardcoding credentials or configuration
- Ignoring error returns or exceptions
- Commenting out failing tests to make CI pass
- Deploying without proper testing
- Using deprecated or unmaintained dependencies
- Implementing partial features with "TODO" placeholders
- Bypassing security checks for convenience
- Assuming data is valid without verification
- Leaving debug code or backdoors in production

#### Quality Checklist Before Completion
- All error cases handled properly
- Unit tests cover all code paths
- Integration tests verify component interactions
- Security requirements fully implemented
- Performance meets acceptable standards
- Documentation complete and accurate
- Code review standards met
- No hardcoded secrets or credentials
- Logging and monitoring in place
- Build passes in containerized environment
- No security vulnerabilities in dependencies
- Edge cases and boundary conditions tested

### Git Workflow
- **NEVER commit automatically** unless explicitly requested by the user
- **NEVER push to remote repositories** under any circumstances
- **ONLY commit when explicitly asked** - never assume commit permission
- Always use feature branches for development
- Require pull request reviews for main branch
- Automated testing must pass before merge

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
- **Go**: golangci-lint (includes staticcheck, gosec, etc.)
- **Python**: flake8, black, isort, mypy (type checking), bandit (security)
- **Docker**: hadolint
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
- **Use Task Agents**: Utilize task agents (subagents) for efficiency when making changes to large files

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

**License-Gated Features**:
```python
from shared.licensing import license_client, requires_feature
from py4web import action

@action('api/advanced/analytics')
@requires_feature("advanced_analytics")
def generate_advanced_report():
    """Requires professional+ license"""
    return {'report': analytics.generate_report()}
```

## WaddleAI Integration (Optional)

For projects requiring AI capabilities, integrate with WaddleAI located at `~/code/WaddleAI`.

**When to Use WaddleAI:**
- Natural language processing (NLP)
- Machine learning model inference
- AI-powered features and automation
- Intelligent data analysis
- Chatbots and conversational interfaces

**Integration Pattern:**
- WaddleAI runs as separate microservice container
- Communicate via REST API or gRPC
- Environment variable configuration for API endpoints
- License-gate AI features as enterprise functionality

**ArticDBM AI Use Cases:**
- ML-based anomaly detection for database queries
- Intelligent threat detection patterns
- Query optimization recommendations
- Automated security policy suggestions

## Development Workflow

### Local Development Setup
```bash
git clone <repository-url>
cd ArticDBM
docker-compose up -d
```

### Building and Testing
```bash
# Start development environment
docker-compose up -d

# Build proxy separately
cd proxy && go build -o articdbm-proxy .

# Run manager separately
cd manager && python -m py4web run /app

# Run tests
go test ./...
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

# Testing
make test-unit               # Run unit tests
make test-integration        # Run integration tests

# License Management
make license-validate        # Validate license
make license-check-features  # Check available features
```

### Code Style
- **Go**: Standard Go formatting with `gofmt`
- **Python**: PEP 8 compliant
- **No comments** unless explicitly requested
- **Security-first**: Always validate inputs, use prepared statements

### Documentation Naming Convention
- **All docs**: Use UPPERCASE.md pattern (e.g., `USER-MANAGEMENT.md`, `THREAT-INTELLIGENCE.md`)
- **Exception**: `index.md` remains lowercase as the documentation homepage
- **Consistency**: This pattern applies to all `.md` files in `/docs/` directory

## Enhanced Security Features

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

### Advanced Access Control
- **IP Whitelisting**: CIDR and individual IP access control
- **TLS Per-User**: Force encrypted connections for sensitive accounts
- **Rate Limiting**: Configurable requests per second per user
- **Time-Limited Permissions**: Automatic permission expiration
- **Query Quotas**: Maximum queries per hour per database

## Monitoring & Metrics

### Prometheus Metrics
Available at `:9090/metrics`:
- `articdbm_active_connections` - Active connection count
- `articdbm_total_queries` - Total queries processed
- `articdbm_query_duration_seconds` - Query execution time
- `articdbm_auth_failures_total` - Authentication failures
- `articdbm_sql_injection_attempts_total` - Blocked injections

### Audit Logging
- All queries logged to `audit_log` table
- User activity tracking
- IP address recording

## Configuration Management

### Environment Variables (Proxy)
Key variables in `proxy/internal/config/config.go`:
- `REDIS_ADDR` - Redis connection
- `MYSQL_ENABLED`, `MYSQL_PORT` - MySQL proxy settings
- `SQL_INJECTION_DETECTION` - Enable security checks
- `MAX_CONNECTIONS` - Connection pool size
- `TLS_ENABLED`, `TLS_CERT`, `TLS_KEY` - TLS configuration

### Dynamic Configuration
- Configuration stored in PostgreSQL via manager
- Synced to Redis every 45-75 seconds
- No proxy restart required for most changes

## Performance Optimizations

### Enhanced Connection Pooling
- **Optimized Pool Settings**: 80% idle connections (vs 50%) for faster reuse
- **Connection Warmup**: Pre-establishes 30% of max connections on startup
- **Smart Lifecycle Management**: 3-minute connection lifetime, 60-second idle timeout
- **Context-Aware Timeouts**: 5-second connection timeout prevents hanging

### Load Balancing & Routing
- **Atomic Round-Robin**: Thread-safe backend selection with minimal overhead
- **Read/Write Splitting**: Automatic query routing based on operation type
- **Backend Health Monitoring**: Automatic failover with health checks
- **Connection Locality**: CPU-optimized connection distribution

### Hot Path Optimizations
- **String Optimization**: Replaced `fmt.Sprintf` with direct concatenation
- **Buffer Pool Reuse**: Recycled buffers for reduced GC pressure
- **Cache Efficiency**: Redis-based auth caching with 5-minute TTL
- **Reduced Allocations**: Minimized memory allocations in critical paths

## MSP & Enterprise Capabilities

### Multi-Tenant Architecture
- **Customer Isolation**: Separate API keys, rate limits, and database permissions per tenant
- **Usage-Based Billing**: Query quotas and rate limits for tiered pricing models
- **White-Label Support**: Remove ArticDBM branding, embed in customer applications
- **Compliance Ready**: IP restrictions, TLS enforcement, audit trails for regulated industries

### Revenue Opportunities
- **Database-as-a-Service**: Offer secure managed databases at $50-200/month per customer
- **High Margins**: 70%+ profit margins with automated security and management
- **Premium Features**: Threat intelligence, advanced security, priority support
- **Scalable Business Model**: Multi-tenant SaaS with recurring revenue potential

### Operational Efficiency
- **Automated Provisioning**: API-driven user and database creation
- **Temporary Access**: One-time tokens for contractors and audits
- **Security Automation**: Threat intelligence feeds with automatic blocking
- **Usage Monitoring**: Comprehensive tracking for billing and compliance

## Troubleshooting & Support

### Common Issues

#### Connection Issues
- Check port bindings in docker-compose
- Verify backend database connectivity
- Review firewall rules

#### Performance Issues
- Monitor connection pool utilization
- Check backend database performance
- Review query patterns in audit logs

#### Security Issues
- Review SQL injection patterns
- Check user permissions
- Monitor authentication failures

### Debug Commands
```bash
# Container debugging
docker-compose logs -f proxy
docker-compose logs -f manager

# Full stack restart
docker-compose down && docker-compose up -d

# Connect to test databases
mysql -h localhost -P 3307 -u testuser -p  # Direct to test MySQL
mysql -h localhost -P 3306 -u testuser -p  # Through proxy

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

## Testing Approach

### Unit Tests
- Go tests for proxy components
- Python tests for manager API
- Mock database connections

### Integration Tests
- Full docker-compose stack testing
- Database protocol testing
- Security feature validation

### Performance Tests
- Load testing with `mysqlslap`, `pgbench`
- Connection pool testing
- Latency measurements

## Deployment Patterns

### Development
- docker-compose with all services
- Local PostgreSQL and Redis
- Test databases included

### Production
- Kubernetes deployment
- External managed databases (RDS, Cloud SQL)
- Redis cluster for HA
- Load balancer for proxy instances

## Key Files to Know

### Critical Files
- `proxy/main.go` - Main proxy entry point
- `proxy/internal/config/config.go` - Configuration management
- `manager/app.py` - Manager API and UI
- `docker-compose.yml` - Development environment

### Configuration Files
- `proxy/go.mod` - Go dependencies
- `manager/requirements.txt` - Python dependencies
- `.TODO` - Original requirements (keep updated)
- `.PLAN` - Implementation plans and progress

### Documentation
- `README.md` - Main project documentation
- `docs/` - Comprehensive documentation suite

## Development Tips

### When Working with Proxy
- Always check Redis connection first
- Use structured logging with zap
- Handle database disconnections gracefully
- Monitor connection pool stats

### When Working with Manager
- Use PyDAL for database operations
- Cache frequently accessed data in Redis
- Validate all API inputs
- Use py4web authentication
- **ALWAYS reference py4web documentation**: https://py4web.com/_documentation to ensure compliance with framework standards
- **Deviation from py4web standards**: If implementation deviates from documented py4web patterns, ask user for approval before proceeding

### When Adding New Database Support
1. Add protocol handler in `proxy/internal/handlers/`
2. Update configuration in `config.go`
3. Add Docker service for testing
4. Update documentation

## Future Enhancements

### Planned Features
- Query caching layer
- Enhanced MongoDB support
- GraphQL API support
- Machine learning-based anomaly detection

### Technical Debt
- Add comprehensive unit tests
- Implement graceful shutdown
- Add configuration validation
- Improve error handling

## CI/CD & Workflow Compliance

ArticDBM implements comprehensive CI/CD workflows with .WORKFLOW compliance standards for all three services (proxy, manager, db-manager).

### Workflows Overview

**build-containers.yml**: Multi-service container build with version detection and conditional tagging
- Builds proxy (Go) and manager (Python) services
- Monitors `.version` file for releases
- Generates epoch64 timestamps
- Multi-architecture support (amd64, arm64)
- Trivy vulnerability scanning for both services

**proxy-build.yml**: Specialized Go proxy build pipeline
- golangci-lint + gosec security scanning
- Coverage reporting to codecov
- Conditional metadata tags based on version changes
- Trivy container scanning

**manager-build.yml**: Specialized Python manager build pipeline
- flake8, black, isort, mypy type checking
- bandit security scanning
- PostgreSQL test database
- Coverage reporting
- Trivy container scanning

**version-release.yml**: Automatic release creation
- Triggers on `.version` file changes
- Creates GitHub pre-releases
- Validates semantic versioning
- Prevents duplicate releases

### Version Management

**Format**: `vMajor.Minor.Patch` (e.g., `v1.2.3`)

**Update Process**:
```bash
echo "v1.2.4" > .version
git add .version
git commit -m "Release v1.2.4"
git push origin main
```

**Automatic Actions**:
1. All three services rebuild with version tags
2. GitHub pre-release created
3. Build summary generated
4. Containers tagged v1.2.4-beta (main) or v1.2.4-alpha (feature branches)

### Image Tagging

**Regular Builds** (no `.version` change):
- Main branch: `beta-<unix-timestamp>`
- Feature branches: `alpha-<unix-timestamp>`

**Version Releases** (`.version` changed):
- Main branch: `v<semver>-beta`
- Feature branches: `v<semver>-alpha`

**Release Tags**: `v<semver>` + `latest`

### Security Scanning

**Proxy (Go)**:
- golangci-lint (multi-tool linting)
- gosec (Go security)
- Trivy (container vulnerability)

**Manager (Python)**:
- flake8 (style)
- bandit (Python security)
- mypy (type checking)
- Trivy (container vulnerability)

**Results**: All uploaded to GitHub Security tab as SARIF

### Comprehensive Documentation

- **[docs/WORKFLOWS.md](docs/WORKFLOWS.md)**: Complete workflow documentation
- **[docs/STANDARDS.md](docs/STANDARDS.md)**: Development and CI/CD standards

---

**Project Version**: See `.version` file
**Last Updated**: 2025-12-11
**Maintained by**: Penguin Tech Inc
**License Server**: https://license.penguintech.io

*This document should be updated as the project evolves. Keep it current with any architectural changes or new features.*
