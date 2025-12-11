# ArticDBM CI/CD Workflows

This document describes the GitHub Actions workflows that power ArticDBM's continuous integration and deployment pipeline.

## Overview

ArticDBM uses a comprehensive CI/CD pipeline with separate workflows for each service component:

- **Proxy Service** (Go) - High-performance database proxy
- **Manager Service** (Python py4web) - Configuration and management UI
- **DB-Manager Service** (Included in build-containers.yml) - Database management utilities

## Workflow Architecture

### Build Workflows

#### 1. build-containers.yml
Multi-service container build pipeline combining all ArticDBM components.

**Triggers:**
- Push to any branch when service code or `.version` changes
- Pull requests to main branch
- Release events
- Manual trigger (workflow_dispatch)

**Jobs:**
1. `build-proxy` - Build Go proxy container
   - Docker multi-arch build (amd64, arm64)
   - Trivy vulnerability scanning
   - GHCR registry push

2. `build-manager` - Build Python manager container
   - Docker multi-arch build (amd64, arm64)
   - Trivy vulnerability scanning
   - GHCR registry push

3. `build-summary` - Generate build summary
   - Version information
   - Architecture details
   - Pull examples and usage

**Path Filters:**
```yaml
paths:
  - 'proxy/**'
  - 'manager/**'
  - 'DB-Manager/**'
  - '.version'
  - '.github/workflows/build-containers.yml'
```

#### 2. proxy-build.yml
Specialized Go proxy service build with comprehensive security scanning.

**Pipeline:**
```
lint (golangci-lint + gosec)
  ↓
test (go test with coverage)
  ↓
build (Docker + Trivy scan)
```

**Security Scanning:**
- **golangci-lint**: Multi-tool linting (staticcheck, gosec, etc.)
- **gosec**: Go security scanner (high/medium confidence)
- **Trivy**: Container vulnerability scanning (SARIF format)
- **CodeQL**: GitHub code analysis (automatic)

**Go Version:** 1.23

**Tags Applied:**
- `alpha-<epoch64>`: Feature branch builds without version change
- `beta-<epoch64>`: Main branch builds without version change
- `v<semver>-alpha`: Feature branch builds with version change
- `v<semver>-beta`: Main branch builds with version change
- `v<semver>`: Release tag builds
- `latest`: Release versions

#### 3. manager-build.yml
Specialized Python manager service build with comprehensive linting.

**Pipeline:**
```
lint (flake8 + black + isort + bandit)
  ↓
test (pytest with coverage + test database)
  ↓
build (Docker + Trivy scan)
```

**Security Scanning:**
- **flake8**: Style and error checking
- **black**: Code formatter enforcement
- **isort**: Import sorting
- **mypy**: Type checking
- **bandit**: Python security scanner (low severity)
- **Trivy**: Container vulnerability scanning
- **CodeQL**: Automatic GitHub analysis

**Python Version:** 3.12

**Test Database:** PostgreSQL 16-alpine

**Tags Applied:**
- `alpha-<epoch64>`: Feature branch builds without version change
- `beta-<epoch64>`: Main branch builds without version change
- `v<semver>-alpha`: Feature branch builds with version change
- `v<semver>-beta`: Main branch builds with version change
- `v<semver>`: Release tag builds
- `latest`: Release versions

#### 4. version-release.yml
Automated release creation when `.version` file changes.

**Triggers:**
- Push to main branch when `.version` changes

**Jobs:**
1. Validates `.version` file exists and is not default (0.0.0)
2. Checks if release already exists
3. Generates automatic release notes
4. Creates GitHub pre-release with SARIF data

**Version Format:** Semantic versioning (Major.Minor.Patch)

**Release Behavior:**
- Version 0.0.0 (default): Skipped
- New versions: Pre-release created automatically
- Existing versions: Skipped (no duplicate releases)

## Version Management

### .version File Format
```
v<Major>.<Minor>.<Patch>
```

Example: `v1.2.3`

### Version Detection

Each build workflow includes version detection logic:

```bash
if [ -f .version ]; then
  VERSION=$(cat .version | tr -d '[:space:]')
  SEMVER=$(echo "$VERSION" | cut -d'.' -f1-3)

  # Check if .version changed in last commit
  if git diff --name-only HEAD^ HEAD | grep -q "^.version$"; then
    echo "changed=true"
  else
    echo "changed=false"
  fi
fi
```

### Updating Versions

To release a new version:

```bash
# Edit .version file
echo "v1.2.4" > .version

# Commit and push
git add .version
git commit -m "Release v1.2.4"
git push origin main
```

This automatically triggers:
1. Container builds with versioned tags (v1.2.4-beta)
2. GitHub pre-release creation
3. Artifact generation

## Image Tagging Strategy

### Branch-Based Tags

**Regular Builds** (no `.version` change):
- Feature branch: `alpha-<unix-timestamp>`
- Main branch: `beta-<unix-timestamp>`

**Version Releases** (`.version` changed):
- Feature branch: `v<semver>-alpha`
- Main branch: `v<semver>-beta`

**Release Tags** (git tag):
- Release version: `v<semver>` + `latest`

### Pull Examples

```bash
# Alpha build from feature branch
docker pull ghcr.io/penguintechinc/articdbm/proxy:alpha-1733949234

# Beta build from main
docker pull ghcr.io/penguintechinc/articdbm/manager:beta-1733949234

# Version release
docker pull ghcr.io/penguintechinc/articdbm/proxy:v1.2.4-beta
docker pull ghcr.io/penguintechinc/articdbm/manager:v1.2.4

# Latest release
docker pull ghcr.io/penguintechinc/articdbm/proxy:latest
```

## Security Scanning

### Multi-Layer Security

1. **Source Code Analysis**
   - golangci-lint (Go)
   - flake8, bandit (Python)
   - CodeQL (automatic)

2. **Container Scanning**
   - Trivy (vulnerability database)
   - SARIF format (GitHub integration)
   - Automatic Security tab updates

3. **Dependency Monitoring**
   - Dependabot alerts
   - Build failure on high severity
   - Manual review required

### Scan Results

Security scan results are automatically uploaded to GitHub Security tab:
- **Code scanning**: Source code vulnerabilities
- **Container scanning**: Trivy results in SARIF format
- **Dependency alerts**: Third-party vulnerability tracking

Access results:
1. GitHub repo → Security tab
2. Code scanning tab for source analysis
3. Container registry → Image details for runtime scan

## Workflows Configuration

### Environment Variables

```yaml
REGISTRY: ghcr.io
PROXY_IMAGE_NAME: ${{ github.repository }}/proxy
MANAGER_IMAGE_NAME: ${{ github.repository }}/manager
```

### Permissions

Each workflow job includes minimal required permissions:
- `contents: read` - Repository access
- `packages: write` - Container registry push

### Cache Strategy

GitHub Actions cache used for:
- Go mod cache (proxy builds)
- Python pip cache (manager builds)
- Docker layer cache (buildx GHA cache)

## Troubleshooting

### Build Failures

**Lint Failures:**
```bash
# Proxy (Go)
cd proxy && golangci-lint run

# Manager (Python)
cd manager && flake8 . && black . && isort . && bandit -r .
```

**Test Failures:**
- Check test logs in GitHub Actions
- Run tests locally: `go test ./...` or `pytest`
- Ensure test databases are available

**Registry Push Failures:**
- Verify GitHub token has `write:packages` scope
- Check registry credentials in secrets
- Ensure workflow has `packages: write` permission

### Security Scan Issues

**gosec Findings (Proxy):**
- Review findings in GitHub Security tab
- False positives can be suppressed with `// #nosec`
- Update dependencies if vulnerabilities found

**bandit Findings (Manager):**
- Review findings in GitHub Security tab
- Low severity issues can be documented
- Fix or document all issues

**Trivy Findings (Containers):**
- Update base images (Debian, Python, Go)
- Update dependencies in Dockerfile
- Use image scanning as risk assessment tool

## Workflow Compliance

All workflows adhere to .WORKFLOW compliance standards:

✓ `.version` file monitoring
✓ Epoch64 timestamp generation
✓ Version detection logic
✓ Conditional metadata tags
✓ Multi-architecture builds (amd64, arm64)
✓ Security scanning (gosec, bandit, Trivy)
✓ SARIF result uploads
✓ Build summary reporting
✓ Release automation

## Related Documentation

- [DEVELOPMENT.md](DEVELOPMENT.md) - Development guidelines
- [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
- [SECURITY-CENTER.md](SECURITY-CENTER.md) - Security policies
- [RELEASE-NOTES.md](RELEASE-NOTES.md) - Version history

---

**Last Updated:** 2025-12-11
**Maintained by:** Penguin Tech Inc
