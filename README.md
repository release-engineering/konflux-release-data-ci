# konflux-release-data-ci

Config for building CI worker image for konflux-release-data repo, including RBAC validation tools.

## Overview

This repository provides:
- CI worker image configuration for the konflux-release-data repository
- RBAC validation tools using Kubernetes' official validation library
- Development tooling for RBAC policy verification

## RBAC Validator Tool

The `tools/` directory contains a Go-based RBAC validator that uses Kubernetes' official validation logic to verify RBAC policy subsets.

### Purpose

The RBAC validator ensures that user-defined roles and permissions are proper subsets of reference roles, preventing privilege escalation in Konflux tenants. It validates that:

- User roles don't exceed the permissions granted by reference roles
- APIGroups, Resources, Verbs, and ResourceNames are properly constrained
- Multi-rule policies are comprehensively validated

### Components

#### `tools/rbac-validator.go`
Main Go binary that:
- Accepts JSON input with user rules and reference rules
- Uses `k8s.io/component-helpers/auth/rbac/validation.Covers()` for authoritative validation
- Returns JSON output indicating whether user rules are covered by reference rules
- Handles errors gracefully with structured error responses

#### `tools/rbac-validator_test.go`
Comprehensive test suite with:
- **Edge case validation**: APIGroups overlap, subresources, resourceNames constraints
- **Real-world Konflux scenarios**: contributor vs admin roles, release pipeline permissions
- **Binary integration tests**: End-to-end validation of JSON input/output
- **Error handling tests**: Invalid JSON and malformed input validation

#### `tools/Makefile`
Development workflow automation:
```bash
make build      # Build the binary
make test       # Run all tests
make fmt        # Format Go code
make lint       # Run golangci-lint
make check-fmt  # Verify code formatting
make ci         # Run full CI pipeline (format check, lint, test, build)
```

#### `tools/.golangci.yml`
Linting configuration with security and code quality checks.

### Integration

The validator is integrated into the CI container and used by tenant validation scripts:

1. **CI Container**: Binary is pre-built during container image creation
2. **Smart Discovery**: Python scripts automatically find the binary via:
   - PATH lookup for CI environments
   - Local repository build for development
   - On-demand compilation as fallback
3. **Tenant Validation**: Used by `tenants-config/tests/` for validating production and staging tenant roles

### Development Workflow

#### Local Development
```bash
cd tools/
make install-tools  # Install golangci-lint
make ci            # Run full validation pipeline
```

#### Adding Test Cases
Test cases should cover:
- Real Konflux role scenarios from infra-deployments
- Edge cases for RBAC validation behavior
- Error conditions and malformed input

#### Binary Usage
```bash
echo '{"userRules": [...], "referenceRules": [...]}' | ./rbac-validator
```

### Dependencies

- Go 1.22+
- `k8s.io/api` v0.30.0
- `k8s.io/component-helpers` v0.30.0
- golangci-lint (for development)

## CI Worker Image

The main CI worker image includes:
- Python environment with tox support
- Go toolchain for RBAC validator
- Pre-built RBAC validator binary
- Development tools and dependencies

## TODO - Need
* Fix SBOM issues related to the ruby gem install
* Ensure existing CI tests can run in this image
* Try running mkdocs CI jobs and update image as necessary

## TODO - Should Do
* Convert to UBI
  * Setup prefetch for tox (pip)
* Setup prefetch for rpms
* Enable konflux-release-data integration test
  * Migrate to internal cluster
  * Setup integration test that clones krd repo and runs tox
    * Bonus points for running pyxis integration tests
