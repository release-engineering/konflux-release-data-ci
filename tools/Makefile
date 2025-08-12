.PHONY: build test fmt lint clean all

# Binary name
BINARY_NAME := rbac-validator

# Build the binary
build:
	go build -o $(BINARY_NAME) rbac-validator.go

# Run tests
test:
	go test -v ./...

# Run testdata coverage tests specifically
test-coverage:
	go test -v -run TestAllowedRoles
	go test -v -run TestDeniedRoles

# Run integration tests with binary
test-integration: build
	go test -v -run TestBinaryWithTestData

# Run all testdata tests
test-testdata: build
	go test -v -run "TestAllowedRoles|TestDeniedRoles|TestBinaryWithTestData|TestTestDataCompleteness"

# Format Go code
fmt:
	gofmt -w .

# Run linter
lint:
	golangci-lint run

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)

# Run all checks (format, lint, test, build)
all: fmt lint test build

# Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Check if code is formatted
check-fmt:
	@if [ -n "$$(gofmt -l .)" ]; then \
		echo "Code is not formatted. Run 'make fmt' to fix."; \
		gofmt -l .; \
		exit 1; \
	fi

# Verify everything is ready for CI
ci: check-fmt lint test test-testdata build