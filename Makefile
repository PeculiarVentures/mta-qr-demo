.PHONY: all test build interop clean install

# Default target
all: install test build

# Install TypeScript dependencies
install:
	cd ts && npm ci

# Run all unit tests (Go + TypeScript)
test: test-go test-ts

test-go:
	cd go && go test ./... -count=1

test-ts:
	cd ts && npm run test:all

# Type-check TypeScript
typecheck:
	cd ts && npx tsc --noEmit

# Build Go binaries
build:
	cd go && go build ./...

# Run the full interop matrix (12 positive cells + 3 negative tests)
# Builds Go binaries, starts all 6 services, tests all cells, shuts down.
interop: build
	python3 interop_test.py

# Start all four default services locally (Ed25519, foreground — use tmux or run in separate terminals)
run-go-issuer:
	cd go && go run ./issuer/

run-go-verifier:
	cd go && go run ./verifier/

run-ts-issuer:
	cd ts && npx tsx issuer/main.ts

run-ts-verifier:
	cd ts && npx tsx verifier/main.ts

# Docker Compose (Ed25519 services)
up:
	docker compose up --build

down:
	docker compose down

# Remove build artifacts
clean:
	rm -f /tmp/mta-go-issuer /tmp/mta-go-verifier
	cd go && go clean ./...
	cd ts && rm -rf dist

# Re-generate signing test vectors (Go only — requires the private key material)
gen-vectors:
	cd go/shared/signing && go run gen_signing_vectors.go
