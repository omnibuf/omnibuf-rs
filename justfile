# List available recipes
default:
    @just --list

# Build all workspace crates and binaries
build:
    cargo build --workspace --all-targets

# Build release binaries
build-release:
    cargo build --workspace --release

# Run all Rust unit and integration tests
test:
    cargo test --workspace --all-targets

# Lint, verify, and generate Rust OmniBuf code from proto/ using buf and protoc-gen-omnibuf-rs
proto:
    buf lint
    cargo build -p protoc-gen-omnibuf-rs
    buf generate
    cargo fmt --all

# Alias for proto code generation
generate: proto

# Run the cross-language OmniBuf conformance suite (584 test cases across all 4 tiers)
conformance:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --release -p conformance-rs
    if [[ -n "${CONFORMANCE_RUNNER:-}" ]]; then
        RUNNER="$CONFORMANCE_RUNNER"
    elif [[ -x "../omnibuf-go/bin/conformance-runner" ]]; then
        RUNNER="../omnibuf-go/bin/conformance-runner"
    elif command -v conformance-runner >/dev/null 2>&1; then
        RUNNER="conformance-runner"
    else
        echo "conformance-runner binary not found; set CONFORMANCE_RUNNER or install conformance-runner" >&2
        exit 1
    fi
    "$RUNNER" ./target/release/conformance-rs

# Run the PeerUpdate benchmark suite and write testdata/benchmarks.json
bench:
    cargo run --release -p omnibuf-bench

# Lint all workspace crates and targets with Clippy warnings denied, plus Protobuf schemas via buf
lint:
    cargo clippy --workspace --all-targets -- -D warnings
    buf lint

# Format Rust and Protobuf files in place
fmt:
    cargo fmt --all
    buf format -w

# Check Rust and Protobuf formatting without modifying files
fmt-check:
    cargo fmt --all -- --check
    buf format -d --exit-code

# Run the complete CI verification pipeline
ci: fmt-check lint build test conformance
