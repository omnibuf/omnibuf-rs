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

# Run the cross-language OmniBuf conformance suite (1109 test cases across all 4 tiers)
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
    elif command -v go >/dev/null 2>&1; then
        exec go run github.com/omnibuf/omnibuf-go/cmd/conformance-runner@v0.2.11 ./target/release/conformance-rs
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

# Check public API semver compatibility against crates.io
semver:
    cargo semver-checks --workspace --all-features

# Verify crate packaging and rustdoc for crates.io
publish-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --exclude conformance-rs --exclude omnibuf-bench --all-features
    cargo package -p omnibuf-derive
    cargo package -p protoc-gen-omnibuf-rs
    cargo package -p omnibuf

# Publish omnibuf-derive, omnibuf, and protoc-gen-omnibuf-rs to crates.io in dependency order
publish:
    #!/usr/bin/env bash
    set -euo pipefail
    VERSION=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml","rb"))["workspace"]["package"]["version"])')
    publish_one() {
        local crate="$1"
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" -H "User-Agent: omnibuf-publish/0.1" "https://crates.io/api/v1/crates/${crate}/${VERSION}")
        if [[ "$code" == "200" ]]; then
            echo "${crate} v${VERSION} is already on crates.io; skipping."
            return 0
        fi
        cargo publish -p "${crate}"
    }
    publish_one omnibuf-derive
    echo "Waiting for omnibuf-derive v${VERSION} in crates.io sparse index..."
    for _ in $(seq 1 30); do
        if curl -fsSL -H "User-Agent: omnibuf-publish/0.1" "https://index.crates.io/om/ni/omnibuf-derive" 2>/dev/null | grep -q "\"vers\":\"${VERSION}\""; then
            break
        fi
        sleep 3
    done
    publish_one omnibuf
    publish_one protoc-gen-omnibuf-rs

# Run the complete CI verification pipeline
ci: fmt-check lint build test conformance
