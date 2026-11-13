# omnibuf-rs

Rust runtime, procedural derive macro, and Buf / Protobuf code generator for the OmniBuf binary wire format.

## Workspace Crates

| Crate | Path | Purpose |
| :--- | :--- | :--- |
| `omnibuf` | `crates/omnibuf` | Core wire codec, single-pass `Encoder`, zero-copy `Decoder`, `Field #0` metadata, `decode_blind`, `splice_fields`, and `prost` / `prost-reflect` integration |
| `omnibuf-derive` | `crates/omnibuf-derive` | `#[derive(OmniBuf)]` procedural macro for native Rust structs and `prost`-generated message structs |
| `protoc-gen-omnibuf-rs` | `crates/protoc-gen-omnibuf-rs` | Buf / Protobuf plugin emitting fast message codecs and zero-unpack `Opaque<T>` packet views |
| `conformance-rs` | `crates/conformance-rs` | Cross-language conformance adapter exercising all 584 vectors across 4 tiers |
| `omnibuf-bench` | `crates/omnibuf-bench` | Reproducible `PeerUpdate` benchmark runner writing `testdata/benchmarks.json` |

## Quick Start

### Native Annotated Structs

```rust
use omnibuf::{EncodeOptions, Message, OmniBuf, decode_blind_json};

#[derive(Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "PeerUpdate")]
pub struct PeerUpdate {
    #[omnibuf(id = 1, name = "asn")]
    pub asn: u32,
    #[omnibuf(id = 2, name = "router_id")]
    pub router_id: String,
    #[omnibuf(id = 3, name = "active")]
    pub active: bool,
    #[omnibuf(id = 5, name = "rssi_dbm", wire = "sint")]
    pub rssi_dbm: i32,
    #[omnibuf(id = 7, name = "tags")]
    pub tags: Vec<String>,
}

fn main() -> omnibuf::Result<()> {
    let update = PeerUpdate {
        asn: 64512,
        router_id: "edge-fra-01".into(),
        active: true,
        rssi_dbm: -68,
        tags: vec!["bgp".into(), "eu-central".into()],
    };

    // Encode with inline Field #0 schema metadata
    let packet = update.encode_omnibuf_with_options(EncodeOptions::self_describing())?;

    // Inspect raw wire bytes with zero schema knowledge
    let json = decode_blind_json(&packet)?;
    assert!(json.contains("\"router_id\":\"edge-fra-01\""));

    // Decode back into a typed Rust struct
    let decoded = PeerUpdate::from_omnibuf(&packet)?;
    assert_eq!(decoded, update);
    Ok(())
}
```

### Code Generation with Buf

Schema modules are configured in `buf.yaml` (v2) and plugin output targets are declared in `buf.gen.yaml` (v2):

```yaml
version: v2
plugins:
  - local: ./target/debug/protoc-gen-omnibuf-rs
    out: crates/conformance-rs/src/generated
    strategy: all
```

Run `just proto` (`cargo build -p protoc-gen-omnibuf-rs && buf generate`) to regenerate Rust message types and zero-unpack `Opaque<Msg><'a>` views. Getters hop field headers in O(1) time via length prefixes and borrow `&str` and `&[u8]` slices directly from the backing packet. Calling `marshal()` rewrites dirty fields via `omnibuf::opaque::splice_fields` and copies clean byte spans verbatim.

### Standard `prost` Integration

Enable the default `prost` feature on `omnibuf` to serialize `prost_reflect::DynamicMessage` and `ReflectMessage` types through `omnibuf::prost_codec::{encode_prost, decode_prost, encode_dynamic, decode_dynamic}`, or attach `#[derive(::omnibuf::OmniBuf)]` via `prost_build::Config::type_attribute` for direct compile-time codecs on `prost` structs.

## Development & Verification

Tool versions are pinned in `mise.toml` (`rust 1.94.0`, `just 1.58.0`, `protobuf 35.1`, `buf 1.75.0`).

```bash
just proto        # Lint schemas and run buf generate with protoc-gen-omnibuf-rs
just build        # Compile all workspace crates and targets
just test         # Run unit and integration tests
just bench        # Run PeerUpdate benchmarks and export testdata/benchmarks.json
just lint         # Run cargo clippy (-D warnings) and buf lint
just conformance  # Run all 584 cross-language conformance cases
just ci           # Run fmt-check, lint, build, test, and conformance
```

## License

MIT
