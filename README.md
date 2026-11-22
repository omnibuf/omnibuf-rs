# omnibuf-rs

[![CI](https://github.com/omnibuf/omnibuf-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/omnibuf/omnibuf-rs/actions/workflows/ci.yml)
[![Wire Spec: v0.1](https://img.shields.io/badge/spec-v0.1-111111?style=flat&labelColor=111111&color=FF4F18)](https://omnibuf.com/spec)
[![Website](https://img.shields.io/badge/website-omnibuf.com-111111?style=flat&labelColor=111111&color=D4FF33)](https://omnibuf.com/rs)

Rust runtime, procedural derive macro, and Buf / Protobuf code generator implementing **[OmniBuf Wire Specification v0.1](https://omnibuf.com/spec)**. Verified against `758/758` cross-language conformance cases.

## Workspace Crates

| Crate | Path | Purpose |
| :--- | :--- | :--- |
| `omnibuf` | `crates/omnibuf` | Core wire codec, single-pass `Encoder`, zero-copy `Decoder`, `Field #0` metadata, `decode_blind`, `splice_fields`, and optional `buffa` and `prost` bridges |
| `omnibuf-derive` | `crates/omnibuf-derive` | `#[derive(OmniBuf)]` procedural macro for native Rust structs, `oneof` enums, `buffa` messages, and `prost` messages |
| `protoc-gen-omnibuf-rs` | `crates/protoc-gen-omnibuf-rs` | Buf / Protobuf plugin emitting typed message codecs, `oneof` enums, and zero-unpack `Opaque<T>` packet views |
| `conformance-rs` | `crates/conformance-rs` | Cross-language conformance adapter passing `758/758` cases across all 4 tiers |
| `omnibuf-bench` | `crates/omnibuf-bench` | Reproducible `PeerUpdate` benchmark suite writing `testdata/benchmarks.json` |

## Feature Flags

`omnibuf` enables `derive`, `buffa`, and `prost` by default. Disabling default features drops `syn`, `buffa`, and `prost`, compiling only the core Prefix-Varint wire primitives, `Field #0`, `opaque`, and `blind` modules for lightweight FFI or embedded targets.

```toml
# Default: #[derive(OmniBuf)] + buffa + prost
omnibuf = "0.1"

# buffa + #[derive(OmniBuf)] only
omnibuf = { version = "0.1", default-features = false, features = ["derive", "buffa"] }

# Pure wire, opaque splicing, and blind decode (zero Protobuf deps)
omnibuf = { version = "0.1", default-features = false }
```

| Feature | Description |
| :--- | :--- |
| `derive` | Re-exports `#[derive(OmniBuf)]` from `omnibuf-derive` |
| `buffa` | Enables `omnibuf::buffa_codec` (`encode_buffa_reflect`, `encode_buffa`, `decode_buffa`, `DynamicMessage`) over `buffa` and `buffa-descriptor` |
| `prost` | Enables `omnibuf::prost_codec` (`encode_prost`, `decode_prost`, `DynamicMessage`) over `prost` and `prost-reflect` |

## Quick Start

### Native Structs and Oneofs

```rust
use omnibuf::{DecodeOptions, EncodeOptions, Message, OmniBuf, decode_blind_json, from_slice_with_options};

#[derive(Debug, PartialEq, OmniBuf)]
pub enum EventPayload {
    #[omnibuf(id = 10, name = "withdraw_prefix")]
    WithdrawPrefix(u32),
    #[omnibuf(id = 11, name = "announce_tag")]
    AnnounceTag(String),
}

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
    #[omnibuf(oneof, tags = "10, 11")]
    pub event: Option<EventPayload>,
}

fn main() -> omnibuf::Result<()> {
    let update = PeerUpdate {
        asn: 64512,
        router_id: "edge-fra-01".into(),
        active: true,
        rssi_dbm: -68,
        tags: vec!["bgp".into(), "eu-central".into()],
        event: Some(EventPayload::AnnounceTag("ixp-de-cix".into())),
    };

    // Encode with inline Field #0 schema metadata
    let packet = update.encode_omnibuf_with_options(EncodeOptions::self_describing())?;

    // Inspect raw wire bytes with zero compile-time schema
    let json = decode_blind_json(&packet)?;
    assert!(json.contains("\"router_id\":\"edge-fra-01\""));

    // Decode with explicit untrusted-input resource caps
    let limits = DecodeOptions {
        max_message_bytes: 1024 * 1024,
        ..DecodeOptions::default_limits()
    };
    let decoded: PeerUpdate = from_slice_with_options(&packet, limits)?;
    assert_eq!(decoded, update);
    Ok(())
}
```

### Code Generation with Buf

Schema modules live in `buf.yaml` v2 and output targets live in `buf.gen.yaml` v2:

```yaml
version: v2
plugins:
  - local: ./target/debug/protoc-gen-omnibuf-rs
    out: crates/conformance-rs/src/generated
    strategy: all
```

Run `just proto` to lint schemas, build `protoc-gen-omnibuf-rs`, and execute `buf generate`. Generated `Opaque<Msg><'a>` views hop field headers in O(1) time via length prefixes and borrow `&str` and `&[u8]` slices straight from the input packet. Untrusted wire buffers validate up front through `Opaque<Msg>::try_new(raw)` and `try_marshal()`, while `marshal()` rewrites dirty fields through `omnibuf::opaque::splice_fields` and copies clean spans verbatim.

```rust
use crate::generated::omnibuf::bench::{OpaquePeerUpdate, PeerUpdate};
use omnibuf::Message;

let pkt = peer.encode_omnibuf()?;
let mut view = OpaquePeerUpdate::try_new(&pkt)?;
if view.get_active() {
    let city: &str = view.get_location().get_city();
    view.set_sequence(view.get_sequence() + 1);
    let updated: Vec<u8> = view.try_marshal()?;
}
```

### Protobuf Integration with `buffa`

`anthropics/buffa` integrates at both compile time and runtime.

1. **Co-derived `#[derive(OmniBuf)]` via `buffa-build`:** Attaching `#[derive(::omnibuf::OmniBuf)]` through `.message_attribute` and `.oneof_attribute` parses `buffa`'s `/// Field N:` doc comments, unwraps `buffa::MessageField<T>`, `buffa::EnumValue<E>`, and `Option<...>` oneof fields, skips internal `__buffa_*` fields, and generates an unrolled single-pass codec. Oneof variants accept `#[omnibuf(id = N)]` via `.field_attribute`, and fixed-width integer fields accept `#[omnibuf(wire = "fixed32")]` or `"fixed64"`.

```rust
// build.rs
buffa_build::Config::new()
    .files(&["omnibuf/bench/peer.proto"])
    .includes(&["proto"])
    .generate_views(true)
    .generate_reflection(true)
    .message_attribute(".", "#[derive(::omnibuf::OmniBuf)]")
    .compile()?;
```

2. **Reflective and dynamic `omnibuf::buffa_codec`:** Pre-compiled `buffa` crates keep their `build.rs` untouched. `encode_buffa_reflect` walks `Reflectable` vtable accessors in place with zero intermediate Protobuf buffers, while `encode_buffa`, `decode_buffa`, `encode_buffa_dynamic`, and `decode_buffa_dynamic` operate against any `Arc<buffa_descriptor::DescriptorPool>`.

```rust
use omnibuf::{EncodeOptions, Message};
use omnibuf::buffa_codec::{decode_buffa, encode_buffa, encode_buffa_reflect};

// Static unrolled codec from co-derived #[derive(OmniBuf)]
let pkt = buffa_peer.encode_omnibuf()?;
let direct = buffa_pb::PeerUpdate::from_omnibuf(&pkt)?;

// Runtime reflection and DescriptorPool transcoding
let pkt = encode_buffa_reflect(&buffa_peer, EncodeOptions::default())?;
let pkt_pool = encode_buffa(&buffa_peer, &pool, EncodeOptions::default())?;
let reflected: buffa_pb::PeerUpdate = decode_buffa(&pkt, &pool)?;
```

### Protobuf Integration with `prost`

`prost` and `prost-reflect` support the same two-tier workflow.

- **Co-derived `#[derive(OmniBuf)]` via `prost-build`:** Pass `.type_attribute("pkg.Msg", "#[derive(::omnibuf::OmniBuf)]")` on `prost_build::Config` to compile `#[prost(...)]` field tags directly into monomorphized `omnibuf::Message` and `omnibuf::codec::Oneof` implementations.
- **Reflective `omnibuf::prost_codec`:** Pass any `prost_reflect::ReflectMessage` or `DynamicMessage` to `encode_prost`, `decode_prost`, `encode_dynamic`, and `decode_dynamic`.

```rust
use omnibuf::{EncodeOptions, Message};
use omnibuf::prost_codec::{decode_prost, encode_prost};

let pkt = encode_prost(&prost_peer, EncodeOptions::default())?;
let mut out = pb::PeerUpdate::default();
decode_prost(&pkt, &mut out)?;
```

## Benchmarks

Rust benchmark results, methodology, and cross-language comparisons live at [omnibuf.com/benchmarks?lang=rs](https://omnibuf.com/benchmarks?lang=rs) (all languages at [omnibuf.com/benchmarks](https://omnibuf.com/benchmarks)). Run `just bench` to execute `crates/omnibuf-bench` locally and update [`testdata/benchmarks.json`](testdata/benchmarks.json).

## Development and Verification

Tool versions are pinned in `mise.toml` (`rust 1.94.0`, `just 1.58.0`, `protobuf 35.1`, `buf 1.75.0`).

```bash
just proto        # Lint schemas and run buf generate with protoc-gen-omnibuf-rs
just build        # Compile all workspace crates and targets
just test         # Run unit and integration tests
just bench        # Run PeerUpdate benchmarks and export testdata/benchmarks.json
just lint         # Run cargo clippy (-D warnings) and buf lint
just conformance  # Run all 758/758 cross-language conformance cases
just ci           # Run fmt-check, lint, build, test, and conformance
```

## License

Released under the [Apache 2.0 License](./LICENSE).
