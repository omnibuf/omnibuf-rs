# omnibuf-rs

[![OmniBuf Spec: v1 DRAFT-1](https://img.shields.io/badge/OmniBuf%20Spec-v1%20DRAFT--1-FF4F18)](https://omnibuf.com/spec)

Rust runtime, `#[derive(OmniBuf)]` proc macro, and Buf/Protobuf plugin for [OmniBuf Wire Specification v1 DRAFT-1](https://omnibuf.com/spec). Full docs live at [omnibuf.com/rs](https://omnibuf.com/rs).

## Install

```toml
# Default features: derive, buffa, prost
omnibuf = "0.1"

# Core wire codec, opaque splicing, and blind decode only (zero Protobuf deps)
omnibuf = { version = "0.1", default-features = false }
```

## Quick usage

```rust
use omnibuf::{DecodeOptions, EncodeOptions, Message, OmniBuf, decode_blind_json, from_slice_with_options};

#[derive(Debug, Default, PartialEq, OmniBuf)]
#[omnibuf(name = "PeerUpdate")]
pub struct PeerUpdate {
    #[omnibuf(id = 1, name = "asn")]
    pub asn: u32,
    #[omnibuf(id = 2, name = "router_id")]
    pub router_id: String,
    #[omnibuf(id = 5, name = "rssi_dbm", wire = "sint")]
    pub rssi_dbm: i32,
}

fn main() -> omnibuf::Result<()> {
    let update = PeerUpdate { asn: 64512, router_id: "edge-fra-01".into(), rssi_dbm: -68 };
    let packet = update.encode_omnibuf_with_options(EncodeOptions::self_describing())?;
    let json = decode_blind_json(&packet)?;
    let decoded: PeerUpdate = from_slice_with_options(&packet, DecodeOptions::default_limits())?;
    assert!(json.contains("edge-fra-01") && decoded == update);
    Ok(())
}
```

## Implementation

- **Derive macro (`omnibuf-derive`):** `#[derive(OmniBuf)]` generates codecs for native Rust structs, `oneof` enums, `buffa` messages, and `prost` messages.
- **Zero-copy decode (`DecodeBorrowed<'de>`):** `from_slice_borrowed` and `decode_into_borrowed` borrow `&'de str` and `&'de [u8]` directly from packet memory.
- **Protobuf codecs (`buffa`, `prost`):** Feature-gated `omnibuf::buffa_codec` and `omnibuf::prost_codec` support static co-derives, runtime reflection, and `DynamicMessage` transcoding.
- **Codegen plugin (`protoc-gen-omnibuf-rs`):** Emits typed Rust structs, `oneof` enums, and `Opaque<T>` packet views with `try_new` and `try_marshal` field splicing.
- **Untrusted input limits:** `from_slice` leaves allocation budgets unbounded. Pass `DecodeOptions::default_limits()` to `from_slice_with_options` for untrusted network bytes.
- **Conformance:** `conformance-rs` passes all 758/758 cross-language conformance cases (`just conformance`).

## License

Apache-2.0
