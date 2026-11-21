//! Core Rust runtime for the OmniBuf binary serialization format.
//!
//! Verified against all `758/758` cross-language conformance cases across generated codecs,
//! Protobuf bridges (`buffa` and `prost`), procedural `#[derive(OmniBuf)]` structs, and
//! schema-less blind inspection.
//!
//! # Modules
//!
//! - [`wire`]: Prefix-Varint (`trailing_zeros()`), single-pass [`wire::Encoder`], zero-copy [`wire::Decoder`], and O(1) header-hopping readers.
//! - [`opaque`]: Zero-unpack [`opaque::splice_fields`] packet rewriter for partial updates.
//! - [`field0`]: Inline [`field0::SchemaMeta`] (`Field #0`) encoder, decoder, and overlay merger.
//! - [`blind`]: Schema-less [`blind::decode_blind`] and [`blind::decode_blind_json`] packet inspection.
//! - [`message`]: [`Message`] trait, [`EncodeOptions`], [`DecodeOptions`], and top-level `to_vec` / `from_slice` helpers.
//! - [`buffa_codec`]: Bridge for `buffa` and `buffa-descriptor` Protobuf message types (`features = ["buffa"]`, enabled by default).
//! - [`prost_codec`]: Bridge for `prost` and `prost-reflect` Protobuf message types (`features = ["prost"]`, enabled by default).
//!
//! # Cargo Features
//!
//! - `default = ["derive", "prost", "buffa"]`: Enables `#[derive(OmniBuf)]` plus both Protobuf bridges.
//! - `derive`: Re-exports `#[derive(OmniBuf)]` for native Rust structs, `oneof` enums, `buffa` structs, and `prost` structs.
//! - `buffa`: Enables [`buffa_codec`] (`encode_buffa_reflect`, `encode_buffa`, `decode_buffa`, and `DynamicMessage` helpers).
//! - `prost`: Enables [`prost_codec`] (`encode_prost`, `decode_prost`, and `prost_reflect::DynamicMessage` helpers).
//! - `default-features = false`: Compiles only the pure wire, `Field #0`, `opaque`, and `blind` modules with zero Protobuf dependencies.
//!
//! # Example
//!
//! ```rust
//! # #[cfg(feature = "derive")]
//! # {
//! use omnibuf::{EncodeOptions, Message, OmniBuf, decode_blind_json, from_slice};
//!
//! #[derive(Debug, Default, PartialEq, OmniBuf)]
//! #[omnibuf(name = "PeerUpdate")]
//! struct PeerUpdate {
//!     #[omnibuf(id = 1, name = "asn")]
//!     asn: u32,
//!     #[omnibuf(id = 2, name = "router_id")]
//!     router_id: String,
//!     #[omnibuf(id = 5, name = "rssi_dbm", wire = "sint")]
//!     rssi_dbm: i32,
//! }
//!
//! let peer = PeerUpdate {
//!     asn: 64512,
//!     router_id: "edge-fra-01".into(),
//!     rssi_dbm: -62,
//! };
//!
//! let pkt = peer.encode_omnibuf_with_options(EncodeOptions::self_describing())?;
//! let json = decode_blind_json(&pkt)?;
//! assert!(json.contains("\"router_id\":\"edge-fra-01\""));
//!
//! let decoded: PeerUpdate = from_slice(&pkt)?;
//! assert_eq!(decoded, peer);
//! # }
//! # Ok::<(), omnibuf::Error>(())
//! ```

pub mod blind;
#[cfg(feature = "buffa")]
pub mod buffa_codec;
pub mod error;
pub mod field0;
pub mod message;
pub mod opaque;
#[cfg(feature = "prost")]
pub mod prost_codec;
pub mod wire;

pub use blind::{
    BlindValue, DecodeBlindOptions, decode_blind, decode_blind_json, decode_blind_with_options,
    encode_base64, stringify_blind_json,
};
pub use error::{Error, Result};
pub use field0::{
    SchemaMeta, decode_schema_meta, merge_schema_meta, read_field0_schema_meta, validate_field0,
};
pub use message::{
    DecodeBorrowed, DecodeOptions, EncodeOptions, Message, codec, decode_into,
    decode_into_borrowed, decode_into_borrowed_with_options, decode_into_with_options, from_slice,
    from_slice_borrowed, from_slice_borrowed_with_options, from_slice_with_options, to_vec,
    to_vec_deterministic, to_vec_with_options,
};
pub use opaque::{
    append_packet, copy_packet, splice_fields, splice_fields_vec, try_append_packet,
    try_copy_packet, try_splice_fields, try_splice_fields_vec,
};
pub use wire::{Decoder, Encoder, MAX_FIELD_NUMBER, MAX_NESTING_DEPTH};

#[cfg(feature = "derive")]
pub use omnibuf_derive::OmniBuf;
