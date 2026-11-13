//! Core Rust runtime for the OmniBuf binary serialization format.
//!
//! Provides:
//! - [`wire`]: Prefix-Varint (`trailing_zeros()`), single-pass [`wire::Encoder`], zero-copy [`wire::Decoder`], and O(1) header-hopping readers.
//! - [`opaque`]: Zero-unpack [`opaque::splice_fields`] packet rewriter for partial updates.
//! - [`field0`]: Inline [`field0::SchemaMeta`] (`Field #0`) encoder, decoder, and overlay merger.
//! - [`blind`]: Schema-less [`blind::decode_blind`] and [`blind::decode_blind_json`] packet inspection.
//! - [`message`]: [`Message`] trait, [`EncodeOptions`], and top-level `to_vec` / `from_slice` helpers.
//! - [`prost_codec`]: Bridge for `prost` and `prost-reflect` Protobuf message types (enabled with the `prost` feature).

pub mod blind;
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
    EncodeOptions, Message, codec, decode_into, from_slice, to_vec, to_vec_deterministic,
    to_vec_with_options,
};
pub use opaque::{copy_packet, splice_fields, splice_fields_vec};
pub use wire::{Decoder, Encoder, MAX_FIELD_NUMBER, MAX_NESTING_DEPTH};

#[cfg(feature = "derive")]
pub use omnibuf_derive::OmniBuf;
