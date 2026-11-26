//! Editions metadata adapter for `prost-types`, whose descriptors predate Protobuf Editions.
//! Extracts `edition` and `FeatureSet` metadata from raw `CodeGeneratorRequest` bytes before
//! `prost-types` discards unknown fields, validates OmniBuf Editions rules, and normalizes
//! supported Editions descriptors into proto3 + `proto3_optional` for code generation.

use std::collections::{HashMap, HashSet};

use prost::Message;
use prost_types::compiler::{CodeGeneratorRequest, CodeGeneratorResponse};
use prost_types::{DescriptorProto, EnumDescriptorProto, FieldDescriptorProto};

const EDITION_2023: i32 = 1000;
const EDITION_2024: i32 = 1001;
const EDITION_2026: i32 = 1002;

const FEATURE_PROTO3_OPTIONAL: u64 = 1;
const FEATURE_SUPPORTS_EDITIONS: u64 = 2;

const FIELD_PRESENCE_EXPLICIT: i32 = 1;
const FIELD_PRESENCE_IMPLICIT: i32 = 2;

const ENUM_TYPE_OPEN: i32 = 1;

const REPEATED_PACKED: i32 = 1;
const REPEATED_EXPANDED: i32 = 2;

const UTF8_VERIFY: i32 = 2;

const MESSAGE_LENGTH_PREFIXED: i32 = 1;
const MESSAGE_DELIMITED: i32 = 2;

const JSON_ALLOW: i32 = 1;
const JSON_LEGACY_BEST_EFFORT: i32 = 2;

const LABEL_REQUIRED: i32 = 2;
const LABEL_REPEATED: i32 = 3;

const TYPE_FLOAT: i32 = 2;
const TYPE_DOUBLE: i32 = 1;
const TYPE_INT64: i32 = 3;
const TYPE_UINT64: i32 = 4;
const TYPE_INT32: i32 = 5;
const TYPE_FIXED64: i32 = 6;
const TYPE_FIXED32: i32 = 7;
const TYPE_BOOL: i32 = 8;
const TYPE_STRING: i32 = 9;
const TYPE_GROUP: i32 = 10;
const TYPE_MESSAGE: i32 = 11;
const TYPE_BYTES: i32 = 12;
const TYPE_UINT32: i32 = 13;
const TYPE_ENUM: i32 = 14;
const TYPE_SFIXED32: i32 = 15;
const TYPE_SFIXED64: i32 = 16;
const TYPE_SINT32: i32 = 17;
const TYPE_SINT64: i32 = 18;

#[derive(Clone, PartialEq, Message)]
struct RequestMetadata {
    #[prost(message, repeated, tag = "15")]
    files: Vec<FileMetadata>,
}

#[derive(Clone, PartialEq, Message)]
struct FileMetadata {
    #[prost(int32, optional, tag = "14")]
    edition: Option<i32>,
    #[prost(message, optional, tag = "8")]
    options: Option<FileOptionsMeta>,
    #[prost(message, repeated, tag = "4")]
    messages: Vec<MessageMetadata>,
    #[prost(message, repeated, tag = "5")]
    enums: Vec<EnumMetadata>,
}

#[derive(Clone, PartialEq, Message)]
struct Features {
    #[prost(int32, optional, tag = "1")]
    presence: Option<i32>,
    #[prost(int32, optional, tag = "2")]
    enum_type: Option<i32>,
    #[prost(int32, optional, tag = "3")]
    repeated_field_encoding: Option<i32>,
    #[prost(int32, optional, tag = "4")]
    utf8: Option<i32>,
    #[prost(int32, optional, tag = "5")]
    message_encoding: Option<i32>,
    #[prost(int32, optional, tag = "6")]
    json_format: Option<i32>,
    // Source-only Edition 2024 / 2026 features accepted and ignored at runtime.
    #[prost(int32, optional, tag = "7")]
    enforce_naming_style: Option<i32>,
    #[prost(int32, optional, tag = "8")]
    default_symbol_visibility: Option<i32>,
    #[prost(int32, optional, tag = "9")]
    enforce_proto_limits: Option<i32>,
}

fn override_nonzero(own: Option<i32>, parent: Option<i32>) -> Option<i32> {
    own.filter(|&v| v != 0).or(parent)
}

impl Features {
    fn edition_defaults() -> Self {
        Self {
            presence: Some(FIELD_PRESENCE_EXPLICIT),
            enum_type: Some(ENUM_TYPE_OPEN),
            repeated_field_encoding: Some(REPEATED_PACKED),
            utf8: Some(UTF8_VERIFY),
            message_encoding: Some(MESSAGE_LENGTH_PREFIXED),
            json_format: Some(JSON_ALLOW),
            enforce_naming_style: None,
            default_symbol_visibility: None,
            enforce_proto_limits: None,
        }
    }

    fn inherit(&self, own: Option<&Self>) -> Self {
        let Some(own) = own else {
            return self.clone();
        };
        Self {
            presence: override_nonzero(own.presence, self.presence),
            enum_type: override_nonzero(own.enum_type, self.enum_type),
            repeated_field_encoding: override_nonzero(
                own.repeated_field_encoding,
                self.repeated_field_encoding,
            ),
            utf8: override_nonzero(own.utf8, self.utf8),
            message_encoding: override_nonzero(own.message_encoding, self.message_encoding),
            json_format: override_nonzero(own.json_format, self.json_format),
            enforce_naming_style: override_nonzero(
                own.enforce_naming_style,
                self.enforce_naming_style,
            ),
            default_symbol_visibility: override_nonzero(
                own.default_symbol_visibility,
                self.default_symbol_visibility,
            ),
            enforce_proto_limits: override_nonzero(
                own.enforce_proto_limits,
                self.enforce_proto_limits,
            ),
        }
    }
}

macro_rules! options_meta {
    ($name:ident, $tag:literal) => {
        #[derive(Clone, PartialEq, Message)]
        struct $name {
            #[prost(message, optional, tag = $tag)]
            features: Option<Features>,
        }
    };
}

options_meta!(FileOptionsMeta, "50");
options_meta!(MessageOptionsMeta, "12");
options_meta!(FieldOptionsMeta, "21");
options_meta!(EnumOptionsMeta, "7");
options_meta!(OneofOptionsMeta, "1");

#[derive(Clone, PartialEq, Message)]
struct MessageMetadata {
    #[prost(message, optional, tag = "7")]
    options: Option<MessageOptionsMeta>,
    #[prost(message, repeated, tag = "2")]
    fields: Vec<FieldMetadata>,
    #[prost(message, repeated, tag = "3")]
    nested: Vec<MessageMetadata>,
    #[prost(message, repeated, tag = "4")]
    enums: Vec<EnumMetadata>,
    #[prost(message, repeated, tag = "8")]
    oneofs: Vec<OneofMetadata>,
}

#[derive(Clone, PartialEq, Message)]
struct FieldMetadata {
    #[prost(message, optional, tag = "8")]
    options: Option<FieldOptionsMeta>,
}

#[derive(Clone, PartialEq, Message)]
struct EnumMetadata {
    #[prost(message, optional, tag = "3")]
    options: Option<EnumOptionsMeta>,
}

#[derive(Clone, PartialEq, Message)]
struct OneofMetadata {
    #[prost(message, optional, tag = "2")]
    options: Option<OneofOptionsMeta>,
}

#[derive(Default)]
struct EnumIndex {
    closed_enums: HashSet<String>,
    enum_zero_names: HashMap<String, HashSet<String>>,
}

impl EnumIndex {
    fn record_enum(&mut self, fq_name: &str, desc: &EnumDescriptorProto, is_closed: bool) {
        let stripped = fq_name.strip_prefix('.').unwrap_or(fq_name);
        if is_closed {
            self.closed_enums.insert(fq_name.to_owned());
            self.closed_enums.insert(stripped.to_owned());
        }
        let zeros: HashSet<String> = desc
            .value
            .iter()
            .filter(|v| v.number == Some(0))
            .filter_map(|v| v.name.clone())
            .collect();
        self.enum_zero_names
            .insert(fq_name.to_owned(), zeros.clone());
        self.enum_zero_names.insert(stripped.to_owned(), zeros);
    }

    fn is_closed(&self, type_name: &str) -> bool {
        self.closed_enums.contains(type_name)
            || self
                .closed_enums
                .contains(type_name.strip_prefix('.').unwrap_or(type_name))
    }

    fn is_zero_enum_value(&self, type_name: &str, def: &str) -> bool {
        self.enum_zero_names
            .get(type_name)
            .or_else(|| {
                self.enum_zero_names
                    .get(type_name.strip_prefix('.').unwrap_or(type_name))
            })
            .is_some_and(|zeros| zeros.contains(def))
    }
}

fn is_map_entry(desc: &DescriptorProto) -> bool {
    desc.options
        .as_ref()
        .and_then(|o| o.map_entry)
        .unwrap_or(false)
}

fn is_zero_default_value(field: &FieldDescriptorProto, def: &str, enums: &EnumIndex) -> bool {
    match field.r#type {
        Some(TYPE_BOOL) => def == "false",
        Some(TYPE_STRING | TYPE_BYTES) => def.is_empty(),
        Some(
            TYPE_INT32 | TYPE_INT64 | TYPE_SINT32 | TYPE_SINT64 | TYPE_SFIXED32 | TYPE_SFIXED64
            | TYPE_UINT32 | TYPE_UINT64 | TYPE_FIXED32 | TYPE_FIXED64,
        ) => def == "0",
        Some(TYPE_FLOAT | TYPE_DOUBLE) => def.parse::<f64>().is_ok_and(|v| v.to_bits() == 0),
        Some(TYPE_ENUM) => field
            .type_name
            .as_deref()
            .is_some_and(|tn| enums.is_zero_enum_value(tn, def)),
        _ => false,
    }
}

fn collect_non_editions_enums(
    fq_parent: &str,
    messages: &[DescriptorProto],
    is_closed: bool,
    enums: &mut EnumIndex,
) {
    for msg in messages {
        let mname = msg.name.as_deref().unwrap_or("");
        let fq = format!("{fq_parent}.{mname}");
        for e in &msg.enum_type {
            let ename = e.name.as_deref().unwrap_or("");
            enums.record_enum(&format!("{fq}.{ename}"), e, is_closed);
        }
        collect_non_editions_enums(&fq, &msg.nested_type, is_closed, enums);
    }
}

fn collect_and_check_editions_enums(
    file_name: &str,
    fq_parent: &str,
    enum_descs: &[EnumDescriptorProto],
    enum_metas: &[EnumMetadata],
    parent: &Features,
    enums: &mut EnumIndex,
) -> Result<(), String> {
    for (desc, meta) in enum_descs.iter().zip(enum_metas) {
        let ename = desc.name.as_deref().unwrap_or("");
        let fq = format!("{fq_parent}.{ename}");
        let resolved = parent.inherit(meta.options.as_ref().and_then(|o| o.features.as_ref()));
        if resolved.enum_type != Some(ENUM_TYPE_OPEN) {
            return Err(format!(
                "omnibuf: editions CLOSED enums are not supported ({file_name}: {fq})"
            ));
        }
        enums.record_enum(&fq, desc, false);
    }
    Ok(())
}

fn collect_editions_message_enums(
    file_name: &str,
    fq_parent: &str,
    messages: &[DescriptorProto],
    metas: &[MessageMetadata],
    parent: &Features,
    enums: &mut EnumIndex,
) -> Result<(), String> {
    for (msg, meta) in messages.iter().zip(metas) {
        let mname = msg.name.as_deref().unwrap_or("");
        let fq = format!("{fq_parent}.{mname}");
        let features = parent.inherit(meta.options.as_ref().and_then(|o| o.features.as_ref()));
        collect_and_check_editions_enums(
            file_name,
            &fq,
            &msg.enum_type,
            &meta.enums,
            &features,
            enums,
        )?;
        collect_editions_message_enums(
            file_name,
            &fq,
            &msg.nested_type,
            &meta.nested,
            &features,
            enums,
        )?;
    }
    Ok(())
}

fn resolve_message(
    file_name: &str,
    msg_fq: &str,
    message: &mut DescriptorProto,
    meta: &MessageMetadata,
    parent: &Features,
    enums: &EnumIndex,
) -> Result<(), String> {
    for ext in &message.extension {
        let extendee = ext.extendee.as_deref().unwrap_or("");
        if !crate::is_option_extendee(extendee) {
            let ext_name = ext.name.as_deref().unwrap_or("extension");
            return Err(format!(
                "omnibuf: non-option extensions are not supported ({file_name}: {msg_fq}.{ext_name})"
            ));
        }
    }
    if !message.extension_range.is_empty() && !crate::is_option_extendee(msg_fq) {
        return Err(format!(
            "omnibuf: non-option extensions are not supported ({file_name}: {msg_fq})"
        ));
    }

    let features = parent.inherit(meta.options.as_ref().and_then(|o| o.features.as_ref()));
    let entry_msg = is_map_entry(message);
    let mut map_field_features: HashMap<String, Features> = HashMap::new();

    for (field, fm) in message.field.iter_mut().zip(&meta.fields) {
        let fname = field.name.as_deref().unwrap_or("field");
        let oneof = field
            .oneof_index
            .and_then(|i| usize::try_from(i).ok())
            .and_then(|i| meta.oneofs.get(i))
            .and_then(|o| o.options.as_ref())
            .and_then(|o| o.features.as_ref());
        let resolved = features
            .inherit(oneof)
            .inherit(fm.options.as_ref().and_then(|o| o.features.as_ref()));

        if field.label == Some(LABEL_REQUIRED)
            || !matches!(
                resolved.presence,
                Some(FIELD_PRESENCE_EXPLICIT | FIELD_PRESENCE_IMPLICIT)
            )
        {
            return Err(format!(
                "omnibuf: editions LEGACY_REQUIRED is not supported ({file_name}: {msg_fq}.{fname})"
            ));
        }

        if field.r#type == Some(TYPE_STRING) && resolved.utf8 != Some(UTF8_VERIFY) {
            return Err(format!(
                "omnibuf: editions utf8_validation = NONE is not supported ({file_name}: {msg_fq}.{fname})"
            ));
        }

        if !matches!(
            resolved.repeated_field_encoding,
            Some(REPEATED_PACKED | REPEATED_EXPANDED)
        ) {
            return Err(format!(
                "omnibuf: unsupported repeated_field_encoding {:?} ({file_name}: {msg_fq}.{fname})",
                resolved.repeated_field_encoding
            ));
        }

        if !matches!(
            resolved.message_encoding,
            Some(MESSAGE_LENGTH_PREFIXED | MESSAGE_DELIMITED)
        ) {
            return Err(format!(
                "omnibuf: unsupported message_encoding {:?} ({file_name}: {msg_fq}.{fname})",
                resolved.message_encoding
            ));
        }

        if !matches!(
            resolved.json_format,
            Some(JSON_ALLOW | JSON_LEGACY_BEST_EFFORT)
        ) {
            return Err(format!(
                "omnibuf: unsupported json_format {:?} ({file_name}: {msg_fq}.{fname})",
                resolved.json_format
            ));
        }

        if field.r#type == Some(TYPE_ENUM) {
            let tname = field.type_name.as_deref().unwrap_or("");
            if enums.is_closed(tname) {
                return Err(format!(
                    "omnibuf: editions CLOSED enums are not supported ({file_name}: {msg_fq}.{fname} references {tname})"
                ));
            }
        }

        if let Some(def) = field.default_value.as_deref()
            && !is_zero_default_value(field, def, enums)
        {
            return Err(format!(
                "omnibuf: custom non-zero default values are not supported ({file_name}: {msg_fq}.{fname} = {def:?})"
            ));
        }

        if field.r#type == Some(TYPE_GROUP) {
            field.r#type = Some(TYPE_MESSAGE);
        }

        if field.label == Some(LABEL_REPEATED)
            && field.r#type == Some(TYPE_MESSAGE)
            && let Some(tname) = field.type_name.as_deref()
        {
            map_field_features.insert(tname.to_owned(), resolved.clone());
            map_field_features.insert(
                tname.strip_prefix('.').unwrap_or(tname).to_owned(),
                resolved.clone(),
            );
        }

        if field.oneof_index.is_none() && field.label != Some(LABEL_REPEATED) && !entry_msg {
            field.proto3_optional = Some(resolved.presence == Some(FIELD_PRESENCE_EXPLICIT));
        }
    }

    for (nested, nm) in message.nested_type.iter_mut().zip(&meta.nested) {
        let nested_name = nested.name.as_deref().unwrap_or("");
        let nested_fq = format!("{msg_fq}.{nested_name}");
        let nested_parent = if is_map_entry(nested) {
            map_field_features.get(&nested_fq).unwrap_or(&features)
        } else {
            &features
        };
        resolve_message(file_name, &nested_fq, nested, nm, nested_parent, enums)?;
    }

    Ok(())
}

/// Generate a binary `CodeGeneratorResponse`, preserving Editions metadata absent from `prost-types`.
pub fn generate_request_bytes(input: &[u8]) -> Result<Vec<u8>, prost::DecodeError> {
    let mut request = CodeGeneratorRequest::decode(input)?;
    let metadata = RequestMetadata::decode(input)?;

    let resolved = (|| -> Result<(), String> {
        let mut enums = EnumIndex::default();

        // Pass 1: validate edition versions and index enum openness / zero defaults across all files.
        for (file, meta) in request.proto_file.iter().zip(&metadata.files) {
            let file_name = file.name.as_deref().unwrap_or("generated.proto");
            let pkg_prefix = match file.package.as_deref() {
                Some(pkg) if !pkg.is_empty() => format!(".{pkg}"),
                _ => String::new(),
            };
            match file.syntax.as_deref() {
                Some("editions") => {
                    if !matches!(
                        meta.edition,
                        Some(EDITION_2023 | EDITION_2024 | EDITION_2026)
                    ) {
                        return Err(format!(
                            "omnibuf: unsupported protobuf edition {:?} ({file_name})",
                            meta.edition
                        ));
                    }
                    let base = Features::edition_defaults()
                        .inherit(meta.options.as_ref().and_then(|o| o.features.as_ref()));
                    collect_and_check_editions_enums(
                        file_name,
                        &pkg_prefix,
                        &file.enum_type,
                        &meta.enums,
                        &base,
                        &mut enums,
                    )?;
                    collect_editions_message_enums(
                        file_name,
                        &pkg_prefix,
                        &file.message_type,
                        &meta.messages,
                        &base,
                        &mut enums,
                    )?;
                }
                Some("proto3") => {
                    for e in &file.enum_type {
                        let ename = e.name.as_deref().unwrap_or("");
                        enums.record_enum(&format!("{pkg_prefix}.{ename}"), e, false);
                    }
                    collect_non_editions_enums(&pkg_prefix, &file.message_type, false, &mut enums);
                }
                _ => {
                    for e in &file.enum_type {
                        let ename = e.name.as_deref().unwrap_or("");
                        enums.record_enum(&format!("{pkg_prefix}.{ename}"), e, true);
                    }
                    collect_non_editions_enums(&pkg_prefix, &file.message_type, true, &mut enums);
                }
            }
        }

        // Pass 2: validate and normalize all Editions files.
        for (file, meta) in request.proto_file.iter_mut().zip(&metadata.files) {
            if file.syntax.as_deref() != Some("editions") {
                continue;
            }
            let file_name = file.name.as_deref().unwrap_or("generated.proto").to_owned();
            for ext in &file.extension {
                let extendee = ext.extendee.as_deref().unwrap_or("");
                if !crate::is_option_extendee(extendee) {
                    let ext_name = ext.name.as_deref().unwrap_or("extension");
                    return Err(format!(
                        "omnibuf: non-option extensions are not supported ({file_name}: {ext_name})"
                    ));
                }
            }
            let pkg_prefix = match file.package.as_deref() {
                Some(pkg) if !pkg.is_empty() => format!(".{pkg}"),
                _ => String::new(),
            };
            let base = Features::edition_defaults()
                .inherit(meta.options.as_ref().and_then(|o| o.features.as_ref()));
            for (message, mm) in file.message_type.iter_mut().zip(&meta.messages) {
                let mname = message.name.as_deref().unwrap_or("");
                let msg_fq = format!("{pkg_prefix}.{mname}");
                resolve_message(&file_name, &msg_fq, message, mm, &base, &enums)?;
            }
            file.syntax = Some("proto3".into());
        }
        Ok(())
    })();

    let mut response = match resolved {
        Ok(()) => crate::generate(&request),
        Err(error) => CodeGeneratorResponse {
            error: Some(error),
            ..Default::default()
        },
    };
    response.supported_features = Some(FEATURE_PROTO3_OPTIONAL | FEATURE_SUPPORTS_EDITIONS);
    let mut output = response.encode_to_vec();
    // CodeGeneratorResponse minimum_edition (#3 = 1000) and maximum_edition (#4 = 1002).
    output.extend_from_slice(&[0x18, 0xe8, 0x07, 0x20, 0xea, 0x07]);
    Ok(output)
}
