use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use prost_types::compiler::code_generator_response::{Feature, File};
use prost_types::compiler::{CodeGeneratorRequest, CodeGeneratorResponse};
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{
    DescriptorProto, EnumDescriptorProto, FieldDescriptorProto, FileDescriptorProto,
};

const WIRE_UINT: u8 = 0;
const WIRE_SINT: u8 = 1;
const WIRE_BOOL_FALSE: u8 = 2;
const WIRE_FIXED32: u8 = 4;
const WIRE_FIXED64: u8 = 5;
const WIRE_SFIXED32: u8 = 6;
const WIRE_SFIXED64: u8 = 7;
const WIRE_FLOAT32: u8 = 8;
const WIRE_FLOAT64: u8 = 9;
const WIRE_STRING: u8 = 10;
const WIRE_BYTES: u8 = 11;
const WIRE_SUB_MSG: u8 = 12;
const WIRE_ARRAY: u8 = 13;
const WIRE_MAP: u8 = 14;

#[derive(Clone)]
struct MapEntryInfo {
    key_field: FieldDescriptorProto,
    val_field: FieldDescriptorProto,
}

#[derive(Clone)]
struct RegisteredMsg {
    file_name: String,
    rust_name: String,
    desc: DescriptorProto,
    direct_opaque: bool,
}

#[derive(Default)]
struct GlobalRegistry {
    map_entries: HashMap<String, MapEntryInfo>,
    messages: HashMap<String, RegisteredMsg>,
    enums: HashMap<String, (String, String)>,
}

/// Executes code generation for a `protoc` [`CodeGeneratorRequest`].
pub fn generate(req: &CodeGeneratorRequest) -> CodeGeneratorResponse {
    let supported = Some(Feature::Proto3Optional as u64);
    let registry = match build_registry(&req.proto_file) {
        Ok(reg) => reg,
        Err(err) => {
            return CodeGeneratorResponse {
                error: Some(err),
                supported_features: supported,
                file: Vec::new(),
            };
        }
    };

    let targets: HashSet<&str> = req.file_to_generate.iter().map(String::as_str).collect();
    let mut files = Vec::new();

    for proto_file in &req.proto_file {
        let name = proto_file.name.as_deref().unwrap_or("");
        if !targets.contains(name) {
            continue;
        }
        match generate_file(proto_file, &registry) {
            Ok(file) => files.push(file),
            Err(err) => {
                return CodeGeneratorResponse {
                    error: Some(err),
                    supported_features: supported,
                    file: Vec::new(),
                };
            }
        }
    }

    CodeGeneratorResponse {
        error: None,
        supported_features: supported,
        file: files,
    }
}

fn build_registry(proto_files: &[FileDescriptorProto]) -> Result<GlobalRegistry, String> {
    let mut reg = GlobalRegistry::default();
    for file in proto_files {
        let file_name = file.name.as_deref().unwrap_or("generated.proto");
        if !file.extension.is_empty() {
            let ext_name = file.extension[0].name.as_deref().unwrap_or("extension");
            return Err(format!(
                "proto2 extensions are not supported by OmniBuf ({file_name}: {ext_name})"
            ));
        }
        let pkg_prefix = match file.package.as_deref() {
            Some(pkg) if !pkg.is_empty() => format!(".{pkg}"),
            _ => String::new(),
        };
        let mut used_type_names: HashSet<String> = HashSet::new();
        for e in &file.enum_type {
            let ename = e.name.as_deref().unwrap_or("UnknownEnum");
            let rust_name = allocate_unique_type_name(&to_pascal_case(ename), &mut used_type_names);
            reg.enums.insert(
                format!("{pkg_prefix}.{ename}"),
                (file_name.to_owned(), rust_name),
            );
        }
        // Reserve top-level message names first so nested messages never steal a top-level name.
        let mut top_names: Vec<String> = Vec::with_capacity(file.message_type.len());
        for m in &file.message_type {
            if is_map_entry(m) {
                top_names.push(String::new());
                continue;
            }
            let mname = m.name.as_deref().unwrap_or("UnknownMsg");
            let rust_name = allocate_unique_type_name(&to_pascal_case(mname), &mut used_type_names);
            top_names.push(rust_name);
        }
        collect_file_messages(
            file_name,
            &pkg_prefix,
            "",
            &file.message_type,
            Some(&top_names),
            &mut used_type_names,
            &mut reg,
        )?;
    }
    Ok(reg)
}

fn allocate_unique_type_name(base: &str, used: &mut HashSet<String>) -> String {
    let sanitized = sanitize_pascal_ident(base);
    if used.insert(sanitized.clone()) {
        return sanitized;
    }
    let mut idx = 2usize;
    loop {
        let cand = format!("{sanitized}{idx}");
        if used.insert(cand.clone()) {
            return cand;
        }
        idx += 1;
    }
}

fn has_real_oneof(desc: &DescriptorProto) -> bool {
    desc.field
        .iter()
        .any(|f| f.oneof_index.is_some() && !f.proto3_optional.unwrap_or(false))
}

fn is_directly_opaque_msg(desc: &DescriptorProto) -> bool {
    if has_real_oneof(desc) {
        return false;
    }
    desc.field.iter().all(|f| {
        let n = f.number.unwrap_or(0);
        n > 0 && n < 64
    })
}

fn collect_file_messages(
    file_name: &str,
    fq_parent: &str,
    rust_prefix: &str,
    messages: &[DescriptorProto],
    preassigned_top: Option<&[String]>,
    used_type_names: &mut HashSet<String>,
    reg: &mut GlobalRegistry,
) -> Result<(), String> {
    for (idx, m) in messages.iter().enumerate() {
        let mname = m.name.as_deref().unwrap_or("UnknownMsg");
        let fq = format!("{fq_parent}.{mname}");

        if !m.extension.is_empty() || !m.extension_range.is_empty() {
            return Err(format!(
                "proto2 extensions are not supported by OmniBuf ({file_name}: {mname})"
            ));
        }
        for f in &m.field {
            if f.r#type() == Type::Group {
                let fname = f.name.as_deref().unwrap_or("group");
                return Err(format!(
                    "proto2 groups are not supported by OmniBuf ({file_name}: {mname}.{fname})"
                ));
            }
        }

        if is_map_entry(m) {
            if let (Some(kf), Some(vf)) = (
                m.field.iter().find(|f| f.number == Some(1)).cloned(),
                m.field.iter().find(|f| f.number == Some(2)).cloned(),
            ) {
                reg.map_entries.insert(
                    fq,
                    MapEntryInfo {
                        key_field: kf,
                        val_field: vf,
                    },
                );
            }
            continue;
        }

        let rust_name = if let Some(top) = preassigned_top {
            top[idx].clone()
        } else {
            let candidate = if rust_prefix.is_empty() {
                to_pascal_case(mname)
            } else {
                format!("{rust_prefix}{}", to_pascal_case(mname))
            };
            allocate_unique_type_name(&candidate, used_type_names)
        };

        reg.messages.insert(
            fq.clone(),
            RegisteredMsg {
                file_name: file_name.to_owned(),
                rust_name: rust_name.clone(),
                desc: m.clone(),
                direct_opaque: is_directly_opaque_msg(m),
            },
        );

        for e in &m.enum_type {
            let ename = e.name.as_deref().unwrap_or("UnknownEnum");
            let cand = format!("{rust_name}{}", to_pascal_case(ename));
            let enum_rust_name = allocate_unique_type_name(&cand, used_type_names);
            reg.enums.insert(
                format!("{fq}.{ename}"),
                (file_name.to_owned(), enum_rust_name),
            );
        }

        collect_file_messages(
            file_name,
            &fq,
            &rust_name,
            &m.nested_type,
            None,
            used_type_names,
            reg,
        )?;
    }
    Ok(())
}

fn out_filename_for_proto(proto_name: &str) -> String {
    let trimmed = proto_name.trim_start_matches('/');
    let without_ext = trimmed.strip_suffix(".proto").unwrap_or(trimmed);
    if let Some((dir, leaf)) = without_ext.rsplit_once('/') {
        let clean_leaf = sanitize_file_stem(leaf);
        format!("{dir}/{clean_leaf}_omnibuf.rs")
    } else {
        let clean_leaf = sanitize_file_stem(without_ext);
        format!("{clean_leaf}_omnibuf.rs")
    }
}

fn sanitize_file_stem(stem: &str) -> String {
    let mut out = String::with_capacity(stem.len());
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "generated".to_owned()
    } else {
        out
    }
}

fn sanitize_module_ident(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for ch in seg.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    escape_rust_ident(&out)
}

fn relative_module_prefix(cur_file: &str, target_file: &str) -> Option<String> {
    if cur_file == target_file {
        return None;
    }
    let cur_clean = cur_file.trim_start_matches('/');
    let target_clean = target_file.trim_start_matches('/');

    let cur_parts: Vec<&str> = cur_clean.split('/').collect();
    let target_parts: Vec<&str> = target_clean.split('/').collect();

    let cur_dirs = &cur_parts[..cur_parts.len().saturating_sub(1)];
    let target_dirs = &target_parts[..target_parts.len().saturating_sub(1)];
    let target_leaf = target_parts.last().copied().unwrap_or("generated.proto");
    let target_stem = target_leaf.strip_suffix(".proto").unwrap_or(target_leaf);
    let target_mod = sanitize_module_ident(&format!("{target_stem}_omnibuf"));

    let common = cur_dirs
        .iter()
        .zip(target_dirs.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let ups = (cur_dirs.len() - common) + 1;
    let mut segs = Vec::with_capacity(ups + (target_dirs.len() - common) + 1);
    for _ in 0..ups {
        segs.push("super".to_owned());
    }
    for dir in &target_dirs[common..] {
        segs.push(sanitize_module_ident(dir));
    }
    segs.push(target_mod);
    Some(segs.join("::"))
}

fn resolve_msg_rust_path(
    cur_file: &str,
    fq_type: &str,
    reg: &GlobalRegistry,
) -> Result<(String, bool), String> {
    if let Some(info) = reg.messages.get(fq_type) {
        let path = match relative_module_prefix(cur_file, &info.file_name) {
            Some(prefix) => format!("{prefix}::{}", info.rust_name),
            None => info.rust_name.clone(),
        };
        return Ok((path, info.direct_opaque));
    }
    let short = fq_type.rsplit('.').next().unwrap_or(fq_type);
    if short.is_empty() {
        return Err(format!("unresolved proto message type {fq_type:?}"));
    }
    Ok((to_pascal_case(short), false))
}

fn resolve_borrowed_rust_path(
    cur_file: &str,
    fq_type: &str,
    reg: &GlobalRegistry,
) -> Result<String, String> {
    if let Some(info) = reg.messages.get(fq_type) {
        let borrowed_ident = format!("{}Borrowed", info.rust_name);
        return Ok(match relative_module_prefix(cur_file, &info.file_name) {
            Some(prefix) => format!("{prefix}::{borrowed_ident}"),
            None => borrowed_ident,
        });
    }
    let short = fq_type.rsplit('.').next().unwrap_or(fq_type);
    if short.is_empty() {
        return Err(format!("unresolved proto message type {fq_type:?}"));
    }
    Ok(format!("{}Borrowed", to_pascal_case(short)))
}

fn resolve_opaque_rust_path(cur_file: &str, fq_type: &str, reg: &GlobalRegistry) -> Option<String> {
    let info = reg.messages.get(fq_type)?;
    if !info.direct_opaque {
        return None;
    }
    let opaque_ident = format!("Opaque{}", info.rust_name);
    Some(match relative_module_prefix(cur_file, &info.file_name) {
        Some(prefix) => format!("{prefix}::{opaque_ident}"),
        None => opaque_ident,
    })
}

/// Checks if `start_fq` can reach `target_fq` through non-boxed singular message or oneof fields.
fn can_reach_singular(
    start_fq: &str,
    target_fq: &str,
    reg: &GlobalRegistry,
    visited: &mut HashSet<String>,
) -> bool {
    if start_fq == target_fq {
        return true;
    }
    if !visited.insert(start_fq.to_owned()) {
        return false;
    }
    let Some(info) = reg.messages.get(start_fq) else {
        return false;
    };
    for f in &info.desc.field {
        if f.label() != Label::Repeated && f.r#type() == Type::Message {
            let next_fq = f.type_name.as_deref().unwrap_or("");
            if !reg.map_entries.contains_key(next_fq)
                && can_reach_singular(next_fq, target_fq, reg, visited)
            {
                return true;
            }
        }
    }
    false
}

fn generate_file(file: &FileDescriptorProto, reg: &GlobalRegistry) -> Result<File, String> {
    let proto_name = file.name.as_deref().unwrap_or("generated.proto");
    let out_filename = out_filename_for_proto(proto_name);

    let pkg_prefix = match file.package.as_deref() {
        Some(pkg) if !pkg.is_empty() => format!(".{pkg}"),
        _ => String::new(),
    };

    let mut code = String::with_capacity(16 * 1024);
    let _ = writeln!(
        code,
        "// @generated by protoc-gen-omnibuf-rs from {proto_name}. DO NOT EDIT.\n"
    );

    for e in &file.enum_type {
        let ename = e.name.as_deref().unwrap_or("UnknownEnum");
        let fq = format!("{pkg_prefix}.{ename}");
        let enum_rust_name = reg
            .enums
            .get(&fq)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| sanitize_pascal_ident(&to_pascal_case(ename)));
        emit_enum(&mut code, &enum_rust_name, e);
    }

    let mut msg_list = Vec::new();
    flatten_messages(&pkg_prefix, &file.message_type, reg, &mut msg_list);

    for (fq_name, rust_name, desc) in &msg_list {
        emit_message(&mut code, proto_name, fq_name, rust_name, desc, reg)?;
    }

    Ok(File {
        name: Some(out_filename),
        insertion_point: None,
        content: Some(code),
        generated_code_info: None,
    })
}

fn is_map_entry(desc: &DescriptorProto) -> bool {
    desc.options
        .as_ref()
        .and_then(|o| o.map_entry)
        .unwrap_or(false)
}

fn flatten_messages<'a>(
    fq_parent: &str,
    messages: &'a [DescriptorProto],
    reg: &GlobalRegistry,
    out: &mut Vec<(String, String, &'a DescriptorProto)>,
) {
    for m in messages {
        if is_map_entry(m) {
            continue;
        }
        let mname = m.name.as_deref().unwrap_or("UnknownMsg");
        let fq = format!("{fq_parent}.{mname}");
        let rust_name = reg
            .messages
            .get(&fq)
            .map(|info| info.rust_name.clone())
            .unwrap_or_else(|| sanitize_pascal_ident(&to_pascal_case(mname)));
        out.push((fq.clone(), rust_name, m));
        flatten_messages(&fq, &m.nested_type, reg, out);
    }
}

fn emit_enum(code: &mut String, enum_name: &str, e: &EnumDescriptorProto) {
    let _ = writeln!(code, "#[allow(dead_code, clippy::enum_variant_names)]");
    let _ = writeln!(
        code,
        "#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]"
    );
    let _ = writeln!(code, "#[repr(i32)]");
    let _ = writeln!(code, "pub enum {enum_name} {{");
    let mut seen_numbers = HashSet::new();
    let mut seen_names = HashSet::new();
    let mut emitted_idx = 0usize;
    for v in &e.value {
        let num = v.number.unwrap_or(0);
        if !seen_numbers.insert(num) {
            continue;
        }
        let base_vname =
            sanitize_enum_variant(&to_pascal_case(v.name.as_deref().unwrap_or("Unspecified")));
        let mut vname = base_vname.clone();
        if !seen_names.insert(vname.clone()) {
            let suffix = if num < 0 {
                format!("Neg{}", num.unsigned_abs())
            } else {
                num.to_string()
            };
            vname = format!("{base_vname}_{suffix}");
            let mut extra = 2usize;
            while !seen_names.insert(vname.clone()) {
                vname = format!("{base_vname}_{suffix}_{extra}");
                extra += 1;
            }
        }
        if emitted_idx == 0 {
            let _ = writeln!(code, "    #[default]");
        }
        let _ = writeln!(code, "    {vname} = {num},");
        emitted_idx += 1;
    }
    let _ = writeln!(code, "}}\n");
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProtoScalar {
    Uint32,
    Uint64,
    Sint32,
    Sint64,
    Fixed32,
    Fixed64,
    Sfixed32,
    Sfixed64,
    Float32,
    Float64,
    Bool,
    String,
    Bytes,
    Enum,
}

impl ProtoScalar {
    fn from_proto_type(t: Type) -> Result<Self, String> {
        match t {
            Type::Uint32 => Ok(Self::Uint32),
            Type::Uint64 => Ok(Self::Uint64),
            Type::Int32 | Type::Sint32 => Ok(Self::Sint32),
            Type::Int64 | Type::Sint64 => Ok(Self::Sint64),
            Type::Fixed32 => Ok(Self::Fixed32),
            Type::Fixed64 => Ok(Self::Fixed64),
            Type::Sfixed32 => Ok(Self::Sfixed32),
            Type::Sfixed64 => Ok(Self::Sfixed64),
            Type::Float => Ok(Self::Float32),
            Type::Double => Ok(Self::Float64),
            Type::Bool => Ok(Self::Bool),
            Type::String => Ok(Self::String),
            Type::Bytes => Ok(Self::Bytes),
            Type::Enum => Ok(Self::Enum),
            other => Err(format!("unsupported scalar proto type {other:?}")),
        }
    }

    fn rust_type(self) -> &'static str {
        match self {
            Self::Uint32 | Self::Fixed32 => "u32",
            Self::Uint64 | Self::Fixed64 => "u64",
            Self::Sint32 | Self::Sfixed32 | Self::Enum => "i32",
            Self::Sint64 | Self::Sfixed64 => "i64",
            Self::Float32 => "f32",
            Self::Float64 => "f64",
            Self::Bool => "bool",
            Self::String => "::std::string::String",
            Self::Bytes => "::std::vec::Vec<u8>",
        }
    }

    fn wire_type(self) -> u8 {
        match self {
            Self::Uint32 | Self::Uint64 => WIRE_UINT,
            Self::Sint32 | Self::Sint64 | Self::Enum => WIRE_SINT,
            Self::Bool => WIRE_BOOL_FALSE,
            Self::Fixed32 => WIRE_FIXED32,
            Self::Fixed64 => WIRE_FIXED64,
            Self::Sfixed32 => WIRE_SFIXED32,
            Self::Sfixed64 => WIRE_SFIXED64,
            Self::Float32 => WIRE_FLOAT32,
            Self::Float64 => WIRE_FLOAT64,
            Self::String => WIRE_STRING,
            Self::Bytes => WIRE_BYTES,
        }
    }
}

#[derive(Clone)]
enum GenFieldKind {
    Scalar(ProtoScalar),
    OptScalar(ProtoScalar),
    SubMsg {
        rust_type: String,
        borrowed_type: String,
        opaque_type: Option<String>,
        boxed: bool,
    },
    ScalarArr(ProtoScalar),
    SubMsgArr {
        rust_type: String,
        borrowed_type: String,
        opaque_type: Option<String>,
    },
    Map {
        key: ProtoScalar,
        val: MapValKind,
    },
}

#[derive(Clone)]
enum MapValKind {
    Scalar(ProtoScalar),
    SubMsg {
        rust_type: String,
        borrowed_type: String,
    },
}

#[derive(Clone)]
struct GenField {
    number: u32,
    proto_name: String,
    rust_ident: String,
    method_stem: String,
    kind: GenFieldKind,
}

#[derive(Clone)]
enum OneofArmKind {
    Scalar(ProtoScalar),
    SubMsg {
        rust_type: String,
        borrowed_type: String,
        boxed: bool,
    },
}

#[derive(Clone)]
struct GenOneofArm {
    number: u32,
    proto_name: String,
    variant_ident: String,
    kind: OneofArmKind,
}

#[derive(Clone)]
struct GenOneof {
    enum_name: String,
    field_ident: String,
    first_number: u32,
    arms: Vec<GenOneofArm>,
}

impl GenOneof {
    fn needs_borrowed_lifetime(&self) -> bool {
        self.arms.iter().any(|arm| match &arm.kind {
            OneofArmKind::Scalar(ProtoScalar::String | ProtoScalar::Bytes) => true,
            OneofArmKind::SubMsg { .. } => true,
            OneofArmKind::Scalar(_) => false,
        })
    }
}

enum OrderedMember {
    Field(GenField),
    Oneof(GenOneof),
}

fn is_reserved_opaque_stem(stem: &str) -> bool {
    matches!(
        stem,
        "new"
            | "try_new"
            | "from_owned"
            | "try_from_owned"
            | "validate"
            | "unmarshal"
            | "try_unmarshal"
            | "raw_bytes"
            | "dirty_mut"
            | "heap_mut"
            | "marshal"
            | "marshal_append"
            | "try_marshal"
            | "try_marshal_append"
            | "marshal_validated"
            | "marshal_validated_append"
    )
}

fn emit_message(
    code: &mut String,
    cur_file: &str,
    fq_msg: &str,
    rust_name: &str,
    desc: &DescriptorProto,
    reg: &GlobalRegistry,
) -> Result<(), String> {
    for e in &desc.enum_type {
        let ename = e.name.as_deref().unwrap_or("UnknownEnum");
        let fq = format!("{fq_msg}.{ename}");
        let enum_rust_name = reg
            .enums
            .get(&fq)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| {
                sanitize_pascal_ident(&format!("{rust_name}{}", to_pascal_case(ename)))
            });
        emit_enum(code, &enum_rust_name, e);
    }

    let mut fields = Vec::with_capacity(desc.field.len());
    let mut oneof_arms_map: HashMap<usize, Vec<GenOneofArm>> = HashMap::new();
    let mut used_stems: HashSet<String> = HashSet::new();
    let mut used_idents: HashSet<String> = HashSet::new();

    for f in &desc.field {
        let fnum = u32::try_from(f.number.unwrap_or(0))
            .map_err(|_| format!("invalid field number on {rust_name}"))?;
        if fnum == 0 {
            return Err(format!("invalid field number 0 on {rust_name}"));
        }
        let proto_name = f.name.as_deref().unwrap_or("field").to_owned();
        let label = f.label();
        let ftype = f.r#type();
        let is_proto3_opt = f.proto3_optional.unwrap_or(false);

        if let Some(oneof_idx) = f.oneof_index
            && !is_proto3_opt
        {
            let oidx = usize::try_from(oneof_idx)
                .map_err(|_| format!("invalid oneof_index on {rust_name}.{proto_name}"))?;
            let arm_kind = if ftype == Type::Message {
                let tname = f.type_name.as_deref().unwrap_or("");
                let (sub_rust, _) = resolve_msg_rust_path(cur_file, tname, reg)?;
                let sub_borrowed = resolve_borrowed_rust_path(cur_file, tname, reg)?;
                let mut visited = HashSet::new();
                let boxed = can_reach_singular(tname, fq_msg, reg, &mut visited);
                OneofArmKind::SubMsg {
                    rust_type: sub_rust,
                    borrowed_type: sub_borrowed,
                    boxed,
                }
            } else {
                OneofArmKind::Scalar(ProtoScalar::from_proto_type(ftype)?)
            };

            let mut var_ident = sanitize_enum_variant(&to_pascal_case(&proto_name));
            let existing = oneof_arms_map.entry(oidx).or_default();
            if existing.iter().any(|a| a.variant_ident == var_ident) {
                var_ident = format!("{var_ident}{fnum}");
            }
            existing.push(GenOneofArm {
                number: fnum,
                proto_name,
                variant_ident: var_ident,
                kind: arm_kind,
            });
            continue;
        }

        let mut method_stem = to_snake_case(&proto_name);
        if is_reserved_opaque_stem(&method_stem) || !used_stems.insert(method_stem.clone()) {
            method_stem = format!("{method_stem}_{fnum}");
            used_stems.insert(method_stem.clone());
        }
        let mut rust_ident = escape_rust_ident(&method_stem);
        if !used_idents.insert(rust_ident.clone()) {
            rust_ident = format!("f_{fnum}");
            used_idents.insert(rust_ident.clone());
        }

        let kind = if label == Label::Repeated && ftype == Type::Message {
            let tname = f.type_name.as_deref().unwrap_or("");
            if let Some(entry) = reg.map_entries.get(tname) {
                let key = ProtoScalar::from_proto_type(entry.key_field.r#type())?;
                let val = if entry.val_field.r#type() == Type::Message {
                    let vt = entry.val_field.type_name.as_deref().unwrap_or("");
                    let (v_rust, _) = resolve_msg_rust_path(cur_file, vt, reg)?;
                    let v_borrowed = resolve_borrowed_rust_path(cur_file, vt, reg)?;
                    MapValKind::SubMsg {
                        rust_type: v_rust,
                        borrowed_type: v_borrowed,
                    }
                } else {
                    MapValKind::Scalar(ProtoScalar::from_proto_type(entry.val_field.r#type())?)
                };
                GenFieldKind::Map { key, val }
            } else {
                let (sub_rust, _) = resolve_msg_rust_path(cur_file, tname, reg)?;
                let sub_borrowed = resolve_borrowed_rust_path(cur_file, tname, reg)?;
                let opaque_type = resolve_opaque_rust_path(cur_file, tname, reg);
                GenFieldKind::SubMsgArr {
                    rust_type: sub_rust,
                    borrowed_type: sub_borrowed,
                    opaque_type,
                }
            }
        } else if label == Label::Repeated {
            GenFieldKind::ScalarArr(ProtoScalar::from_proto_type(ftype)?)
        } else if ftype == Type::Message {
            let tname = f.type_name.as_deref().unwrap_or("");
            let (sub_rust, _) = resolve_msg_rust_path(cur_file, tname, reg)?;
            let sub_borrowed = resolve_borrowed_rust_path(cur_file, tname, reg)?;
            let opaque_type = resolve_opaque_rust_path(cur_file, tname, reg);
            let mut visited = HashSet::new();
            let boxed = can_reach_singular(tname, fq_msg, reg, &mut visited);
            GenFieldKind::SubMsg {
                rust_type: sub_rust,
                borrowed_type: sub_borrowed,
                opaque_type,
                boxed,
            }
        } else if is_proto3_opt {
            GenFieldKind::OptScalar(ProtoScalar::from_proto_type(ftype)?)
        } else {
            GenFieldKind::Scalar(ProtoScalar::from_proto_type(ftype)?)
        };

        fields.push(GenField {
            number: fnum,
            proto_name,
            rust_ident,
            method_stem,
            kind,
        });
    }

    fields.sort_by_key(|f| f.number);

    let mut oneofs = Vec::new();
    for (oidx, oneof_proto) in desc.oneof_decl.iter().enumerate() {
        let Some(mut arms) = oneof_arms_map.remove(&oidx) else {
            continue;
        };
        if arms.is_empty() {
            continue;
        }
        arms.sort_by_key(|a| a.number);
        let raw_oname = oneof_proto.name.as_deref().unwrap_or("oneof");
        let enum_name = format!("{rust_name}{}", to_pascal_case(raw_oname));
        let base_snake = to_snake_case(raw_oname);
        let mut field_ident = escape_rust_ident(&base_snake);
        if !used_idents.insert(field_ident.clone()) {
            field_ident = format!("{base_snake}_oneof");
            used_idents.insert(field_ident.clone());
        }
        let first_number = arms[0].number;
        oneofs.push(GenOneof {
            enum_name,
            field_ident,
            first_number,
            arms,
        });
    }
    oneofs.sort_by_key(|o| o.first_number);

    // Emit oneof enums before the parent struct.
    for oneof in &oneofs {
        let _ = writeln!(code, "#[allow(dead_code, clippy::enum_variant_names)]");
        let _ = writeln!(code, "#[derive(Clone, Debug, PartialEq)]");
        let _ = writeln!(code, "pub enum {} {{", oneof.enum_name);
        for arm in &oneof.arms {
            let arm_ty = match &arm.kind {
                OneofArmKind::Scalar(s) => s.rust_type().to_owned(),
                OneofArmKind::SubMsg {
                    rust_type, boxed, ..
                } => {
                    if *boxed {
                        format!("::std::boxed::Box<{rust_type}>")
                    } else {
                        rust_type.clone()
                    }
                }
            };
            let _ = writeln!(code, "    {}({arm_ty}),", arm.variant_ident);
        }
        let _ = writeln!(code, "}}\n");
    }

    // 1. Struct definition
    let _ = writeln!(code, "#[allow(dead_code)]");
    let _ = writeln!(code, "#[derive(Clone, Debug, Default, PartialEq)]");
    let _ = writeln!(code, "pub struct {rust_name} {{");
    for gf in &fields {
        let fty = rust_field_type(&gf.kind);
        let _ = writeln!(code, "    pub {}: {fty},", gf.rust_ident);
    }
    for oneof in &oneofs {
        let _ = writeln!(
            code,
            "    pub {}: ::core::option::Option<{}>,",
            oneof.field_ident, oneof.enum_name
        );
    }
    let _ = writeln!(code, "}}\n");

    // 2. Inherent fast convenience methods
    let _ = writeln!(code, "#[allow(dead_code)]");
    let _ = writeln!(code, "impl {rust_name} {{");
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn marshal_omnibuf(&self) -> ::std::vec::Vec<u8> {{"
    );
    let _ = writeln!(
        code,
        "        let cap = <Self as ::omnibuf::Message>::encoded_size_hint(self).max(128);"
    );
    let _ = writeln!(
        code,
        "        let mut dst = ::std::vec::Vec::with_capacity(cap);"
    );
    let _ = writeln!(code, "        self.marshal_omnibuf_append(&mut dst);");
    let _ = writeln!(code, "        dst");
    let _ = writeln!(code, "    }}\n");
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn marshal_omnibuf_append(&self, dst: &mut ::std::vec::Vec<u8>) {{"
    );
    let _ = writeln!(
        code,
        "        let _ = <Self as ::omnibuf::Message>::encode_omnibuf_append(self, dst, true);"
    );
    let _ = writeln!(code, "    }}\n");
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn unmarshal_omnibuf(&mut self, data: &[u8]) -> ::omnibuf::Result<()> {{"
    );
    let _ = writeln!(
        code,
        "        <Self as ::omnibuf::Message>::decode_omnibuf(self, data)"
    );
    let _ = writeln!(code, "    }}");
    let _ = writeln!(code, "}}\n");

    // 3. `omnibuf::Message` implementation
    emit_message_trait_impl(code, desc, rust_name, &fields, &oneofs);

    // 4. Zero-copy borrowed `<Msg>Borrowed<'a>` view & `DecodeBorrowed<'a>` impl
    emit_borrowed_view(code, rust_name, &fields, &oneofs);

    // 5. Zero-unpack `Opaque<Msg><'a>` view & splicer (when all field numbers < 64 and no oneofs)
    if oneofs.is_empty() && fields.iter().all(|f| f.number < 64) {
        emit_opaque_view(code, rust_name, &fields);
    }

    Ok(())
}

fn rust_field_type(kind: &GenFieldKind) -> String {
    match kind {
        GenFieldKind::Scalar(s) => s.rust_type().to_owned(),
        GenFieldKind::OptScalar(s) => format!("::core::option::Option<{}>", s.rust_type()),
        GenFieldKind::SubMsg {
            rust_type, boxed, ..
        } => {
            if *boxed {
                format!("::core::option::Option<::std::boxed::Box<{rust_type}>>")
            } else {
                format!("::core::option::Option<{rust_type}>")
            }
        }
        GenFieldKind::ScalarArr(s) => format!("::std::vec::Vec<{}>", s.rust_type()),
        GenFieldKind::SubMsgArr { rust_type, .. } => format!("::std::vec::Vec<{rust_type}>"),
        GenFieldKind::Map { key, val } => {
            let kt = key.rust_type();
            let vt = match val {
                MapValKind::Scalar(vs) => vs.rust_type().to_owned(),
                MapValKind::SubMsg { rust_type, .. } => rust_type.clone(),
            };
            format!("::std::collections::HashMap<{kt}, {vt}>")
        }
    }
}

fn emit_message_trait_impl(
    code: &mut String,
    desc: &DescriptorProto,
    rust_name: &str,
    fields: &[GenField],
    oneofs: &[GenOneof],
) {
    let proto_short_name = desc.name.as_deref().unwrap_or(rust_name);
    let total_members = fields.len() + oneofs.len();

    let mut ordered = Vec::with_capacity(total_members);
    for gf in fields {
        ordered.push((gf.number, OrderedMember::Field(gf.clone())));
    }
    for go in oneofs {
        ordered.push((go.first_number, OrderedMember::Oneof(go.clone())));
    }
    ordered.sort_by_key(|(n, _)| *n);

    let _ = writeln!(code, "impl ::omnibuf::Message for {rust_name} {{");
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    fn encode_omnibuf_append(&self, dst: &mut ::std::vec::Vec<u8>, deterministic: bool) -> ::omnibuf::Result<()> {{"
    );
    let _ = writeln!(code, "        let _ = deterministic;");
    for (_, member) in &ordered {
        match member {
            OrderedMember::Field(gf) => emit_encode_stmt(code, gf, "self.", true),
            OrderedMember::Oneof(go) => emit_encode_oneof(code, go),
        }
    }
    let _ = writeln!(code, "        ::core::result::Result::Ok(())");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    fn decode_omnibuf_at_depth(&mut self, data: &[u8], depth: usize, merge: bool) -> ::omnibuf::Result<()> {{"
    );
    if total_members == 0 {
        let _ = writeln!(code, "        let _ = merge;");
        let _ = writeln!(
            code,
            "        let mut dec = ::omnibuf::Decoder::with_depth(data, depth)?;"
        );
        let _ = writeln!(
            code,
            "        while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {{"
        );
        let _ = writeln!(code, "            dec.skip_unknown(fnum, wt)?;");
        let _ = writeln!(code, "        }}");
        let _ = writeln!(code, "        ::core::result::Result::Ok(())");
    } else {
        let _ = writeln!(
            code,
            "        let mut dec = ::omnibuf::Decoder::with_depth(data, depth)?;"
        );
        let _ = writeln!(code, "        if !merge {{ self.clear_omnibuf(); }}");
        let _ = writeln!(
            code,
            "        while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {{"
        );
        let _ = writeln!(code, "            match fnum {{");
        for gf in fields {
            emit_decode_arm(code, gf);
        }
        for go in oneofs {
            for arm in &go.arms {
                emit_decode_oneof_arm(code, go, arm);
            }
        }
        let _ = writeln!(code, "                _ => dec.skip_unknown(fnum, wt)?,");
        let _ = writeln!(code, "            }}");
        let _ = writeln!(code, "        }}");
        let _ = writeln!(code, "        ::core::result::Result::Ok(())");
    }
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(code, "    fn clear_omnibuf(&mut self) {{");
    for gf in fields {
        let clear_expr = clear_stmt_for_field(gf);
        let _ = writeln!(code, "        {clear_expr}");
    }
    for go in oneofs {
        let fident = &go.field_ident;
        let _ = writeln!(
            code,
            "        if self.{fident}.is_some() {{ self.{fident} = ::core::option::Option::None; }}"
        );
    }
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    fn min_wire_size_bounded(&self, depth_rem: usize) -> usize {{"
    );
    let _ = writeln!(code, "        let _ = depth_rem;");
    if total_members == 0 {
        let _ = writeln!(code, "        0");
    } else {
        let _ = writeln!(code, "        let mut __sz = 0usize;");
        for gf in fields {
            emit_min_wire_size_field(code, gf);
        }
        for go in oneofs {
            emit_min_wire_size_oneof(code, go);
        }
        let _ = writeln!(code, "        __sz");
    }
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(
        code,
        "    fn build_schema_meta(active: &mut ::std::collections::HashSet<::core::any::TypeId>, depth: usize) -> ::core::option::Option<::omnibuf::SchemaMeta> {{"
    );
    let _ = writeln!(code, "        if depth >= ::omnibuf::MAX_NESTING_DEPTH {{");
    let _ = writeln!(code, "            return ::core::option::Option::None;");
    let _ = writeln!(code, "        }}");
    let _ = writeln!(
        code,
        "        let type_id = ::core::any::TypeId::of::<Self>();"
    );
    let _ = writeln!(code, "        let mut meta = ::omnibuf::SchemaMeta {{");
    let _ = writeln!(
        code,
        "            type_name: ::std::string::String::from({proto_short_name:?}),"
    );
    let _ = writeln!(
        code,
        "            fields: ::std::collections::BTreeMap::new(),"
    );
    let _ = writeln!(
        code,
        "            children: ::std::collections::BTreeMap::new(),"
    );
    let _ = writeln!(code, "        }};");
    for gf in fields {
        let fnum = gf.number;
        let pname = &gf.proto_name;
        let _ = writeln!(
            code,
            "        meta.fields.insert({fnum}, ::std::string::String::from({pname:?}));"
        );
    }
    for go in oneofs {
        for arm in &go.arms {
            let fnum = arm.number;
            let pname = &arm.proto_name;
            let _ = writeln!(
                code,
                "        meta.fields.insert({fnum}, ::std::string::String::from({pname:?}));"
            );
        }
    }
    let _ = writeln!(code, "        if !active.insert(type_id) {{");
    let _ = writeln!(
        code,
        "            return ::core::option::Option::Some(meta);"
    );
    let _ = writeln!(code, "        }}");
    for gf in fields {
        let fnum = gf.number;
        let child_ty = match &gf.kind {
            GenFieldKind::SubMsg { rust_type, .. } | GenFieldKind::SubMsgArr { rust_type, .. } => {
                Some(rust_type.as_str())
            }
            GenFieldKind::Map {
                val: MapValKind::SubMsg { rust_type, .. },
                ..
            } => Some(rust_type.as_str()),
            _ => None,
        };
        if let Some(rt) = child_ty {
            let _ = writeln!(
                code,
                "        if let ::core::option::Option::Some(c) = <{rt} as ::omnibuf::Message>::build_schema_meta(active, depth + 2) {{ meta.children.insert({fnum}, c); }}"
            );
        }
    }
    for go in oneofs {
        for arm in &go.arms {
            if let OneofArmKind::SubMsg { rust_type, .. } = &arm.kind {
                let fnum = arm.number;
                let _ = writeln!(
                    code,
                    "        if let ::core::option::Option::Some(c) = <{rust_type} as ::omnibuf::Message>::build_schema_meta(active, depth + 2) {{ meta.children.insert({fnum}, c); }}"
                );
            }
        }
    }
    let _ = writeln!(code, "        active.remove(&type_id);");
    let _ = writeln!(code, "        ::core::option::Option::Some(meta)");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(
        code,
        "    fn is_schema_cyclic(active: &mut ::std::collections::HashSet<::core::any::TypeId>, depth: usize) -> bool {{"
    );
    let _ = writeln!(
        code,
        "        if depth >= ::omnibuf::MAX_NESTING_DEPTH {{ return false; }}"
    );
    let _ = writeln!(
        code,
        "        let type_id = ::core::any::TypeId::of::<Self>();"
    );
    let _ = writeln!(
        code,
        "        if !active.insert(type_id) {{ return true; }}"
    );
    for gf in fields {
        let child_ty = match &gf.kind {
            GenFieldKind::SubMsg { rust_type, .. } | GenFieldKind::SubMsgArr { rust_type, .. } => {
                Some(rust_type.as_str())
            }
            GenFieldKind::Map {
                val: MapValKind::SubMsg { rust_type, .. },
                ..
            } => Some(rust_type.as_str()),
            _ => None,
        };
        if let Some(rt) = child_ty {
            let _ = writeln!(
                code,
                "        if <{rt} as ::omnibuf::Message>::is_schema_cyclic(active, depth + 2) {{ active.remove(&type_id); return true; }}"
            );
        }
    }
    for go in oneofs {
        for arm in &go.arms {
            if let OneofArmKind::SubMsg { rust_type, .. } = &arm.kind {
                let _ = writeln!(
                    code,
                    "        if <{rust_type} as ::omnibuf::Message>::is_schema_cyclic(active, depth + 2) {{ active.remove(&type_id); return true; }}"
                );
            }
        }
    }
    let _ = writeln!(code, "        active.remove(&type_id);");
    let _ = writeln!(code, "        false");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(
        code,
        "    fn build_value_schema_meta(&self, depth: usize) -> ::core::option::Option<::omnibuf::SchemaMeta> {{"
    );
    let _ = writeln!(
        code,
        "        if depth >= ::omnibuf::MAX_NESTING_DEPTH {{ return ::core::option::Option::None; }}"
    );
    let _ = writeln!(code, "        let mut meta = ::omnibuf::SchemaMeta {{");
    let _ = writeln!(
        code,
        "            type_name: ::std::string::String::from({proto_short_name:?}),"
    );
    let _ = writeln!(
        code,
        "            fields: ::std::collections::BTreeMap::new(),"
    );
    let _ = writeln!(
        code,
        "            children: ::std::collections::BTreeMap::new(),"
    );
    let _ = writeln!(code, "        }};");
    for gf in fields {
        let fnum = gf.number;
        let pname = &gf.proto_name;
        let _ = writeln!(
            code,
            "        meta.fields.insert({fnum}, ::std::string::String::from({pname:?}));"
        );
    }
    for go in oneofs {
        for arm in &go.arms {
            let fnum = arm.number;
            let pname = &arm.proto_name;
            let _ = writeln!(
                code,
                "        meta.fields.insert({fnum}, ::std::string::String::from({pname:?}));"
            );
        }
    }
    let mut child_code = String::new();
    for gf in fields {
        let fnum = gf.number;
        let fident = &gf.rust_ident;
        match &gf.kind {
            GenFieldKind::SubMsg {
                rust_type, boxed, ..
            } => {
                let sub_ref = if *boxed { "&**__sub" } else { "__sub" };
                let _ = writeln!(
                    child_code,
                    "            if let ::core::option::Option::Some(ref __sub) = self.{fident} && let ::core::option::Option::Some(__c) = <{rust_type} as ::omnibuf::Message>::build_value_schema_meta({sub_ref}, depth + 2) {{ meta.children.insert({fnum}, __c); }}"
                );
            }
            GenFieldKind::SubMsgArr { rust_type, .. } => {
                let _ = writeln!(
                    child_code,
                    "            if !self.{fident}.is_empty() {{ let mut __ch = ::core::option::Option::None; for __el in &self.{fident} {{ if let ::core::option::Option::Some(__cm) = <{rust_type} as ::omnibuf::Message>::build_value_schema_meta(__el, depth + 2) {{ __ch = ::core::option::Option::Some(::omnibuf::merge_schema_meta(__ch, __cm)); }} }} if let ::core::option::Option::Some(__c) = __ch {{ meta.children.insert({fnum}, __c); }} }}"
                );
            }
            GenFieldKind::Map {
                val: MapValKind::SubMsg { rust_type, .. },
                ..
            } => {
                let _ = writeln!(
                    child_code,
                    "            if !self.{fident}.is_empty() {{ let mut __ch = ::core::option::Option::None; for __el in self.{fident}.values() {{ if let ::core::option::Option::Some(__cm) = <{rust_type} as ::omnibuf::Message>::build_value_schema_meta(__el, depth + 2) {{ __ch = ::core::option::Option::Some(::omnibuf::merge_schema_meta(__ch, __cm)); }} }} if let ::core::option::Option::Some(__c) = __ch {{ meta.children.insert({fnum}, __c); }} }}"
                );
            }
            _ => {}
        }
    }
    for go in oneofs {
        let fident = &go.field_ident;
        let ename = &go.enum_name;
        let has_sub = go
            .arms
            .iter()
            .any(|a| matches!(a.kind, OneofArmKind::SubMsg { .. }));
        if has_sub {
            let _ = writeln!(
                child_code,
                "            if let ::core::option::Option::Some(ref __ov) = self.{fident} {{ match __ov {{"
            );
            for arm in &go.arms {
                if let OneofArmKind::SubMsg {
                    rust_type, boxed, ..
                } = &arm.kind
                {
                    let fnum = arm.number;
                    let vident = &arm.variant_ident;
                    let sub_ref = if *boxed { "&**__v" } else { "__v" };
                    let _ = writeln!(
                        child_code,
                        "                {ename}::{vident}(__v) => {{ if let ::core::option::Option::Some(__c) = <{rust_type} as ::omnibuf::Message>::build_value_schema_meta({sub_ref}, depth + 2) {{ meta.children.insert({fnum}, __c); }} }}"
                    );
                }
            }
            let _ = writeln!(child_code, "                _ => {{}}");
            let _ = writeln!(child_code, "            }} }}");
        }
    }
    if !child_code.is_empty() {
        let _ = writeln!(
            code,
            "        if depth + 2 < ::omnibuf::MAX_NESTING_DEPTH {{"
        );
        code.push_str(&child_code);
        let _ = writeln!(code, "        }}");
    }
    let _ = writeln!(code, "        ::core::option::Option::Some(meta)");
    let _ = writeln!(code, "    }}");
    let _ = writeln!(code, "}}\n");
}

fn emit_encode_oneof(code: &mut String, go: &GenOneof) {
    let fident = &go.field_ident;
    let ename = &go.enum_name;
    let _ = writeln!(
        code,
        "        if let ::core::option::Option::Some(ref __active) = self.{fident} {{"
    );
    let _ = writeln!(code, "            match __active {{");
    for arm in &go.arms {
        let fnum = arm.number;
        let vident = &arm.variant_ident;
        let _ = writeln!(code, "                {ename}::{vident}(__v) => {{");
        match &arm.kind {
            OneofArmKind::Scalar(s) => {
                let expr = match s {
                    ProtoScalar::String | ProtoScalar::Bytes => "__v",
                    _ => "*__v",
                };
                emit_scalar_write_call(code, fnum, *s, expr);
            }
            OneofArmKind::SubMsg { boxed, .. } => {
                let inner = if *boxed { "&**__v" } else { "__v" };
                let _ = writeln!(
                    code,
                    "                    ::omnibuf::codec::write_sub_msg_field(dst, {fnum}, {inner}, deterministic)?;"
                );
            }
        }
        let _ = writeln!(code, "                }}");
    }
    let _ = writeln!(code, "            }}");
    let _ = writeln!(code, "        }}");
}

fn emit_decode_oneof_arm(code: &mut String, go: &GenOneof, arm: &GenOneofArm) {
    let fnum = arm.number;
    let fident = &go.field_ident;
    let ename = &go.enum_name;
    let vident = &arm.variant_ident;

    match &arm.kind {
        OneofArmKind::Scalar(ProtoScalar::Bool) => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == ::omnibuf::wire::WIRE_BOOL_FALSE || wt == ::omnibuf::wire::WIRE_BOOL_TRUE => {{ self.{fident} = ::core::option::Option::Some({ename}::{vident}(wt == ::omnibuf::wire::WIRE_BOOL_TRUE)); }}"
            );
        }
        OneofArmKind::Scalar(s) => {
            let wt = s.wire_type();
            let expr = scalar_decode_expr(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ self.{fident} = ::core::option::Option::Some({ename}::{vident}({expr})); }}"
            );
        }
        OneofArmKind::SubMsg {
            rust_type, boxed, ..
        } => {
            let _ = writeln!(code, "                {fnum} if wt == {WIRE_SUB_MSG} => {{");
            let _ = writeln!(
                code,
                "                    let __sb = dec.read_container(0)?;"
            );
            let _ = writeln!(
                code,
                "                    if let ::core::option::Option::Some({ename}::{vident}(ref mut __sub)) = self.{fident} {{"
            );
            if *boxed {
                let _ = writeln!(
                    code,
                    "                        <{rust_type} as ::omnibuf::Message>::decode_omnibuf_at_depth(&mut **__sub, __sb, depth + 1, true)?;"
                );
            } else {
                let _ = writeln!(
                    code,
                    "                        <{rust_type} as ::omnibuf::Message>::decode_omnibuf_at_depth(__sub, __sb, depth + 1, true)?;"
                );
            }
            let _ = writeln!(code, "                    }} else {{");
            if *boxed {
                let _ = writeln!(
                    code,
                    "                        let mut __sub = ::std::boxed::Box::new({rust_type}::default());"
                );
                let _ = writeln!(
                    code,
                    "                        <{rust_type} as ::omnibuf::Message>::decode_omnibuf_at_depth(&mut *__sub, __sb, depth + 1, true)?;"
                );
            } else {
                let _ = writeln!(
                    code,
                    "                        let mut __sub = {rust_type}::default();"
                );
                let _ = writeln!(
                    code,
                    "                        <{rust_type} as ::omnibuf::Message>::decode_omnibuf_at_depth(&mut __sub, __sb, depth + 1, true)?;"
                );
            }
            let _ = writeln!(
                code,
                "                        self.{fident} = ::core::option::Option::Some({ename}::{vident}(__sub));"
            );
            let _ = writeln!(code, "                    }}");
            let _ = writeln!(code, "                }}");
        }
    }
}

fn emit_scalar_write_call(code: &mut String, fnum: u32, scalar: ProtoScalar, expr: &str) {
    match scalar {
        ProtoScalar::Uint32 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_uint_field(dst, {fnum}, u64::from({expr}));"
            );
        }
        ProtoScalar::Uint64 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_uint_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Sint32 | ProtoScalar::Enum => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_sint_field(dst, {fnum}, i64::from({expr}));"
            );
        }
        ProtoScalar::Sint64 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_sint_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Bool => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_bool_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Fixed32 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_fixed32_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Fixed64 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_fixed64_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Sfixed32 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_sfixed32_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Sfixed64 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_sfixed64_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Float32 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_float32_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::Float64 => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_float64_field(dst, {fnum}, {expr});"
            );
        }
        ProtoScalar::String => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_string_field(dst, {fnum}, {expr}.as_str());"
            );
        }
        ProtoScalar::Bytes => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_bytes_field(dst, {fnum}, {expr}.as_slice());"
            );
        }
    }
}

fn scalar_elem_write_snippet(scalar: ProtoScalar, var: &str) -> String {
    match scalar {
        ProtoScalar::Uint32 => {
            format!("::omnibuf::wire::append_varint(dst, u64::from(*{var}));")
        }
        ProtoScalar::Uint64 => {
            format!("::omnibuf::wire::append_varint(dst, *{var});")
        }
        ProtoScalar::Sint32 | ProtoScalar::Enum => {
            format!(
                "::omnibuf::wire::append_varint(dst, ::omnibuf::wire::encode_zigzag(i64::from(*{var})));"
            )
        }
        ProtoScalar::Sint64 => {
            format!("::omnibuf::wire::append_varint(dst, ::omnibuf::wire::encode_zigzag(*{var}));")
        }
        ProtoScalar::Bool => format!("dst.push(u8::from(*{var}));"),
        ProtoScalar::Fixed32 | ProtoScalar::Sfixed32 => {
            format!("dst.extend_from_slice(&({var}).to_le_bytes());")
        }
        ProtoScalar::Fixed64 | ProtoScalar::Sfixed64 => {
            format!("dst.extend_from_slice(&({var}).to_le_bytes());")
        }
        ProtoScalar::Float32 | ProtoScalar::Float64 => {
            format!("dst.extend_from_slice(&({var}).to_bits().to_le_bytes());")
        }
        ProtoScalar::String => {
            format!("::omnibuf::wire::append_bytes_elem(dst, ({var}).as_bytes());")
        }
        ProtoScalar::Bytes => {
            format!("::omnibuf::wire::append_bytes_elem(dst, ({var}).as_slice());")
        }
    }
}

fn scalar_elem_read_snippet(scalar: ProtoScalar) -> String {
    let ty = scalar.rust_type();
    match scalar {
        ProtoScalar::Uint32 => {
            format!("::omnibuf::codec::read_elem_uint(b, p).map(|(v, np)| (v as {ty}, np))")
        }
        ProtoScalar::Uint64 => "::omnibuf::codec::read_elem_uint(b, p)".to_owned(),
        ProtoScalar::Sint32 | ProtoScalar::Enum => {
            format!("::omnibuf::codec::read_elem_sint(b, p).map(|(v, np)| (v as {ty}, np))")
        }
        ProtoScalar::Sint64 => "::omnibuf::codec::read_elem_sint(b, p)".to_owned(),
        ProtoScalar::Bool => "::omnibuf::codec::read_elem_bool(b, p)".to_owned(),
        ProtoScalar::Fixed32 => "::omnibuf::codec::read_elem_fixed32(b, p)".to_owned(),
        ProtoScalar::Fixed64 => "::omnibuf::codec::read_elem_fixed64(b, p)".to_owned(),
        ProtoScalar::Sfixed32 => "::omnibuf::codec::read_elem_sfixed32(b, p)".to_owned(),
        ProtoScalar::Sfixed64 => "::omnibuf::codec::read_elem_sfixed64(b, p)".to_owned(),
        ProtoScalar::Float32 => "::omnibuf::codec::read_elem_float32(b, p)".to_owned(),
        ProtoScalar::Float64 => "::omnibuf::codec::read_elem_float64(b, p)".to_owned(),
        ProtoScalar::String => "::omnibuf::codec::read_elem_string(b, p)".to_owned(),
        ProtoScalar::Bytes => "::omnibuf::codec::read_elem_bytes(b, p)".to_owned(),
    }
}

fn scalar_elem_read_arg(scalar: ProtoScalar) -> String {
    let ty = scalar.rust_type();
    match scalar {
        ProtoScalar::Uint32 => {
            format!("|b, p| ::omnibuf::codec::read_elem_uint(b, p).map(|(v, np)| (v as {ty}, np))")
        }
        ProtoScalar::Uint64 => "::omnibuf::codec::read_elem_uint".to_owned(),
        ProtoScalar::Sint32 | ProtoScalar::Enum => {
            format!("|b, p| ::omnibuf::codec::read_elem_sint(b, p).map(|(v, np)| (v as {ty}, np))")
        }
        ProtoScalar::Sint64 => "::omnibuf::codec::read_elem_sint".to_owned(),
        ProtoScalar::Bool => "::omnibuf::codec::read_elem_bool".to_owned(),
        ProtoScalar::Fixed32 => "::omnibuf::codec::read_elem_fixed32".to_owned(),
        ProtoScalar::Fixed64 => "::omnibuf::codec::read_elem_fixed64".to_owned(),
        ProtoScalar::Sfixed32 => "::omnibuf::codec::read_elem_sfixed32".to_owned(),
        ProtoScalar::Sfixed64 => "::omnibuf::codec::read_elem_sfixed64".to_owned(),
        ProtoScalar::Float32 => "::omnibuf::codec::read_elem_float32".to_owned(),
        ProtoScalar::Float64 => "::omnibuf::codec::read_elem_float64".to_owned(),
        ProtoScalar::String => "::omnibuf::codec::read_elem_string".to_owned(),
        ProtoScalar::Bytes => "::omnibuf::codec::read_elem_bytes".to_owned(),
    }
}

fn emit_encode_stmt(code: &mut String, gf: &GenField, prefix: &str, fallible: bool) {
    let fnum = gf.number;
    let access = format!("{prefix}{}", gf.rust_ident);
    let q = if fallible { "?" } else { ".unwrap()" };

    match &gf.kind {
        GenFieldKind::Scalar(s) => {
            emit_scalar_write_call(code, fnum, *s, &access);
        }
        GenFieldKind::OptScalar(s) => {
            let _ = writeln!(
                code,
                "        if let ::core::option::Option::Some(ref v) = {access} {{"
            );
            let expr = match s {
                ProtoScalar::String | ProtoScalar::Bytes => "v",
                _ => "*v",
            };
            emit_scalar_write_call(code, fnum, *s, expr);
            let _ = writeln!(code, "        }}");
        }
        GenFieldKind::SubMsg { boxed, .. } => {
            let inner = if *boxed { "&**sub" } else { "sub" };
            let _ = writeln!(
                code,
                "        if let ::core::option::Option::Some(ref sub) = {access} {{"
            );
            let _ = writeln!(
                code,
                "            ::omnibuf::codec::write_sub_msg_field(dst, {fnum}, {inner}, deterministic){q};"
            );
            let _ = writeln!(code, "        }}");
        }
        GenFieldKind::ScalarArr(s) => {
            let ewt = s.wire_type();
            match s {
                ProtoScalar::Uint32 => {
                    let _ = writeln!(
                        code,
                        "        ::omnibuf::codec::write_varint_vec_field(dst, {fnum}, {ewt}, &{access}, |item| u64::from(*item)){q};"
                    );
                }
                ProtoScalar::Uint64 => {
                    let _ = writeln!(
                        code,
                        "        ::omnibuf::codec::write_varint_vec_field(dst, {fnum}, {ewt}, &{access}, |item| *item){q};"
                    );
                }
                ProtoScalar::Sint32 | ProtoScalar::Enum => {
                    let _ = writeln!(
                        code,
                        "        ::omnibuf::codec::write_varint_vec_field(dst, {fnum}, {ewt}, &{access}, |item| ::omnibuf::wire::encode_zigzag(i64::from(*item))){q};"
                    );
                }
                ProtoScalar::Sint64 => {
                    let _ = writeln!(
                        code,
                        "        ::omnibuf::codec::write_varint_vec_field(dst, {fnum}, {ewt}, &{access}, |item| ::omnibuf::wire::encode_zigzag(*item)){q};"
                    );
                }
                _ => {
                    let ws = scalar_elem_write_snippet(*s, "item");
                    let _ = writeln!(
                        code,
                        "        ::omnibuf::codec::write_scalar_vec_field(dst, {fnum}, {ewt}, &{access}, |dst, item| {{ {ws} ::core::result::Result::Ok(()) }}){q};"
                    );
                }
            }
        }
        GenFieldKind::SubMsgArr { .. } => {
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_sub_msg_vec_field(dst, {fnum}, &{access}, deterministic){q};"
            );
        }
        GenFieldKind::Map { key, val } => {
            let kwt = key.wire_type();
            let wk = scalar_elem_write_snippet(*key, "k");
            let (vwt, wv) = match val {
                MapValKind::Scalar(vs) => (
                    vs.wire_type(),
                    format!(
                        "let _ = det; {} ::core::result::Result::Ok(())",
                        scalar_elem_write_snippet(*vs, "v")
                    ),
                ),
                MapValKind::SubMsg { .. } => (
                    WIRE_SUB_MSG,
                    "let p = dst.len(); if ::omnibuf::Message::min_wire_size(v) > 16_383 { dst.extend_from_slice(&[0, 0, 0, 0]); v.encode_omnibuf_append(dst, det)?; ::omnibuf::wire::backpatch_container_len_4b(dst, p); } else { dst.extend_from_slice(&[0, 0]); v.encode_omnibuf_append(dst, det)?; ::omnibuf::wire::backpatch_container_len(dst, p); } ::core::result::Result::Ok(())".to_owned(),
                ),
            };
            let _ = writeln!(
                code,
                "        ::omnibuf::codec::write_hash_map_field(dst, {fnum}, {kwt}, {vwt}, &{access}, deterministic, |dst, k| {{ {wk} ::core::result::Result::Ok(()) }}, |dst, v, det| {{ {wv} }}){q};"
            );
        }
    }
}

fn scalar_decode_expr(scalar: ProtoScalar) -> &'static str {
    match scalar {
        ProtoScalar::Uint32 => "dec.read_uint()? as u32",
        ProtoScalar::Uint64 => "dec.read_uint()?",
        ProtoScalar::Sint32 | ProtoScalar::Enum => "dec.read_sint()? as i32",
        ProtoScalar::Sint64 => "dec.read_sint()?",
        ProtoScalar::Fixed32 => "dec.read_fixed32()?",
        ProtoScalar::Fixed64 => "dec.read_fixed64()?",
        ProtoScalar::Sfixed32 => "dec.read_sfixed32()?",
        ProtoScalar::Sfixed64 => "dec.read_sfixed64()?",
        ProtoScalar::Float32 => "dec.read_float32()?",
        ProtoScalar::Float64 => "dec.read_float64()?",
        ProtoScalar::String => "dec.read_str()?.to_owned()",
        ProtoScalar::Bytes => "dec.read_bytes()?.to_vec()",
        ProtoScalar::Bool => "wt == ::omnibuf::wire::WIRE_BOOL_TRUE",
    }
}

fn emit_decode_arm(code: &mut String, gf: &GenField) {
    let fnum = gf.number;
    let fident = &gf.rust_ident;

    match &gf.kind {
        GenFieldKind::Scalar(ProtoScalar::Bool) => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == ::omnibuf::wire::WIRE_BOOL_FALSE || wt == ::omnibuf::wire::WIRE_BOOL_TRUE => {{ self.{fident} = wt == ::omnibuf::wire::WIRE_BOOL_TRUE; }}"
            );
        }
        GenFieldKind::OptScalar(ProtoScalar::Bool) => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == ::omnibuf::wire::WIRE_BOOL_FALSE || wt == ::omnibuf::wire::WIRE_BOOL_TRUE => {{ self.{fident} = ::core::option::Option::Some(wt == ::omnibuf::wire::WIRE_BOOL_TRUE); }}"
            );
        }
        GenFieldKind::Scalar(ProtoScalar::String) => {
            let wt = ProtoScalar::String.wire_type();
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ let s = dec.read_str()?; ::omnibuf::codec::assign_str(&mut self.{fident}, s); }}"
            );
        }
        GenFieldKind::Scalar(ProtoScalar::Bytes) => {
            let wt = ProtoScalar::Bytes.wire_type();
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ let b = dec.read_bytes()?; ::omnibuf::codec::assign_bytes(&mut self.{fident}, b); }}"
            );
        }
        GenFieldKind::Scalar(s) => {
            let wt = s.wire_type();
            let expr = scalar_decode_expr(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ self.{fident} = {expr}; }}"
            );
        }
        GenFieldKind::OptScalar(s) => {
            let wt = s.wire_type();
            let expr = scalar_decode_expr(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ self.{fident} = ::core::option::Option::Some({expr}); }}"
            );
        }
        GenFieldKind::SubMsg { boxed, .. } => {
            let fn_name = if *boxed {
                "read_opt_box_sub_msg_field"
            } else {
                "read_opt_sub_msg_field"
            };
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_SUB_MSG} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::{fn_name}(&mut self.{fident}, dec.data(), pos, depth, true)?; dec.set_position(next_pos); }}"
            );
        }
        GenFieldKind::ScalarArr(s) => {
            let ewt = s.wire_type();
            let rs_arg = scalar_elem_read_arg(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_ARRAY} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::read_scalar_vec_field(&mut self.{fident}, dec.data(), pos, depth, {ewt}, false, {rs_arg})?; dec.set_position(next_pos); }}"
            );
        }
        GenFieldKind::SubMsgArr { .. } => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_ARRAY} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::read_sub_msg_vec_field(&mut self.{fident}, dec.data(), pos, depth, false)?; dec.set_position(next_pos); }}"
            );
        }
        GenFieldKind::Map { key, val } => {
            let kwt = key.wire_type();
            let rk_arg = scalar_elem_read_arg(*key);
            let (vwt, rv) = match val {
                MapValKind::Scalar(vs) => (
                    vs.wire_type(),
                    format!("|b, p, _d| {}", scalar_elem_read_snippet(*vs)),
                ),
                MapValKind::SubMsg { rust_type, .. } => (
                    WIRE_SUB_MSG,
                    format!(
                        "|b, p, d| {{ let (sb, np) = ::omnibuf::wire::read_len_slice(b, p, 0)?; let mut sub = {rust_type}::default(); <{rust_type} as ::omnibuf::Message>::decode_omnibuf_at_depth(&mut sub, sb, d + 1, true)?; ::core::result::Result::Ok((sub, np)) }}"
                    ),
                ),
            };
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_MAP} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::read_hash_map_field(&mut self.{fident}, dec.data(), pos, depth, {kwt}, {vwt}, false, {rk_arg}, {rv})?; dec.set_position(next_pos); }}"
            );
        }
    }
}

fn clear_stmt_for_field(gf: &GenField) -> String {
    let fident = &gf.rust_ident;
    match &gf.kind {
        GenFieldKind::Scalar(ProtoScalar::String | ProtoScalar::Bytes) => {
            format!("self.{fident}.clear();")
        }
        GenFieldKind::ScalarArr(_) | GenFieldKind::SubMsgArr { .. } | GenFieldKind::Map { .. } => {
            format!("if !self.{fident}.is_empty() {{ self.{fident}.clear(); }}")
        }
        GenFieldKind::OptScalar(_) | GenFieldKind::SubMsg { .. } => {
            format!(
                "if self.{fident}.is_some() {{ self.{fident} = ::core::option::Option::None; }}"
            )
        }
        GenFieldKind::Scalar(_) => format!("self.{fident} = ::core::default::Default::default();"),
    }
}

fn tag_varint_width(fnum: u32, wt: u8) -> usize {
    let tag = (u64::from(fnum) << 4) | u64::from(wt & 0x0F);
    if tag <= 127 {
        1
    } else if tag <= 16_383 {
        2
    } else if tag <= 2_097_151 {
        3
    } else if tag <= 268_435_455 {
        4
    } else {
        5
    }
}

fn scalar_min_size_expr(fnum: u32, scalar: ProtoScalar, access: &str) -> String {
    let tw = tag_varint_width(fnum, scalar.wire_type());
    match scalar {
        ProtoScalar::Bool => format!("{tw}usize"),
        ProtoScalar::Fixed32 | ProtoScalar::Sfixed32 | ProtoScalar::Float32 => {
            format!("{}usize", tw + 4)
        }
        ProtoScalar::Fixed64 | ProtoScalar::Sfixed64 | ProtoScalar::Float64 => {
            format!("{}usize", tw + 8)
        }
        ProtoScalar::Uint32
        | ProtoScalar::Uint64
        | ProtoScalar::Sint32
        | ProtoScalar::Sint64
        | ProtoScalar::Enum => format!("{}usize", tw + 1),
        ProtoScalar::String | ProtoScalar::Bytes => {
            format!(
                "{{ let __l = ({access}).len(); {tw}usize + ::omnibuf::wire::varint_len(__l as u64) + __l }}"
            )
        }
    }
}

fn emit_min_wire_size_field(code: &mut String, gf: &GenField) {
    let fnum = gf.number;
    let fident = &gf.rust_ident;
    match &gf.kind {
        GenFieldKind::Scalar(s) => {
            let expr = scalar_min_size_expr(fnum, *s, &format!("self.{fident}"));
            let _ = writeln!(code, "        __sz += {expr};");
        }
        GenFieldKind::OptScalar(s) => {
            let expr = scalar_min_size_expr(fnum, *s, "__v");
            let _ = writeln!(
                code,
                "        if let ::core::option::Option::Some(ref __v) = self.{fident} {{ let _ = __v; __sz += {expr}; }}"
            );
        }
        GenFieldKind::SubMsg {
            rust_type, boxed, ..
        } => {
            let tw = tag_varint_width(fnum, WIRE_SUB_MSG);
            let sub_ref = if *boxed { "&**__s" } else { "__s" };
            let _ = writeln!(
                code,
                "        if let ::core::option::Option::Some(ref __s) = self.{fident} {{ let __sub = if depth_rem > 0 {{ <{rust_type} as ::omnibuf::Message>::min_wire_size_bounded({sub_ref}, depth_rem - 1) }} else {{ 0usize }}; __sz += {tw}usize + ::omnibuf::wire::container_len_width(__sub) + __sub; }}"
            );
        }
        GenFieldKind::ScalarArr(s) => {
            let tw = tag_varint_width(fnum, WIRE_ARRAY);
            let elems_expr = match s {
                ProtoScalar::String | ProtoScalar::Bytes => format!(
                    "self.{fident}.iter().map(|__x| {{ let __l = __x.len(); ::omnibuf::wire::varint_len(__l as u64) + __l }}).sum::<usize>()"
                ),
                ProtoScalar::Fixed32 | ProtoScalar::Sfixed32 | ProtoScalar::Float32 => {
                    "__c * 4usize".to_owned()
                }
                ProtoScalar::Fixed64 | ProtoScalar::Sfixed64 | ProtoScalar::Float64 => {
                    "__c * 8usize".to_owned()
                }
                _ => "__c".to_owned(),
            };
            let _ = writeln!(
                code,
                "        if !self.{fident}.is_empty() {{ let __c = self.{fident}.len(); let __b = 1usize + ::omnibuf::wire::varint_len(__c as u64) + ({elems_expr}); __sz += {tw}usize + ::omnibuf::wire::container_len_width(__b) + __b; }}"
            );
        }
        GenFieldKind::SubMsgArr { rust_type, .. } => {
            let tw = tag_varint_width(fnum, WIRE_ARRAY);
            let _ = writeln!(
                code,
                "        if !self.{fident}.is_empty() {{ let __c = self.{fident}.len(); let mut __elems = 0usize; if depth_rem > 0 {{ for __el in &self.{fident} {{ let __s = <{rust_type} as ::omnibuf::Message>::min_wire_size_bounded(__el, depth_rem - 1); __elems += ::omnibuf::wire::container_len_width(__s) + __s; }} }} else {{ __elems = __c; }} let __b = 1usize + ::omnibuf::wire::varint_len(__c as u64) + __elems; __sz += {tw}usize + ::omnibuf::wire::container_len_width(__b) + __b; }}"
            );
        }
        GenFieldKind::Map { key, val } => {
            let tw = tag_varint_width(fnum, WIRE_MAP);
            let key_expr = match key {
                ProtoScalar::String | ProtoScalar::Bytes => {
                    "{ let __l = __k.len(); ::omnibuf::wire::varint_len(__l as u64) + __l }"
                        .to_owned()
                }
                ProtoScalar::Fixed32 | ProtoScalar::Sfixed32 | ProtoScalar::Float32 => {
                    "4usize".to_owned()
                }
                ProtoScalar::Fixed64 | ProtoScalar::Sfixed64 | ProtoScalar::Float64 => {
                    "8usize".to_owned()
                }
                _ => "1usize".to_owned(),
            };
            let val_expr = match val {
                MapValKind::Scalar(ProtoScalar::String | ProtoScalar::Bytes) => {
                    "{ let __l = __v.len(); ::omnibuf::wire::varint_len(__l as u64) + __l }"
                        .to_owned()
                }
                MapValKind::Scalar(
                    ProtoScalar::Fixed32 | ProtoScalar::Sfixed32 | ProtoScalar::Float32,
                ) => "4usize".to_owned(),
                MapValKind::Scalar(
                    ProtoScalar::Fixed64 | ProtoScalar::Sfixed64 | ProtoScalar::Float64,
                ) => "8usize".to_owned(),
                MapValKind::Scalar(_) => "1usize".to_owned(),
                MapValKind::SubMsg { rust_type, .. } => format!(
                    "if depth_rem > 0 {{ let __s = <{rust_type} as ::omnibuf::Message>::min_wire_size_bounded(__v, depth_rem - 1); ::omnibuf::wire::container_len_width(__s) + __s }} else {{ 1usize }}"
                ),
            };
            let _ = writeln!(
                code,
                "        if !self.{fident}.is_empty() {{ let __c = self.{fident}.len(); let mut __entries = 0usize; for (__k, __v) in &self.{fident} {{ let _ = (__k, __v); __entries += ({key_expr}) + ({val_expr}); }} let __b = 2usize + ::omnibuf::wire::varint_len(__c as u64) + __entries; __sz += {tw}usize + ::omnibuf::wire::container_len_width(__b) + __b; }}"
            );
        }
    }
}

fn emit_min_wire_size_oneof(code: &mut String, go: &GenOneof) {
    let fident = &go.field_ident;
    let ename = &go.enum_name;
    let _ = writeln!(
        code,
        "        if let ::core::option::Option::Some(ref __ov) = self.{fident} {{ match __ov {{"
    );
    for arm in &go.arms {
        let fnum = arm.number;
        let vident = &arm.variant_ident;
        match &arm.kind {
            OneofArmKind::Scalar(s) => {
                let expr = scalar_min_size_expr(fnum, *s, "__v");
                let _ = writeln!(
                    code,
                    "            {ename}::{vident}(__v) => {{ let _ = __v; __sz += {expr}; }}"
                );
            }
            OneofArmKind::SubMsg {
                rust_type, boxed, ..
            } => {
                let tw = tag_varint_width(fnum, WIRE_SUB_MSG);
                let sub_ref = if *boxed { "&**__v" } else { "__v" };
                let _ = writeln!(
                    code,
                    "            {ename}::{vident}(__v) => {{ let __sub = if depth_rem > 0 {{ <{rust_type} as ::omnibuf::Message>::min_wire_size_bounded({sub_ref}, depth_rem - 1) }} else {{ 0usize }}; __sz += {tw}usize + ::omnibuf::wire::container_len_width(__sub) + __sub; }}"
                );
            }
        }
    }
    let _ = writeln!(code, "        }} }}");
}

fn borrowed_scalar_type(s: ProtoScalar) -> &'static str {
    match s {
        ProtoScalar::String => "&'a str",
        ProtoScalar::Bytes => "&'a [u8]",
        other => other.rust_type(),
    }
}

fn borrowed_field_type(kind: &GenFieldKind) -> String {
    match kind {
        GenFieldKind::Scalar(s) => borrowed_scalar_type(*s).to_owned(),
        GenFieldKind::OptScalar(s) => {
            format!("::core::option::Option<{}>", borrowed_scalar_type(*s))
        }
        GenFieldKind::SubMsg {
            borrowed_type,
            boxed,
            ..
        } => {
            if *boxed {
                format!("::core::option::Option<::std::boxed::Box<{borrowed_type}<'a>>>")
            } else {
                format!("::core::option::Option<{borrowed_type}<'a>>")
            }
        }
        GenFieldKind::ScalarArr(s) => format!("::std::vec::Vec<{}>", borrowed_scalar_type(*s)),
        GenFieldKind::SubMsgArr { borrowed_type, .. } => {
            format!("::std::vec::Vec<{borrowed_type}<'a>>")
        }
        GenFieldKind::Map { key, val } => {
            let kt = borrowed_scalar_type(*key);
            let vt = match val {
                MapValKind::Scalar(vs) => borrowed_scalar_type(*vs).to_owned(),
                MapValKind::SubMsg { borrowed_type, .. } => format!("{borrowed_type}<'a>"),
            };
            format!("::std::collections::HashMap<{kt}, {vt}>")
        }
    }
}

fn borrowed_scalar_decode_expr(scalar: ProtoScalar) -> &'static str {
    match scalar {
        ProtoScalar::String => "dec.read_str()?",
        ProtoScalar::Bytes => "dec.read_bytes()?",
        other => scalar_decode_expr(other),
    }
}

fn borrowed_scalar_elem_read_arg(scalar: ProtoScalar) -> String {
    match scalar {
        ProtoScalar::String => "::omnibuf::codec::read_elem_str_borrowed".to_owned(),
        ProtoScalar::Bytes => "::omnibuf::codec::read_elem_bytes_borrowed".to_owned(),
        other => scalar_elem_read_arg(other),
    }
}

fn borrowed_scalar_elem_read_snippet(scalar: ProtoScalar) -> String {
    match scalar {
        ProtoScalar::String => "::omnibuf::codec::read_elem_str_borrowed(b, p)".to_owned(),
        ProtoScalar::Bytes => "::omnibuf::codec::read_elem_bytes_borrowed(b, p)".to_owned(),
        other => scalar_elem_read_snippet(other),
    }
}

fn emit_borrowed_view(
    code: &mut String,
    rust_name: &str,
    fields: &[GenField],
    oneofs: &[GenOneof],
) {
    let borrowed_name = format!("{rust_name}Borrowed");
    let total_members = fields.len() + oneofs.len();

    for oneof in oneofs {
        if !oneof.needs_borrowed_lifetime() {
            continue;
        }
        let b_enum = format!("{}Borrowed", oneof.enum_name);
        let _ = writeln!(code, "#[allow(dead_code, clippy::enum_variant_names)]");
        let _ = writeln!(code, "#[derive(Clone, Debug, PartialEq)]");
        let _ = writeln!(code, "pub enum {b_enum}<'a> {{");
        for arm in &oneof.arms {
            let arm_ty = match &arm.kind {
                OneofArmKind::Scalar(s) => borrowed_scalar_type(*s).to_owned(),
                OneofArmKind::SubMsg {
                    borrowed_type,
                    boxed,
                    ..
                } => {
                    if *boxed {
                        format!("::std::boxed::Box<{borrowed_type}<'a>>")
                    } else {
                        format!("{borrowed_type}<'a>")
                    }
                }
            };
            let _ = writeln!(code, "    {}({arm_ty}),", arm.variant_ident);
        }
        let _ = writeln!(code, "}}\n");
    }

    let _ = writeln!(code, "#[allow(dead_code)]");
    let _ = writeln!(code, "#[derive(Clone, Debug, Default, PartialEq)]");
    let _ = writeln!(code, "pub struct {borrowed_name}<'a> {{");
    for gf in fields {
        let fty = borrowed_field_type(&gf.kind);
        let _ = writeln!(code, "    pub {}: {fty},", gf.rust_ident);
    }
    for oneof in oneofs {
        if oneof.needs_borrowed_lifetime() {
            let _ = writeln!(
                code,
                "    pub {}: ::core::option::Option<{}Borrowed<'a>>,",
                oneof.field_ident, oneof.enum_name
            );
        } else {
            let _ = writeln!(
                code,
                "    pub {}: ::core::option::Option<{}>,",
                oneof.field_ident, oneof.enum_name
            );
        }
    }
    let _ = writeln!(code, "    _marker: ::core::marker::PhantomData<&'a [u8]>,");
    let _ = writeln!(code, "}}\n");

    let _ = writeln!(code, "#[allow(dead_code)]");
    let _ = writeln!(code, "impl<'a> {borrowed_name}<'a> {{");
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn from_omnibuf(data: &'a [u8]) -> ::omnibuf::Result<Self> {{"
    );
    let _ = writeln!(
        code,
        "        <Self as ::omnibuf::DecodeBorrowed<'a>>::from_omnibuf_borrowed(data)"
    );
    let _ = writeln!(code, "    }}\n");
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn unmarshal_omnibuf(&mut self, data: &'a [u8]) -> ::omnibuf::Result<()> {{"
    );
    let _ = writeln!(
        code,
        "        <Self as ::omnibuf::DecodeBorrowed<'a>>::decode_omnibuf_borrowed(self, data)"
    );
    let _ = writeln!(code, "    }}");
    let _ = writeln!(code, "}}\n");

    let _ = writeln!(
        code,
        "impl<'a> ::omnibuf::DecodeBorrowed<'a> for {borrowed_name}<'a> {{"
    );
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    fn decode_omnibuf_borrowed_at_depth(&mut self, data: &'a [u8], depth: usize, merge: bool) -> ::omnibuf::Result<()> {{"
    );
    if total_members == 0 {
        let _ = writeln!(code, "        let _ = merge;");
        let _ = writeln!(
            code,
            "        let mut dec = ::omnibuf::Decoder::with_depth(data, depth)?;"
        );
        let _ = writeln!(
            code,
            "        while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {{"
        );
        let _ = writeln!(code, "            dec.skip_unknown(fnum, wt)?;");
        let _ = writeln!(code, "        }}");
        let _ = writeln!(code, "        ::core::result::Result::Ok(())");
    } else {
        let _ = writeln!(
            code,
            "        let mut dec = ::omnibuf::Decoder::with_depth(data, depth)?;"
        );
        let _ = writeln!(
            code,
            "        if !merge {{ self.clear_omnibuf_borrowed(); }}"
        );
        let _ = writeln!(
            code,
            "        while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {{"
        );
        let _ = writeln!(code, "            match fnum {{");
        for gf in fields {
            emit_borrowed_decode_arm(code, gf);
        }
        for go in oneofs {
            for arm in &go.arms {
                emit_borrowed_decode_oneof_arm(code, go, arm);
            }
        }
        let _ = writeln!(code, "                _ => dec.skip_unknown(fnum, wt)?,");
        let _ = writeln!(code, "            }}");
        let _ = writeln!(code, "        }}");
        let _ = writeln!(code, "        ::core::result::Result::Ok(())");
    }
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(code, "    fn clear_omnibuf_borrowed(&mut self) {{");
    for gf in fields {
        let fident = &gf.rust_ident;
        match &gf.kind {
            GenFieldKind::Scalar(ProtoScalar::String) => {
                let _ = writeln!(code, "        self.{fident} = \"\";");
            }
            GenFieldKind::Scalar(ProtoScalar::Bytes) => {
                let _ = writeln!(code, "        self.{fident} = &[];");
            }
            GenFieldKind::ScalarArr(_)
            | GenFieldKind::SubMsgArr { .. }
            | GenFieldKind::Map { .. } => {
                let _ = writeln!(
                    code,
                    "        if !self.{fident}.is_empty() {{ self.{fident}.clear(); }}"
                );
            }
            GenFieldKind::OptScalar(_) | GenFieldKind::SubMsg { .. } => {
                let _ = writeln!(
                    code,
                    "        if self.{fident}.is_some() {{ self.{fident} = ::core::option::Option::None; }}"
                );
            }
            GenFieldKind::Scalar(_) => {
                let _ = writeln!(
                    code,
                    "        self.{fident} = ::core::default::Default::default();"
                );
            }
        }
    }
    for go in oneofs {
        let fident = &go.field_ident;
        let _ = writeln!(
            code,
            "        if self.{fident}.is_some() {{ self.{fident} = ::core::option::Option::None; }}"
        );
    }
    let _ = writeln!(code, "    }}");
    let _ = writeln!(code, "}}\n");
}

fn emit_borrowed_decode_arm(code: &mut String, gf: &GenField) {
    let fnum = gf.number;
    let fident = &gf.rust_ident;

    match &gf.kind {
        GenFieldKind::Scalar(ProtoScalar::Bool) => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == ::omnibuf::wire::WIRE_BOOL_FALSE || wt == ::omnibuf::wire::WIRE_BOOL_TRUE => {{ self.{fident} = wt == ::omnibuf::wire::WIRE_BOOL_TRUE; }}"
            );
        }
        GenFieldKind::OptScalar(ProtoScalar::Bool) => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == ::omnibuf::wire::WIRE_BOOL_FALSE || wt == ::omnibuf::wire::WIRE_BOOL_TRUE => {{ self.{fident} = ::core::option::Option::Some(wt == ::omnibuf::wire::WIRE_BOOL_TRUE); }}"
            );
        }
        GenFieldKind::Scalar(s) => {
            let wt = s.wire_type();
            let expr = borrowed_scalar_decode_expr(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ self.{fident} = {expr}; }}"
            );
        }
        GenFieldKind::OptScalar(s) => {
            let wt = s.wire_type();
            let expr = borrowed_scalar_decode_expr(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ self.{fident} = ::core::option::Option::Some({expr}); }}"
            );
        }
        GenFieldKind::SubMsg { boxed, .. } => {
            let fn_name = if *boxed {
                "read_opt_box_sub_msg_borrowed_field"
            } else {
                "read_opt_sub_msg_borrowed_field"
            };
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_SUB_MSG} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::{fn_name}(&mut self.{fident}, dec.data(), pos, depth, true)?; dec.set_position(next_pos); }}"
            );
        }
        GenFieldKind::ScalarArr(s) => {
            let ewt = s.wire_type();
            let rs_arg = borrowed_scalar_elem_read_arg(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_ARRAY} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::read_scalar_vec_borrowed_field(&mut self.{fident}, dec.data(), pos, depth, {ewt}, false, {rs_arg})?; dec.set_position(next_pos); }}"
            );
        }
        GenFieldKind::SubMsgArr { .. } => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_ARRAY} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::read_sub_msg_borrowed_vec_field(&mut self.{fident}, dec.data(), pos, depth, false)?; dec.set_position(next_pos); }}"
            );
        }
        GenFieldKind::Map { key, val } => {
            let kwt = key.wire_type();
            let rk_arg = borrowed_scalar_elem_read_arg(*key);
            let (vwt, rv) = match val {
                MapValKind::Scalar(vs) => (
                    vs.wire_type(),
                    format!("|b, p, _d| {}", borrowed_scalar_elem_read_snippet(*vs)),
                ),
                MapValKind::SubMsg { borrowed_type, .. } => (
                    WIRE_SUB_MSG,
                    format!(
                        "|b, p, d| {{ let (sb, np) = ::omnibuf::wire::read_len_slice(b, p, 0)?; let mut sub = {borrowed_type}::default(); <{borrowed_type}<'a> as ::omnibuf::DecodeBorrowed<'a>>::decode_omnibuf_borrowed_at_depth(&mut sub, sb, d + 1, true)?; ::core::result::Result::Ok((sub, np)) }}"
                    ),
                ),
            };
            let _ = writeln!(
                code,
                "                {fnum} if wt == {WIRE_MAP} => {{ let pos = dec.position(); let next_pos = ::omnibuf::codec::read_hash_map_borrowed_field(&mut self.{fident}, dec.data(), pos, depth, {kwt}, {vwt}, false, {rk_arg}, {rv})?; dec.set_position(next_pos); }}"
            );
        }
    }
}

fn emit_borrowed_decode_oneof_arm(code: &mut String, go: &GenOneof, arm: &GenOneofArm) {
    let fnum = arm.number;
    let fident = &go.field_ident;
    let ename = if go.needs_borrowed_lifetime() {
        format!("{}Borrowed", go.enum_name)
    } else {
        go.enum_name.clone()
    };
    let vident = &arm.variant_ident;

    match &arm.kind {
        OneofArmKind::Scalar(ProtoScalar::Bool) => {
            let _ = writeln!(
                code,
                "                {fnum} if wt == ::omnibuf::wire::WIRE_BOOL_FALSE || wt == ::omnibuf::wire::WIRE_BOOL_TRUE => {{ self.{fident} = ::core::option::Option::Some({ename}::{vident}(wt == ::omnibuf::wire::WIRE_BOOL_TRUE)); }}"
            );
        }
        OneofArmKind::Scalar(s) => {
            let wt = s.wire_type();
            let expr = borrowed_scalar_decode_expr(*s);
            let _ = writeln!(
                code,
                "                {fnum} if wt == {wt} => {{ self.{fident} = ::core::option::Option::Some({ename}::{vident}({expr})); }}"
            );
        }
        OneofArmKind::SubMsg {
            borrowed_type,
            boxed,
            ..
        } => {
            let _ = writeln!(code, "                {fnum} if wt == {WIRE_SUB_MSG} => {{");
            let _ = writeln!(
                code,
                "                    let __sb = dec.read_container(0)?;"
            );
            let _ = writeln!(
                code,
                "                    if let ::core::option::Option::Some({ename}::{vident}(ref mut __sub)) = self.{fident} {{"
            );
            if *boxed {
                let _ = writeln!(
                    code,
                    "                        <{borrowed_type}<'a> as ::omnibuf::DecodeBorrowed<'a>>::decode_omnibuf_borrowed_at_depth(&mut **__sub, __sb, depth + 1, true)?;"
                );
            } else {
                let _ = writeln!(
                    code,
                    "                        <{borrowed_type}<'a> as ::omnibuf::DecodeBorrowed<'a>>::decode_omnibuf_borrowed_at_depth(__sub, __sb, depth + 1, true)?;"
                );
            }
            let _ = writeln!(code, "                    }} else {{");
            if *boxed {
                let _ = writeln!(
                    code,
                    "                        let mut __sub = ::std::boxed::Box::new({borrowed_type}::default());"
                );
                let _ = writeln!(
                    code,
                    "                        <{borrowed_type}<'a> as ::omnibuf::DecodeBorrowed<'a>>::decode_omnibuf_borrowed_at_depth(&mut *__sub, __sb, depth + 1, true)?;"
                );
            } else {
                let _ = writeln!(
                    code,
                    "                        let mut __sub = {borrowed_type}::default();"
                );
                let _ = writeln!(
                    code,
                    "                        <{borrowed_type}<'a> as ::omnibuf::DecodeBorrowed<'a>>::decode_omnibuf_borrowed_at_depth(&mut __sub, __sb, depth + 1, true)?;"
                );
            }
            let _ = writeln!(
                code,
                "                        self.{fident} = ::core::option::Option::Some({ename}::{vident}(__sub));"
            );
            let _ = writeln!(code, "                    }}");
            let _ = writeln!(code, "                }}");
        }
    }
}

fn emit_opaque_view(code: &mut String, rust_name: &str, fields: &[GenField]) {
    let opaque_name = format!("Opaque{rust_name}");
    let dirty_name = format!("Opaque{rust_name}Dirty");
    let has_fields = !fields.is_empty();
    let max_field = fields.iter().map(|f| f.number).max().unwrap_or(0);

    if has_fields {
        let _ = writeln!(code, "#[allow(dead_code)]");
        let _ = writeln!(code, "#[derive(Clone, Debug, Default)]");
        let _ = writeln!(code, "struct {dirty_name} {{");
        for gf in fields {
            let fty = rust_field_type(&gf.kind);
            let _ = writeln!(code, "    f_{}: {fty},", gf.method_stem);
        }
        let _ = writeln!(code, "}}\n");
    }

    let _ = writeln!(code, "#[allow(dead_code)]");
    let _ = writeln!(code, "#[derive(Clone, Debug, Default)]");
    let _ = writeln!(code, "pub struct {opaque_name}<'a> {{");
    let _ = writeln!(code, "    pub(crate) raw: ::std::borrow::Cow<'a, [u8]>,");
    let _ = writeln!(code, "    dirty: u64,");
    let _ = writeln!(code, "    dir: ::omnibuf::opaque::LazyFieldDir,");
    if has_fields {
        let _ = writeln!(
            code,
            "    dirty_state: ::core::option::Option<::std::boxed::Box<{dirty_name}>>,"
        );
    }
    let _ = writeln!(code, "}}\n");

    let _ = writeln!(code, "#[allow(dead_code, clippy::too_many_arguments)]");
    let _ = writeln!(code, "impl<'a> {opaque_name}<'a> {{");
    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(code, "    pub fn new(raw: &'a [u8]) -> Self {{");
    let _ = writeln!(code, "        Self {{");
    let _ = writeln!(code, "            raw: ::std::borrow::Cow::Borrowed(raw),");
    let _ = writeln!(code, "            ..Self::default()");
    let _ = writeln!(code, "        }}");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn try_new(raw: &'a [u8]) -> ::omnibuf::Result<Self> {{"
    );
    let _ = writeln!(code, "        ::omnibuf::wire::validate_message(raw, 0)?;");
    let _ = writeln!(code, "        ::core::result::Result::Ok(Self::new(raw))");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn from_owned(raw: ::std::vec::Vec<u8>) -> {opaque_name}<'static> {{"
    );
    let _ = writeln!(code, "        {opaque_name} {{");
    let _ = writeln!(code, "            raw: ::std::borrow::Cow::Owned(raw),");
    let _ = writeln!(code, "            ..{opaque_name}::default()");
    let _ = writeln!(code, "        }}");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn try_from_owned(raw: ::std::vec::Vec<u8>) -> ::omnibuf::Result<{opaque_name}<'static>> {{"
    );
    let _ = writeln!(code, "        ::omnibuf::wire::validate_message(&raw, 0)?;");
    let _ = writeln!(
        code,
        "        ::core::result::Result::Ok(Self::from_owned(raw))"
    );
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn validate(&self) -> ::omnibuf::Result<()> {{"
    );
    let _ = writeln!(
        code,
        "        ::omnibuf::wire::validate_message(&self.raw, 0)"
    );
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(code, "    pub fn unmarshal(&mut self, raw: &'a [u8]) {{");
    let _ = writeln!(
        code,
        "        self.raw = ::std::borrow::Cow::Borrowed(raw);"
    );
    let _ = writeln!(code, "        self.dirty = 0;");
    let _ = writeln!(code, "        self.dir.reset();");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn try_unmarshal(&mut self, raw: &'a [u8]) -> ::omnibuf::Result<()> {{"
    );
    let _ = writeln!(code, "        ::omnibuf::wire::validate_message(raw, 0)?;");
    let _ = writeln!(code, "        self.unmarshal(raw);");
    let _ = writeln!(code, "        ::core::result::Result::Ok(())");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(code, "    pub fn raw_bytes(&self) -> &[u8] {{");
    let _ = writeln!(code, "        &self.raw");
    let _ = writeln!(code, "    }}\n");

    if has_fields {
        let _ = writeln!(code, "    #[inline]");
        let _ = writeln!(code, "    fn dirty_mut(&mut self) -> &mut {dirty_name} {{");
        let _ = writeln!(
            code,
            "        self.dirty_state.get_or_insert_with(::core::default::Default::default)"
        );
        let _ = writeln!(code, "    }}\n");
    }

    for gf in fields {
        emit_opaque_field_methods(code, gf);
    }

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(code, "    pub fn marshal(&self) -> ::std::vec::Vec<u8> {{");
    let _ = writeln!(
        code,
        "        let mut dst = ::std::vec::Vec::with_capacity(self.raw.len() + 32);"
    );
    let _ = writeln!(code, "        self.marshal_append(&mut dst);");
    let _ = writeln!(code, "        dst");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(
        code,
        "    pub fn marshal_append(&self, dst: &mut ::std::vec::Vec<u8>) {{"
    );
    let _ = writeln!(code, "        if self.dirty == 0 {{");
    let _ = writeln!(
        code,
        "            ::omnibuf::opaque::append_packet(dst, &self.raw);"
    );
    let _ = writeln!(code, "            return;");
    let _ = writeln!(code, "        }}");
    let _ = writeln!(
        code,
        "        ::omnibuf::opaque::splice_fields(dst, &self.raw, self.dirty, {max_field}, |dst, fnum| {{"
    );
    let _ = writeln!(code, "            let deterministic = true;");
    let _ = writeln!(code, "            let _ = deterministic;");
    let _ = writeln!(code, "            match fnum {{");
    for gf in fields {
        let fnum = gf.number;
        let _ = writeln!(code, "                {fnum} => {{");
        emit_opaque_dirty_field(code, gf);
        let _ = writeln!(code, "                }}");
    }
    let _ = writeln!(code, "                _ => {{}}");
    let _ = writeln!(code, "            }}");
    let _ = writeln!(code, "        }});");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn try_marshal(&self) -> ::omnibuf::Result<::std::vec::Vec<u8>> {{"
    );
    let _ = writeln!(
        code,
        "        let mut dst = ::std::vec::Vec::with_capacity(self.raw.len() + 32);"
    );
    let _ = writeln!(code, "        self.try_marshal_append(&mut dst)?;");
    let _ = writeln!(code, "        ::core::result::Result::Ok(dst)");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(
        code,
        "    pub fn try_marshal_append(&self, dst: &mut ::std::vec::Vec<u8>) -> ::omnibuf::Result<()> {{"
    );
    let _ = writeln!(code, "        if self.dirty == 0 {{");
    let _ = writeln!(
        code,
        "            return ::omnibuf::opaque::try_append_packet(dst, &self.raw);"
    );
    let _ = writeln!(code, "        }}");
    let _ = writeln!(
        code,
        "        ::omnibuf::opaque::try_splice_fields(dst, &self.raw, self.dirty, {max_field}, |dst, fnum| {{"
    );
    let _ = writeln!(code, "            let deterministic = true;");
    let _ = writeln!(code, "            let _ = deterministic;");
    let _ = writeln!(code, "            match fnum {{");
    for gf in fields {
        let fnum = gf.number;
        let _ = writeln!(code, "                {fnum} => {{");
        emit_opaque_dirty_field(code, gf);
        let _ = writeln!(code, "                }}");
    }
    let _ = writeln!(code, "                _ => {{}}");
    let _ = writeln!(code, "            }}");
    let _ = writeln!(code, "        }})");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn marshal_validated(&self) -> ::omnibuf::Result<::std::vec::Vec<u8>> {{"
    );
    let _ = writeln!(code, "        self.try_marshal()");
    let _ = writeln!(code, "    }}\n");

    let _ = writeln!(code, "    #[inline]");
    let _ = writeln!(
        code,
        "    pub fn marshal_validated_append(&self, dst: &mut ::std::vec::Vec<u8>) -> ::omnibuf::Result<()> {{"
    );
    let _ = writeln!(code, "        self.try_marshal_append(dst)");
    let _ = writeln!(code, "    }}");
    let _ = writeln!(code, "}}\n");
}

fn emit_opaque_field_methods(code: &mut String, gf: &GenField) {
    let fnum = gf.number;
    let stem = &gf.method_stem;
    let bit = 1u64 << fnum;

    match &gf.kind {
        GenFieldKind::Scalar(ProtoScalar::String)
        | GenFieldKind::OptScalar(ProtoScalar::String) => {
            let is_opt = matches!(gf.kind, GenFieldKind::OptScalar(_));
            if is_opt {
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(code, "    pub fn has_{stem}(&self) -> bool {{");
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().is_some_and(|d| d.f_{stem}.is_some());"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        self.dir.locate_mask(&self.raw, {fnum}, 1u16 << {WIRE_STRING}).is_some()"
                );
                let _ = writeln!(code, "    }}");
            }
            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn get_{stem}(&self) -> &str {{");
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            if is_opt {
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}.as_deref()).unwrap_or(\"\");"
                );
            } else {
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().map_or(\"\", |d| d.f_{stem}.as_str());"
                );
            }
            let _ = writeln!(code, "        }}");
            let _ = writeln!(
                code,
                "        self.dir.read_str(&self.raw, {fnum}).unwrap_or(\"\")"
            );
            let _ = writeln!(code, "    }}");

            let _ = writeln!(code, "    #[inline]");
            if is_opt {
                let _ = writeln!(
                    code,
                    "    pub fn set_{stem}(&mut self, v: ::core::option::Option<::std::string::String>) {{"
                );
                let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v;");
            } else {
                let _ = writeln!(
                    code,
                    "    pub fn set_{stem}(&mut self, v: impl ::std::convert::Into<::std::string::String>) {{"
                );
                let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v.into();");
            }
            let _ = writeln!(code, "        self.dirty |= {bit}u64;");
            let _ = writeln!(code, "    }}\n");
        }
        GenFieldKind::Scalar(ProtoScalar::Bytes) | GenFieldKind::OptScalar(ProtoScalar::Bytes) => {
            let is_opt = matches!(gf.kind, GenFieldKind::OptScalar(_));
            if is_opt {
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(code, "    pub fn has_{stem}(&self) -> bool {{");
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().is_some_and(|d| d.f_{stem}.is_some());"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        self.dir.locate_mask(&self.raw, {fnum}, 1u16 << {WIRE_BYTES}).is_some()"
                );
                let _ = writeln!(code, "    }}");
            }
            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn get_{stem}(&self) -> &[u8] {{");
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            if is_opt {
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}.as_deref()).unwrap_or(&[]);"
                );
            } else {
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().map_or(&[], |d| d.f_{stem}.as_slice());"
                );
            }
            let _ = writeln!(code, "        }}");
            let _ = writeln!(
                code,
                "        self.dir.read_bytes(&self.raw, {fnum}).unwrap_or(&[])"
            );
            let _ = writeln!(code, "    }}");

            let _ = writeln!(code, "    #[inline]");
            if is_opt {
                let _ = writeln!(
                    code,
                    "    pub fn set_{stem}(&mut self, v: ::core::option::Option<::std::vec::Vec<u8>>) {{"
                );
                let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v;");
            } else {
                let _ = writeln!(
                    code,
                    "    pub fn set_{stem}(&mut self, v: impl ::std::convert::Into<::std::vec::Vec<u8>>) {{"
                );
                let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v.into();");
            }
            let _ = writeln!(code, "        self.dirty |= {bit}u64;");
            let _ = writeln!(code, "    }}\n");
        }
        GenFieldKind::Scalar(s) | GenFieldKind::OptScalar(s) => {
            let is_opt = matches!(gf.kind, GenFieldKind::OptScalar(_));
            let rty = s.rust_type();
            if is_opt {
                let mask_expr = if *s == ProtoScalar::Bool {
                    "(1u16 << ::omnibuf::wire::WIRE_BOOL_FALSE) | (1u16 << ::omnibuf::wire::WIRE_BOOL_TRUE)".to_owned()
                } else {
                    format!("1u16 << {}", s.wire_type())
                };
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(code, "    pub fn has_{stem}(&self) -> bool {{");
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().is_some_and(|d| d.f_{stem}.is_some());"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        self.dir.locate_mask(&self.raw, {fnum}, {mask_expr}).is_some()"
                );
                let _ = writeln!(code, "    }}");
            }
            let read_call = match s {
                ProtoScalar::Uint32 => {
                    format!("self.dir.read_uint(&self.raw, {fnum}).unwrap_or(0) as u32")
                }
                ProtoScalar::Uint64 => {
                    format!("self.dir.read_uint(&self.raw, {fnum}).unwrap_or(0)")
                }
                ProtoScalar::Sint32 | ProtoScalar::Enum => {
                    format!("self.dir.read_sint(&self.raw, {fnum}).unwrap_or(0) as i32")
                }
                ProtoScalar::Sint64 => {
                    format!("self.dir.read_sint(&self.raw, {fnum}).unwrap_or(0)")
                }
                ProtoScalar::Bool => {
                    format!("self.dir.read_bool(&self.raw, {fnum}).unwrap_or(false)")
                }
                ProtoScalar::Fixed32 => {
                    format!("self.dir.read_fixed32(&self.raw, {fnum}).unwrap_or(0)")
                }
                ProtoScalar::Fixed64 => {
                    format!("self.dir.read_fixed64(&self.raw, {fnum}).unwrap_or(0)")
                }
                ProtoScalar::Sfixed32 => {
                    format!("self.dir.read_sfixed32(&self.raw, {fnum}).unwrap_or(0)")
                }
                ProtoScalar::Sfixed64 => {
                    format!("self.dir.read_sfixed64(&self.raw, {fnum}).unwrap_or(0)")
                }
                ProtoScalar::Float32 => {
                    format!("self.dir.read_float32(&self.raw, {fnum}).unwrap_or(0.0)")
                }
                ProtoScalar::Float64 => {
                    format!("self.dir.read_float64(&self.raw, {fnum}).unwrap_or(0.0)")
                }
                ProtoScalar::String | ProtoScalar::Bytes => unreachable!(),
            };

            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn get_{stem}(&self) -> {rty} {{");
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            if is_opt {
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}).unwrap_or_default();"
                );
            } else {
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().map_or_else(::core::default::Default::default, |d| d.f_{stem});"
                );
            }
            let _ = writeln!(code, "        }}");
            let _ = writeln!(code, "        {read_call}");
            let _ = writeln!(code, "    }}");

            let _ = writeln!(code, "    #[inline]");
            if is_opt {
                let _ = writeln!(
                    code,
                    "    pub fn set_{stem}(&mut self, v: ::core::option::Option<{rty}>) {{"
                );
            } else {
                let _ = writeln!(code, "    pub fn set_{stem}(&mut self, v: {rty}) {{");
            }
            let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v;");
            let _ = writeln!(code, "        self.dirty |= {bit}u64;");
            let _ = writeln!(code, "    }}\n");
        }
        GenFieldKind::SubMsg {
            rust_type,
            opaque_type,
            boxed,
            ..
        } => {
            let set_ty = rust_field_type(&gf.kind);
            let deref_sub = if *boxed { "&**sub" } else { "sub" };

            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn has_{stem}(&self) -> bool {{");
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            let _ = writeln!(
                code,
                "            return self.dirty_state.as_deref().is_some_and(|d| d.f_{stem}.is_some());"
            );
            let _ = writeln!(code, "        }}");
            let _ = writeln!(code, "        self.dir.has_sub_msg(&self.raw, {fnum})");
            let _ = writeln!(code, "    }}");

            if let Some(sub_opaque) = opaque_type {
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(code, "    pub fn get_{stem}(&self) -> {sub_opaque}<'_> {{");
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            if let ::core::option::Option::Some(ref sub) = self.dirty_state.as_deref().unwrap().f_{stem} {{"
                );
                let _ = writeln!(
                    code,
                    "                return {sub_opaque}::from_owned(({deref_sub}).marshal_omnibuf());"
                );
                let _ = writeln!(code, "            }}");
                let _ = writeln!(code, "            return {sub_opaque}::new(&[]);");
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        match self.dir.read_sub_msg(&self.raw, {fnum}) {{"
                );
                let _ = writeln!(
                    code,
                    "            ::core::option::Option::Some(::std::borrow::Cow::Borrowed(slice)) => {sub_opaque}::new(slice),"
                );
                let _ = writeln!(
                    code,
                    "            ::core::option::Option::Some(::std::borrow::Cow::Owned(vec)) => {sub_opaque}::from_owned(vec),"
                );
                let _ = writeln!(
                    code,
                    "            ::core::option::Option::None => {sub_opaque}::new(&[]),"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(code, "    }}");
            } else {
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(
                    code,
                    "    pub fn get_{stem}(&self) -> ::core::option::Option<{rust_type}> {{"
                );
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                if *boxed {
                    let _ = writeln!(
                        code,
                        "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}.as_deref().cloned());"
                    );
                } else {
                    let _ = writeln!(
                        code,
                        "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}.clone());"
                    );
                }
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        let cow = self.dir.read_sub_msg(&self.raw, {fnum})?;"
                );
                let _ = writeln!(
                    code,
                    "        <{rust_type} as ::omnibuf::Message>::from_omnibuf(&cow).ok()"
                );
                let _ = writeln!(code, "    }}");
            }

            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn set_{stem}(&mut self, v: {set_ty}) {{");
            let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v;");
            let _ = writeln!(code, "        self.dirty |= {bit}u64;");
            let _ = writeln!(code, "    }}\n");
        }
        GenFieldKind::ScalarArr(s) => {
            let ewt = s.wire_type();
            let elem_ty = s.rust_type();
            let rs = scalar_elem_read_snippet(*s);

            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn {stem}_len(&self) -> usize {{");
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            let _ = writeln!(
                code,
                "            return self.dirty_state.as_deref().map_or(0, |d| d.f_{stem}.len());"
            );
            let _ = writeln!(code, "        }}");
            let _ = writeln!(
                code,
                "        ::omnibuf::wire::counted_arr_len(&self.raw, {fnum}, {ewt})"
            );
            let _ = writeln!(code, "    }}");

            let _ = writeln!(
                code,
                "    pub fn get_{stem}(&self) -> ::std::vec::Vec<{elem_ty}> {{"
            );
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            let _ = writeln!(
                code,
                "            return self.dirty_state.as_deref().map_or_else(::std::vec::Vec::new, |d| d.f_{stem}.clone());"
            );
            let _ = writeln!(code, "        }}");
            let _ = writeln!(code, "        let mut out = ::std::vec::Vec::new();");
            let _ = writeln!(code, "        let mut pos = 0usize;");
            let _ = writeln!(code, "        loop {{");
            let _ = writeln!(
                code,
                "            let (matched, valid) = ::omnibuf::wire::next_container_field(&self.raw, pos, {fnum}, {WIRE_ARRAY}, 2, false);"
            );
            let _ = writeln!(
                code,
                "            if !valid {{ return ::std::vec::Vec::new(); }}"
            );
            let _ = writeln!(
                code,
                "            let ::core::option::Option::Some((body, next_pos)) = matched else {{ return out; }};"
            );
            let _ = writeln!(
                code,
                "            let ::core::option::Option::Some((e, count, mut p)) = ::omnibuf::wire::parse_array_header(body) else {{ return ::std::vec::Vec::new(); }};"
            );
            let _ = writeln!(
                code,
                "            if e != {ewt} {{ return ::std::vec::Vec::new(); }}"
            );
            let _ = writeln!(code, "            out.reserve(count.min(4096));");
            let _ = writeln!(code, "            let b = body;");
            let _ = writeln!(code, "            for _ in 0..count {{");
            let _ = writeln!(
                code,
                "                let ::core::result::Result::Ok((val, np)) = {rs} else {{ return ::std::vec::Vec::new(); }};"
            );
            let _ = writeln!(code, "                out.push(val);");
            let _ = writeln!(code, "                p = np;");
            let _ = writeln!(code, "            }}");
            let _ = writeln!(
                code,
                "            if p != body.len() {{ return ::std::vec::Vec::new(); }}"
            );
            let _ = writeln!(code, "            pos = next_pos;");
            let _ = writeln!(code, "        }}");
            let _ = writeln!(code, "    }}");

            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(
                code,
                "    pub fn set_{stem}(&mut self, v: ::std::vec::Vec<{elem_ty}>) {{"
            );
            let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v;");
            let _ = writeln!(code, "        self.dirty |= {bit}u64;");
            let _ = writeln!(code, "    }}\n");
        }
        GenFieldKind::SubMsgArr {
            rust_type,
            opaque_type,
            ..
        } => {
            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn {stem}_len(&self) -> usize {{");
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            let _ = writeln!(
                code,
                "            return self.dirty_state.as_deref().map_or(0, |d| d.f_{stem}.len());"
            );
            let _ = writeln!(code, "        }}");
            let _ = writeln!(
                code,
                "        ::omnibuf::wire::sub_msg_arr_len(&self.raw, {fnum})"
            );
            let _ = writeln!(code, "    }}");

            if let Some(sub_opaque) = opaque_type {
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(
                    code,
                    "    pub fn iter_{stem}(&self) -> impl ::core::iter::ExactSizeIterator<Item = {sub_opaque}<'_>> + '_ {{"
                );
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            let slice = self.dirty_state.as_deref().map_or(&[][..], |d| d.f_{stem}.as_slice());"
                );
                let _ = writeln!(
                    code,
                    "            return ::omnibuf::opaque::OpaqueSubMsgIter::dirty(slice, |elem: &{rust_type}| {sub_opaque}::from_owned(elem.marshal_omnibuf()));"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        ::omnibuf::opaque::OpaqueSubMsgIter::clean(&self.raw, {fnum}, {sub_opaque}::new)"
                );
                let _ = writeln!(code, "    }}");

                let _ = writeln!(
                    code,
                    "    pub fn get_{stem}(&self, idx: usize) -> {sub_opaque}<'_> {{"
                );
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            if let ::core::option::Option::Some(elem) = self.dirty_state.as_deref().and_then(|d| d.f_{stem}.get(idx)) {{"
                );
                let _ = writeln!(
                    code,
                    "                return {sub_opaque}::from_owned(elem.marshal_omnibuf());"
                );
                let _ = writeln!(code, "            }}");
                let _ = writeln!(code, "            return {sub_opaque}::new(&[]);");
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        match ::omnibuf::wire::read_sub_msg_arr_elem(&self.raw, {fnum}, idx) {{"
                );
                let _ = writeln!(
                    code,
                    "            ::core::option::Option::Some(slice) => {sub_opaque}::new(slice),"
                );
                let _ = writeln!(
                    code,
                    "            ::core::option::Option::None => {sub_opaque}::new(&[]),"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(code, "    }}");
            } else {
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(
                    code,
                    "    pub fn iter_{stem}(&self) -> impl ::core::iter::ExactSizeIterator<Item = ::core::option::Option<{rust_type}>> + '_ {{"
                );
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            let slice = self.dirty_state.as_deref().map_or(&[][..], |d| d.f_{stem}.as_slice());"
                );
                let _ = writeln!(
                    code,
                    "            return ::omnibuf::opaque::OpaqueSubMsgIter::dirty(slice, |elem: &{rust_type}| ::core::option::Option::Some(elem.clone()));"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        ::omnibuf::opaque::OpaqueSubMsgIter::clean(&self.raw, {fnum}, |slice| <{rust_type} as ::omnibuf::Message>::from_omnibuf(slice).ok())"
                );
                let _ = writeln!(code, "    }}");

                let _ = writeln!(
                    code,
                    "    pub fn get_{stem}(&self, idx: usize) -> ::core::option::Option<{rust_type}> {{"
                );
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}.get(idx).cloned());"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        let slice = ::omnibuf::wire::read_sub_msg_arr_elem(&self.raw, {fnum}, idx)?;"
                );
                let _ = writeln!(
                    code,
                    "        <{rust_type} as ::omnibuf::Message>::from_omnibuf(slice).ok()"
                );
                let _ = writeln!(code, "    }}");
            }

            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(
                code,
                "    pub fn set_{stem}(&mut self, v: ::std::vec::Vec<{rust_type}>) {{"
            );
            let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v;");
            let _ = writeln!(code, "        self.dirty |= {bit}u64;");
            let _ = writeln!(code, "    }}\n");
        }
        GenFieldKind::Map { key, val } => {
            let map_ty = rust_field_type(&gf.kind);
            if *key == ProtoScalar::String
                && matches!(
                    val,
                    MapValKind::Scalar(ProtoScalar::Uint64 | ProtoScalar::Uint32)
                )
            {
                let vty = match val {
                    MapValKind::Scalar(vs) => vs.rust_type(),
                    _ => "u64",
                };
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(
                    code,
                    "    pub fn lookup_{stem}(&self, key: &str) -> ::core::option::Option<{vty}> {{"
                );
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}.get(key).copied());"
                );
                let _ = writeln!(code, "        }}");
                if matches!(val, MapValKind::Scalar(ProtoScalar::Uint64)) {
                    let _ = writeln!(
                        code,
                        "        ::omnibuf::wire::lookup_map_string_uint(&self.raw, {fnum}, key)"
                    );
                } else {
                    let _ = writeln!(
                        code,
                        "        ::omnibuf::wire::lookup_map_string_uint(&self.raw, {fnum}, key).map(|v| v as {vty})"
                    );
                }
                let _ = writeln!(code, "    }}");
            } else if *key == ProtoScalar::String
                && matches!(val, MapValKind::Scalar(ProtoScalar::String))
            {
                let _ = writeln!(code, "    #[inline]");
                let _ = writeln!(
                    code,
                    "    pub fn lookup_{stem}(&self, key: &str) -> ::core::option::Option<&str> {{"
                );
                let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
                let _ = writeln!(
                    code,
                    "            return self.dirty_state.as_deref().and_then(|d| d.f_{stem}.get(key).map(::std::string::String::as_str));"
                );
                let _ = writeln!(code, "        }}");
                let _ = writeln!(
                    code,
                    "        ::omnibuf::wire::lookup_map_string_str(&self.raw, {fnum}, key)"
                );
                let _ = writeln!(code, "    }}");
            }

            let _ = writeln!(code, "    pub fn get_{stem}(&self) -> {map_ty} {{");
            let _ = writeln!(code, "        if (self.dirty & {bit}u64) != 0 {{");
            let _ = writeln!(
                code,
                "            return self.dirty_state.as_deref().map_or_else(::core::default::Default::default, |d| d.f_{stem}.clone());"
            );
            let _ = writeln!(code, "        }}");
            if *key == ProtoScalar::String && matches!(val, MapValKind::Scalar(ProtoScalar::Uint64))
            {
                let _ = writeln!(
                    code,
                    "        ::omnibuf::wire::read_map_string_uint(&self.raw, {fnum}).unwrap_or_default()"
                );
            } else {
                let kwt = key.wire_type();
                let rk = scalar_elem_read_snippet(*key);
                let (vwt, rv) = match val {
                    MapValKind::Scalar(vs) => (vs.wire_type(), scalar_elem_read_snippet(*vs)),
                    MapValKind::SubMsg { rust_type, .. } => (
                        WIRE_SUB_MSG,
                        format!(
                            "::omnibuf::wire::read_len_slice(b, p, 0).and_then(|(sb, np)| <{rust_type} as ::omnibuf::Message>::from_omnibuf(sb).map(|sub| (sub, np)))"
                        ),
                    ),
                };
                let _ = writeln!(
                    code,
                    "        let mut out = ::std::collections::HashMap::new();"
                );
                let _ = writeln!(code, "        let mut pos = 0usize;");
                let _ = writeln!(code, "        loop {{");
                let _ = writeln!(
                    code,
                    "            let (matched, valid) = ::omnibuf::wire::next_container_field(&self.raw, pos, {fnum}, {WIRE_MAP}, 3, false);"
                );
                let _ = writeln!(
                    code,
                    "            if !valid {{ return ::std::collections::HashMap::new(); }}"
                );
                let _ = writeln!(
                    code,
                    "            let ::core::option::Option::Some((body, next_pos)) = matched else {{ return out; }};"
                );
                let _ = writeln!(
                    code,
                    "            let ::core::option::Option::Some((kw, vw, count, mut p)) = ::omnibuf::wire::parse_map_header(body) else {{ return ::std::collections::HashMap::new(); }};"
                );
                let _ = writeln!(
                    code,
                    "            if kw != {kwt} || vw != {vwt} {{ return ::std::collections::HashMap::new(); }}"
                );
                let _ = writeln!(code, "            out.reserve(count.min(4096));");
                let _ = writeln!(code, "            let b = body;");
                let _ = writeln!(code, "            for _ in 0..count {{");
                let _ = writeln!(
                    code,
                    "                let ::core::result::Result::Ok((k, np)) = {rk} else {{ return ::std::collections::HashMap::new(); }};"
                );
                let _ = writeln!(code, "                p = np;");
                let _ = writeln!(
                    code,
                    "                let ::core::result::Result::Ok((v, np)) = {rv} else {{ return ::std::collections::HashMap::new(); }};"
                );
                let _ = writeln!(code, "                p = np;");
                let _ = writeln!(code, "                out.insert(k, v);");
                let _ = writeln!(code, "            }}");
                let _ = writeln!(
                    code,
                    "            if p != body.len() {{ return ::std::collections::HashMap::new(); }}"
                );
                let _ = writeln!(code, "            pos = next_pos;");
                let _ = writeln!(code, "        }}");
            }
            let _ = writeln!(code, "    }}");

            let _ = writeln!(code, "    #[inline]");
            let _ = writeln!(code, "    pub fn set_{stem}(&mut self, v: {map_ty}) {{");
            let _ = writeln!(code, "        self.dirty_mut().f_{stem} = v;");
            let _ = writeln!(code, "        self.dirty |= {bit}u64;");
            let _ = writeln!(code, "    }}\n");
        }
    }
}

fn emit_opaque_dirty_field(code: &mut String, gf: &GenField) {
    let temp = GenField {
        number: gf.number,
        proto_name: gf.proto_name.clone(),
        rust_ident: format!("f_{}", gf.method_stem),
        method_stem: gf.method_stem.clone(),
        kind: gf.kind.clone(),
    };
    emit_encode_stmt(code, &temp, "self.dirty_state.as_deref().unwrap().", false);
}

fn sanitize_pascal_ident(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        }
    }
    if out.is_empty() {
        return "Unnamed".to_owned();
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, 'T');
    }
    match out.as_str() {
        "Self" => "Self_".to_owned(),
        _ => out,
    }
}

fn sanitize_enum_variant(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        }
    }
    if out.is_empty() {
        return "Unspecified".to_owned();
    }
    if out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, 'V');
    }
    match out.as_str() {
        "Self" => "Self_".to_owned(),
        _ => escape_rust_ident(&out),
    }
}

fn to_pascal_case(s: &str) -> String {
    let all_shouty = s.chars().all(|c| !c.is_lowercase());
    let mut out = String::with_capacity(s.len());
    let mut upper_next = true;
    for ch in s.chars() {
        if ch == '_' || ch == '-' || ch == '.' {
            upper_next = true;
        } else if upper_next {
            for up in ch.to_uppercase() {
                out.push(up);
            }
            upper_next = false;
        } else if all_shouty {
            for lo in ch.to_lowercase() {
                out.push(lo);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn to_snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    let chars: Vec<char> = s.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        if ch == '-' || ch == '.' {
            out.push('_');
            continue;
        }
        if ch.is_uppercase() {
            let prev_lower = i > 0 && chars[i - 1].is_lowercase();
            let next_lower =
                i + 1 < chars.len() && chars[i + 1].is_lowercase() && i > 0 && chars[i - 1] != '_';
            if prev_lower || next_lower {
                out.push('_');
            }
            for lo in ch.to_lowercase() {
                out.push(lo);
            }
        } else {
            out.push(ch);
        }
    }
    out
}

fn escape_rust_ident(s: &str) -> String {
    match s {
        "self" | "super" | "crate" | "Self" => format!("{s}_"),
        "as" | "break" | "const" | "continue" | "else" | "enum" | "extern" | "false" | "fn"
        | "for" | "if" | "impl" | "in" | "let" | "loop" | "match" | "mod" | "move" | "mut"
        | "pub" | "ref" | "return" | "static" | "struct" | "trait" | "true" | "type" | "unsafe"
        | "use" | "where" | "while" | "async" | "await" | "dyn" | "abstract" | "become" | "box"
        | "do" | "final" | "gen" | "macro" | "override" | "priv" | "typeof" | "unsized"
        | "virtual" | "yield" | "try" => format!("r#{s}"),
        "" => "_field".to_owned(),
        other if other.as_bytes()[0].is_ascii_digit() => format!("_{other}"),
        _ => s.to_owned(),
    }
}
