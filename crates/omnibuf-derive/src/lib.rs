use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{
    Attribute, Data, DeriveInput, Error, Expr, ExprLit, Field, GenericArgument, Ident, Lit, Meta,
    PathArguments, Result, Token, Type, parse_macro_input,
};

const MAX_FIELD_NUMBER: u32 = 536_870_911;
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

/// Derives `omnibuf::Message` for a Rust struct with named fields.
///
/// Supports both native `#[omnibuf(...)]` attributes and `prost`-generated `#[prost(...)]` attributes.
#[proc_macro_derive(OmniBuf, attributes(omnibuf))]
pub fn derive_omnibuf(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_derive_omnibuf(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

struct StructConfig {
    type_name: String,
    crate_path: syn::Path,
}

#[derive(Default)]
struct FieldAttr {
    id: Option<u32>,
    name: Option<String>,
    wire: Option<String>,
    key_wire: Option<String>,
    val_wire: Option<String>,
    omit_empty: bool,
    skip: bool,
    prost_enum: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScalarType {
    U8,
    U16,
    U32,
    U64,
    Usize,
    I8,
    I16,
    I32,
    I64,
    Isize,
    F32,
    F64,
    Bool,
    String,
    Bytes,
}

enum FieldShape {
    Scalar {
        scalar: ScalarType,
        wire_wt: u8,
    },
    OptScalar {
        scalar: ScalarType,
        wire_wt: u8,
    },
    SubMsg {
        ty: Box<Type>,
        boxed: bool,
    },
    OptSubMsg {
        ty: Box<Type>,
        boxed: bool,
    },
    ScalarVec {
        scalar: ScalarType,
        elem_wt: u8,
    },
    SubMsgVec {
        ty: Box<Type>,
        boxed: bool,
    },
    Map {
        is_btree: bool,
        key_scalar: ScalarType,
        key_wt: u8,
        val: MapValShape,
    },
}

enum MapValShape {
    Scalar { scalar: ScalarType, wire_wt: u8 },
    SubMsg { ty: Box<Type>, boxed: bool },
}

struct CompiledField {
    ident: Ident,
    id: u32,
    schema_name: String,
    omit_empty: bool,
    shape: FieldShape,
}

fn expand_derive_omnibuf(input: &DeriveInput) -> Result<TokenStream2> {
    let cfg = parse_struct_attrs(&input.attrs, &input.ident)?;
    let krate = &cfg.crate_path;

    let Data::Struct(data_struct) = &input.data else {
        return Err(Error::new_spanned(
            &input.ident,
            "#[derive(OmniBuf)] is only supported on structs with named fields",
        ));
    };

    let fields = match &data_struct.fields {
        syn::Fields::Named(named) => &named.named,
        syn::Fields::Unit => {
            return expand_empty_struct(input, &cfg);
        }
        syn::Fields::Unnamed(_) => {
            return Err(Error::new_spanned(
                &input.ident,
                "#[derive(OmniBuf)] requires named struct fields",
            ));
        }
    };

    let mut compiled = Vec::with_capacity(fields.len());
    let mut used_ids = HashSet::new();

    for field in fields {
        let Some(cf) = compile_field(field, &mut used_ids)? else {
            continue;
        };
        compiled.push(cf);
    }

    // Sort fields by ascending field ID for canonical wire emission order.
    compiled.sort_by_key(|f| f.id);

    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let num_fields = compiled.len();
    let type_name_lit = &cfg.type_name;

    let mut encode_stmts = Vec::with_capacity(num_fields);
    let mut decode_arms = Vec::with_capacity(num_fields + 2);
    let mut clear_unseen_stmts = Vec::with_capacity(num_fields);
    let mut clear_all_stmts = Vec::with_capacity(num_fields);
    let mut is_empty_checks = Vec::with_capacity(num_fields);
    let mut schema_stmts = Vec::with_capacity(num_fields);

    for (idx, cf) in compiled.iter().enumerate() {
        let f_ident = &cf.ident;
        let f_id = cf.id;
        let f_name = &cf.schema_name;

        encode_stmts.push(gen_encode_field(krate, cf));
        decode_arms.push(gen_decode_arm(krate, cf, idx));
        clear_unseen_stmts.push(gen_clear_field(krate, cf, Some(idx)));
        clear_all_stmts.push(gen_clear_field(krate, cf, None));
        is_empty_checks.push(quote! {
            if !#krate::codec::IsEmpty::is_omnibuf_empty(&self.#f_ident) {
                return false;
            }
        });
        schema_stmts.push(gen_schema_field(krate, cf, f_id, f_name));
    }

    Ok(quote! {
        impl #impl_generics #krate::codec::IsEmpty for #ident #ty_generics #where_clause {
            #[inline]
            fn is_omnibuf_empty(&self) -> bool {
                #(#is_empty_checks)*
                true
            }
        }

        impl #impl_generics #krate::Message for #ident #ty_generics #where_clause {
            fn encode_omnibuf_append(
                &self,
                dst: &mut ::std::vec::Vec<u8>,
                deterministic: bool,
            ) -> #krate::Result<()> {
                let _ = deterministic;
                #(#encode_stmts)*
                ::core::result::Result::Ok(())
            }

            fn decode_omnibuf_at_depth(
                &mut self,
                data: &[u8],
                depth: usize,
                merge: bool,
            ) -> #krate::Result<()> {
                let mut dec = #krate::Decoder::with_depth(data, depth)?;
                let mut seen = [false; #num_fields];
                while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {
                    match fnum {
                        #(#decode_arms)*
                        _ => dec.skip_unknown(fnum, wt)?,
                    }
                }
                if !merge {
                    #(#clear_unseen_stmts)*
                }
                ::core::result::Result::Ok(())
            }

            fn clear_omnibuf(&mut self) {
                #(#clear_all_stmts)*
            }

            fn build_schema_meta(
                active: &mut ::std::collections::HashSet<&'static str>,
                depth: usize,
            ) -> ::core::option::Option<#krate::SchemaMeta> {
                let type_key = ::core::any::type_name::<Self>();
                if depth > #krate::MAX_NESTING_DEPTH || active.contains(type_key) {
                    return ::core::option::Option::None;
                }
                active.insert(type_key);
                let mut meta = #krate::SchemaMeta {
                    type_name: ::std::string::String::from(#type_name_lit),
                    fields: ::std::collections::BTreeMap::new(),
                    children: ::std::collections::BTreeMap::new(),
                };
                #(#schema_stmts)*
                active.remove(type_key);
                ::core::option::Option::Some(meta)
            }
        }
    })
}

fn expand_empty_struct(input: &DeriveInput, cfg: &StructConfig) -> Result<TokenStream2> {
    let krate = &cfg.crate_path;
    let ident = &input.ident;
    let type_name_lit = &cfg.type_name;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    Ok(quote! {
        impl #impl_generics #krate::codec::IsEmpty for #ident #ty_generics #where_clause {
            #[inline]
            fn is_omnibuf_empty(&self) -> bool {
                true
            }
        }

        impl #impl_generics #krate::Message for #ident #ty_generics #where_clause {
            fn encode_omnibuf_append(
                &self,
                _dst: &mut ::std::vec::Vec<u8>,
                _deterministic: bool,
            ) -> #krate::Result<()> {
                ::core::result::Result::Ok(())
            }

            fn decode_omnibuf_at_depth(
                &mut self,
                data: &[u8],
                depth: usize,
                _merge: bool,
            ) -> #krate::Result<()> {
                let mut dec = #krate::Decoder::with_depth(data, depth)?;
                while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {
                    dec.skip_unknown(fnum, wt)?;
                }
                ::core::result::Result::Ok(())
            }

            fn clear_omnibuf(&mut self) {}

            fn build_schema_meta(
                active: &mut ::std::collections::HashSet<&'static str>,
                depth: usize,
            ) -> ::core::option::Option<#krate::SchemaMeta> {
                let type_key = ::core::any::type_name::<Self>();
                if depth > #krate::MAX_NESTING_DEPTH || active.contains(type_key) {
                    return ::core::option::Option::None;
                }
                ::core::option::Option::Some(#krate::SchemaMeta {
                    type_name: ::std::string::String::from(#type_name_lit),
                    fields: ::std::collections::BTreeMap::new(),
                    children: ::std::collections::BTreeMap::new(),
                })
            }
        }
    })
}

fn parse_struct_attrs(attrs: &[Attribute], ident: &Ident) -> Result<StructConfig> {
    let mut type_name = ident.to_string();
    if let Some(stripped) = type_name.strip_prefix("r#") {
        type_name = stripped.to_owned();
    }
    let mut crate_path: syn::Path = syn::parse_quote!(::omnibuf);

    for attr in attrs {
        if !attr.path().is_ident("omnibuf") {
            continue;
        }
        let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
        for meta in nested {
            match meta {
                Meta::NameValue(nv) if nv.path.is_ident("name") => {
                    type_name = lit_str_from_expr(&nv.value)?;
                }
                Meta::NameValue(nv) if nv.path.is_ident("crate") => {
                    let s = lit_str_from_expr(&nv.value)?;
                    crate_path = syn::parse_str(&s).map_err(|e| {
                        Error::new_spanned(&nv.value, format!("invalid crate path: {e}"))
                    })?;
                }
                other => {
                    return Err(Error::new_spanned(
                        other,
                        "unsupported struct-level #[omnibuf(...)] attribute (expected `name = \"...\"` or `crate = \"...\"`)",
                    ));
                }
            }
        }
    }

    Ok(StructConfig {
        type_name,
        crate_path,
    })
}

fn lit_str_from_expr(expr: &Expr) -> Result<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    }) = expr
    {
        Ok(s.value())
    } else {
        Err(Error::new_spanned(expr, "expected string literal"))
    }
}

fn lit_u32_from_expr(expr: &Expr) -> Result<u32> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(int_lit),
            ..
        }) => int_lit.base10_parse::<u32>(),
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => s
            .value()
            .parse::<u32>()
            .map_err(|e| Error::new_spanned(s, format!("invalid field number: {e}"))),
        _ => Err(Error::new_spanned(expr, "expected integer literal")),
    }
}

fn parse_field_attrs(field: &Field) -> Result<FieldAttr> {
    let mut out = FieldAttr::default();
    let mut has_omnibuf = false;

    for attr in &field.attrs {
        if attr.path().is_ident("omnibuf") {
            has_omnibuf = true;
            let tokens: Punctuated<Expr, Token![,]> =
                attr.parse_args_with(Punctuated::parse_terminated)?;
            for expr in tokens {
                match expr {
                    Expr::Lit(ExprLit {
                        lit: Lit::Int(int_lit),
                        ..
                    }) => {
                        out.id = Some(int_lit.base10_parse::<u32>()?);
                    }
                    Expr::Assign(assign) => {
                        let Expr::Path(ref left) = *assign.left else {
                            return Err(Error::new_spanned(assign, "invalid attribute key"));
                        };
                        if left.path.is_ident("id") || left.path.is_ident("tag") {
                            out.id = Some(lit_u32_from_expr(&assign.right)?);
                        } else if left.path.is_ident("name") {
                            out.name = Some(lit_str_from_expr(&assign.right)?);
                        } else if left.path.is_ident("wire") {
                            out.wire = Some(lit_str_from_expr(&assign.right)?);
                        } else if left.path.is_ident("key_wire") {
                            out.key_wire = Some(lit_str_from_expr(&assign.right)?);
                        } else if left.path.is_ident("val_wire") {
                            out.val_wire = Some(lit_str_from_expr(&assign.right)?);
                        } else {
                            return Err(Error::new_spanned(left, "unknown #[omnibuf(...)] option"));
                        }
                    }
                    Expr::Path(p)
                        if p.path.is_ident("omitempty") || p.path.is_ident("omit_empty") =>
                    {
                        out.omit_empty = true;
                    }
                    Expr::Path(p) if p.path.is_ident("skip") => {
                        out.skip = true;
                    }
                    other => {
                        return Err(Error::new_spanned(
                            other,
                            "unsupported #[omnibuf(...)] argument",
                        ));
                    }
                }
            }
        }
    }

    if !has_omnibuf {
        for attr in &field.attrs {
            if attr.path().is_ident("prost") {
                parse_prost_attr(attr, &mut out)?;
            }
        }
    }

    Ok(out)
}

fn parse_prost_attr(attr: &Attribute, out: &mut FieldAttr) -> Result<()> {
    let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
    for meta in nested {
        match meta {
            Meta::NameValue(nv) if nv.path.is_ident("tag") => {
                out.id = Some(lit_u32_from_expr(&nv.value)?);
            }
            Meta::NameValue(nv) if nv.path.is_ident("enumeration") => {
                out.wire = Some("sint".to_owned());
                out.prost_enum = true;
            }
            Meta::NameValue(nv) if nv.path.is_ident("bytes") => {
                out.wire = Some("bytes".to_owned());
            }
            Meta::NameValue(nv)
                if nv.path.is_ident("map")
                    || nv.path.is_ident("btree_map")
                    || nv.path.is_ident("hash_map") =>
            {
                let spec = lit_str_from_expr(&nv.value)?;
                if let Some((k_raw, v_raw)) = spec.split_once(',') {
                    if let Some(kw) = prost_token_to_wire(k_raw.trim()) {
                        out.key_wire = Some(kw.to_owned());
                    }
                    let vt = v_raw.trim();
                    if let Some(vw) = prost_token_to_wire(vt) {
                        out.val_wire = Some(vw.to_owned());
                    }
                }
            }
            Meta::Path(p) => {
                if let Some(ident) = p.get_ident()
                    && let Some(w) = prost_token_to_wire(&ident.to_string())
                {
                    out.wire = Some(w.to_owned());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn prost_token_to_wire(tok: &str) -> Option<&'static str> {
    match tok {
        "uint32" | "uint64" => Some("uint"),
        "int32" | "int64" | "sint32" | "sint64" | "enumeration" => Some("sint"),
        "bool" => Some("bool"),
        "fixed32" => Some("fixed32"),
        "fixed64" => Some("fixed64"),
        "sfixed32" => Some("sfixed32"),
        "sfixed64" => Some("sfixed64"),
        "float" => Some("float32"),
        "double" => Some("float64"),
        "string" => Some("string"),
        "bytes" => Some("bytes"),
        "message" => Some("submsg"),
        _ => None,
    }
}

fn compile_field(field: &Field, used_ids: &mut HashSet<u32>) -> Result<Option<CompiledField>> {
    let ident = field
        .ident
        .clone()
        .ok_or_else(|| Error::new_spanned(field, "expected named field"))?;
    let attr = parse_field_attrs(field)?;
    if attr.skip {
        return Ok(None);
    }

    let id = attr.id.ok_or_else(|| {
        Error::new_spanned(
            field,
            "missing OmniBuf field number; add `#[omnibuf(id = N)]` or `#[omnibuf(skip)]`",
        )
    })?;

    if id == 0 {
        return Err(Error::new_spanned(
            field,
            "field number 0 is reserved for inline SchemaMeta (Field #0)",
        ));
    }
    if id > MAX_FIELD_NUMBER {
        return Err(Error::new_spanned(
            field,
            format!("field number {id} exceeds MAX_FIELD_NUMBER ({MAX_FIELD_NUMBER})"),
        ));
    }
    if (19_000..=19_999).contains(&id) {
        return Err(Error::new_spanned(
            field,
            format!("field number {id} falls in Protobuf reserved range 19000..=19999"),
        ));
    }
    if !used_ids.insert(id) {
        return Err(Error::new_spanned(
            field,
            format!("duplicate OmniBuf field number {id}"),
        ));
    }

    let schema_name = match attr.name {
        Some(n) => n,
        None => {
            let raw = ident.to_string();
            raw.strip_prefix("r#").unwrap_or(&raw).to_owned()
        }
    };

    let shape = classify_field_type(
        &field.ty,
        attr.wire.as_deref(),
        attr.key_wire.as_deref(),
        attr.val_wire.as_deref(),
        Span::call_site(),
    )?;

    Ok(Some(CompiledField {
        ident,
        id,
        schema_name,
        omit_empty: attr.omit_empty,
        shape,
    }))
}

fn last_type_segment(ty: &Type) -> Option<(&Ident, &PathArguments)> {
    if let Type::Path(tp) = ty
        && tp.qself.is_none()
        && let Some(seg) = tp.path.segments.last()
    {
        return Some((&seg.ident, &seg.arguments));
    }
    None
}

fn single_generic_type(args: &PathArguments) -> Option<&Type> {
    if let PathArguments::AngleBracketed(ab) = args
        && ab.args.len() == 1
        && let Some(GenericArgument::Type(inner)) = ab.args.first()
    {
        return Some(inner);
    }
    None
}

fn double_generic_types(args: &PathArguments) -> Option<(&Type, &Type)> {
    if let PathArguments::AngleBracketed(ab) = args
        && ab.args.len() >= 2
    {
        let mut iter = ab.args.iter();
        if let (Some(GenericArgument::Type(k)), Some(GenericArgument::Type(v))) =
            (iter.next(), iter.next())
        {
            return Some((k, v));
        }
    }
    None
}

fn parse_primitive_scalar(ty: &Type) -> Option<ScalarType> {
    let (ident, args) = last_type_segment(ty)?;
    if !matches!(args, PathArguments::None) {
        return None;
    }
    match ident.to_string().as_str() {
        "u8" => Some(ScalarType::U8),
        "u16" => Some(ScalarType::U16),
        "u32" => Some(ScalarType::U32),
        "u64" => Some(ScalarType::U64),
        "usize" => Some(ScalarType::Usize),
        "i8" => Some(ScalarType::I8),
        "i16" => Some(ScalarType::I16),
        "i32" => Some(ScalarType::I32),
        "i64" => Some(ScalarType::I64),
        "isize" => Some(ScalarType::Isize),
        "f32" => Some(ScalarType::F32),
        "f64" => Some(ScalarType::F64),
        "bool" => Some(ScalarType::Bool),
        "String" => Some(ScalarType::String),
        _ => None,
    }
}

fn is_vec_u8(ty: &Type) -> bool {
    if let Some((ident, args)) = last_type_segment(ty)
        && ident == "Vec"
        && let Some(inner) = single_generic_type(args)
    {
        return matches!(parse_primitive_scalar(inner), Some(ScalarType::U8));
    }
    false
}

fn resolve_scalar_wire(scalar: ScalarType, wire_opt: Option<&str>, span: Span) -> Result<u8> {
    match scalar {
        ScalarType::U8
        | ScalarType::U16
        | ScalarType::U32
        | ScalarType::U64
        | ScalarType::Usize => match wire_opt {
            None | Some("uint") => Ok(WIRE_UINT),
            Some("sint") => Ok(WIRE_SINT),
            Some("fixed32") => Ok(WIRE_FIXED32),
            Some("fixed64") => Ok(WIRE_FIXED64),
            Some(other) => Err(Error::new(
                span,
                format!("unsupported wire override {other:?} for unsigned integer"),
            )),
        },
        ScalarType::I8
        | ScalarType::I16
        | ScalarType::I32
        | ScalarType::I64
        | ScalarType::Isize => match wire_opt {
            None | Some("sint") => Ok(WIRE_SINT),
            Some("uint") => Ok(WIRE_UINT),
            Some("fixed32") | Some("sfixed32") => Ok(WIRE_SFIXED32),
            Some("fixed64") | Some("sfixed64") => Ok(WIRE_SFIXED64),
            Some(other) => Err(Error::new(
                span,
                format!("unsupported wire override {other:?} for signed integer"),
            )),
        },
        ScalarType::F32 => match wire_opt {
            None | Some("float32") | Some("fixed32") => Ok(WIRE_FLOAT32),
            Some(other) => Err(Error::new(
                span,
                format!("unsupported wire override {other:?} for f32"),
            )),
        },
        ScalarType::F64 => match wire_opt {
            None | Some("float64") | Some("fixed64") => Ok(WIRE_FLOAT64),
            Some(other) => Err(Error::new(
                span,
                format!("unsupported wire override {other:?} for f64"),
            )),
        },
        ScalarType::Bool => match wire_opt {
            None | Some("bool") => Ok(WIRE_BOOL_FALSE),
            Some(other) => Err(Error::new(
                span,
                format!("unsupported wire override {other:?} for bool"),
            )),
        },
        ScalarType::String => match wire_opt {
            None | Some("string") => Ok(WIRE_STRING),
            Some(other) => Err(Error::new(
                span,
                format!("unsupported wire override {other:?} for String"),
            )),
        },
        ScalarType::Bytes => match wire_opt {
            None | Some("bytes") => Ok(WIRE_BYTES),
            Some(other) => Err(Error::new(
                span,
                format!("unsupported wire override {other:?} for Vec<u8>"),
            )),
        },
    }
}

fn classify_field_type(
    ty: &Type,
    wire_opt: Option<&str>,
    key_wire_opt: Option<&str>,
    val_wire_opt: Option<&str>,
    span: Span,
) -> Result<FieldShape> {
    if is_vec_u8(ty) && matches!(wire_opt, None | Some("bytes")) {
        return Ok(FieldShape::Scalar {
            scalar: ScalarType::Bytes,
            wire_wt: WIRE_BYTES,
        });
    }

    if let Some(scalar) = parse_primitive_scalar(ty) {
        let wire_wt = resolve_scalar_wire(scalar, wire_opt, span)?;
        return Ok(FieldShape::Scalar { scalar, wire_wt });
    }

    if let Some((ident, args)) = last_type_segment(ty) {
        let name = ident.to_string();
        if name == "Option"
            && let Some(inner) = single_generic_type(args)
        {
            if is_vec_u8(inner) && matches!(wire_opt, None | Some("bytes")) {
                return Ok(FieldShape::OptScalar {
                    scalar: ScalarType::Bytes,
                    wire_wt: WIRE_BYTES,
                });
            }
            if let Some(scalar) = parse_primitive_scalar(inner) {
                let wire_wt = resolve_scalar_wire(scalar, wire_opt, span)?;
                return Ok(FieldShape::OptScalar { scalar, wire_wt });
            }
            if let Some((b_ident, b_args)) = last_type_segment(inner)
                && b_ident == "Box"
                && let Some(boxed_inner) = single_generic_type(b_args)
            {
                return Ok(FieldShape::OptSubMsg {
                    ty: Box::new(boxed_inner.clone()),
                    boxed: true,
                });
            }
            return Ok(FieldShape::OptSubMsg {
                ty: Box::new(inner.clone()),
                boxed: false,
            });
        }

        if name == "Vec"
            && let Some(elem_ty) = single_generic_type(args)
        {
            if is_vec_u8(elem_ty) {
                return Ok(FieldShape::ScalarVec {
                    scalar: ScalarType::Bytes,
                    elem_wt: WIRE_BYTES,
                });
            }
            if let Some(scalar) = parse_primitive_scalar(elem_ty) {
                let elem_wt = resolve_scalar_wire(scalar, wire_opt, span)?;
                return Ok(FieldShape::ScalarVec { scalar, elem_wt });
            }
            if let Some((b_ident, b_args)) = last_type_segment(elem_ty)
                && b_ident == "Box"
                && let Some(boxed_inner) = single_generic_type(b_args)
            {
                return Ok(FieldShape::SubMsgVec {
                    ty: Box::new(boxed_inner.clone()),
                    boxed: true,
                });
            }
            return Ok(FieldShape::SubMsgVec {
                ty: Box::new(elem_ty.clone()),
                boxed: false,
            });
        }

        if (name == "HashMap" || name == "BTreeMap")
            && let Some((k_ty, v_ty)) = double_generic_types(args)
        {
            let is_btree = name == "BTreeMap";
            let Some(key_scalar) = parse_primitive_scalar(k_ty) else {
                return Err(Error::new_spanned(
                    k_ty,
                    "OmniBuf map keys must be integer, bool, or String",
                ));
            };
            if matches!(
                key_scalar,
                ScalarType::F32 | ScalarType::F64 | ScalarType::Bytes
            ) {
                return Err(Error::new_spanned(
                    k_ty,
                    "float and bytes types are not valid OmniBuf map keys",
                ));
            }
            let key_wt = resolve_scalar_wire(key_scalar, key_wire_opt, span)?;

            let val_shape = if is_vec_u8(v_ty) && matches!(val_wire_opt, None | Some("bytes")) {
                MapValShape::Scalar {
                    scalar: ScalarType::Bytes,
                    wire_wt: WIRE_BYTES,
                }
            } else if let Some(val_scalar) = parse_primitive_scalar(v_ty) {
                let val_wt = resolve_scalar_wire(val_scalar, val_wire_opt, span)?;
                MapValShape::Scalar {
                    scalar: val_scalar,
                    wire_wt: val_wt,
                }
            } else if let Some((b_ident, b_args)) = last_type_segment(v_ty)
                && b_ident == "Box"
                && let Some(boxed_inner) = single_generic_type(b_args)
            {
                MapValShape::SubMsg {
                    ty: Box::new(boxed_inner.clone()),
                    boxed: true,
                }
            } else {
                MapValShape::SubMsg {
                    ty: Box::new(v_ty.clone()),
                    boxed: false,
                }
            };

            return Ok(FieldShape::Map {
                is_btree,
                key_scalar,
                key_wt,
                val: val_shape,
            });
        }

        if name == "Box"
            && let Some(boxed_inner) = single_generic_type(args)
        {
            return Ok(FieldShape::SubMsg {
                ty: Box::new(boxed_inner.clone()),
                boxed: true,
            });
        }
    }

    Ok(FieldShape::SubMsg {
        ty: Box::new(ty.clone()),
        boxed: false,
    })
}

fn scalar_rust_type_tokens(scalar: ScalarType) -> TokenStream2 {
    match scalar {
        ScalarType::U8 => quote!(u8),
        ScalarType::U16 => quote!(u16),
        ScalarType::U32 => quote!(u32),
        ScalarType::U64 => quote!(u64),
        ScalarType::Usize => quote!(usize),
        ScalarType::I8 => quote!(i8),
        ScalarType::I16 => quote!(i16),
        ScalarType::I32 => quote!(i32),
        ScalarType::I64 => quote!(i64),
        ScalarType::Isize => quote!(isize),
        ScalarType::F32 => quote!(f32),
        ScalarType::F64 => quote!(f64),
        ScalarType::Bool => quote!(bool),
        ScalarType::String => quote!(::std::string::String),
        ScalarType::Bytes => quote!(::std::vec::Vec<u8>),
    }
}

fn gen_write_scalar_field_expr(
    krate: &syn::Path,
    f_id: u32,
    scalar: ScalarType,
    wire_wt: u8,
    val_expr: TokenStream2,
) -> TokenStream2 {
    match (scalar, wire_wt) {
        (ScalarType::Bool, _) => quote! {
            #krate::codec::write_bool_field(dst, #f_id, *#val_expr);
        },
        (ScalarType::String, _) => quote! {
            #krate::codec::write_string_field(dst, #f_id, (#val_expr).as_str());
        },
        (ScalarType::Bytes, _) => quote! {
            #krate::codec::write_bytes_field(dst, #f_id, (#val_expr).as_slice());
        },
        (ScalarType::F32, _) => quote! {
            #krate::codec::write_float32_field(dst, #f_id, *#val_expr);
        },
        (ScalarType::F64, _) => quote! {
            #krate::codec::write_float64_field(dst, #f_id, *#val_expr);
        },
        (_, WIRE_UINT) => quote! {
            #krate::codec::write_uint_field(dst, #f_id, (*#val_expr) as u64);
        },
        (_, WIRE_SINT) => quote! {
            #krate::codec::write_sint_field(dst, #f_id, (*#val_expr) as i64);
        },
        (_, WIRE_FIXED32) => quote! {
            #krate::codec::write_fixed32_field(dst, #f_id, (*#val_expr) as u32);
        },
        (_, WIRE_FIXED64) => quote! {
            #krate::codec::write_fixed64_field(dst, #f_id, (*#val_expr) as u64);
        },
        (_, WIRE_SFIXED32) => quote! {
            #krate::codec::write_sfixed32_field(dst, #f_id, (*#val_expr) as i32);
        },
        (_, WIRE_SFIXED64) => quote! {
            #krate::codec::write_sfixed64_field(dst, #f_id, (*#val_expr) as i64);
        },
        _ => unreachable!(),
    }
}

fn gen_write_elem_payload_expr(
    krate: &syn::Path,
    scalar: ScalarType,
    wire_wt: u8,
    item_ident: &Ident,
) -> TokenStream2 {
    match (scalar, wire_wt) {
        (ScalarType::Bool, _) => quote! {
            dst.push(u8::from(*#item_ident));
        },
        (ScalarType::String, _) => quote! {
            #krate::wire::append_varint(dst, (#item_ident).len() as u64);
            dst.extend_from_slice((#item_ident).as_bytes());
        },
        (ScalarType::Bytes, _) => quote! {
            #krate::wire::append_varint(dst, (#item_ident).len() as u64);
            dst.extend_from_slice((#item_ident).as_slice());
        },
        (ScalarType::F32, _) => quote! {
            dst.extend_from_slice(&(#item_ident).to_bits().to_le_bytes());
        },
        (ScalarType::F64, _) => quote! {
            dst.extend_from_slice(&(#item_ident).to_bits().to_le_bytes());
        },
        (_, WIRE_UINT) => quote! {
            #krate::wire::append_varint(dst, (*#item_ident) as u64);
        },
        (_, WIRE_SINT) => quote! {
            #krate::wire::append_varint(dst, #krate::wire::encode_zigzag((*#item_ident) as i64));
        },
        (_, WIRE_FIXED32) => quote! {
            dst.extend_from_slice(&((*#item_ident) as u32).to_le_bytes());
        },
        (_, WIRE_FIXED64) => quote! {
            dst.extend_from_slice(&((*#item_ident) as u64).to_le_bytes());
        },
        (_, WIRE_SFIXED32) => quote! {
            dst.extend_from_slice(&((*#item_ident) as i32).to_le_bytes());
        },
        (_, WIRE_SFIXED64) => quote! {
            dst.extend_from_slice(&((*#item_ident) as i64).to_le_bytes());
        },
        _ => unreachable!(),
    }
}

fn gen_read_elem_payload_expr(krate: &syn::Path, scalar: ScalarType, wire_wt: u8) -> TokenStream2 {
    let target_ty = scalar_rust_type_tokens(scalar);
    match (scalar, wire_wt) {
        (ScalarType::Bool, _) => quote! { #krate::codec::read_elem_bool(b, p) },
        (ScalarType::String, _) => quote! { #krate::codec::read_elem_string(b, p) },
        (ScalarType::Bytes, _) => quote! { #krate::codec::read_elem_bytes(b, p) },
        (ScalarType::F32, _) => quote! { #krate::codec::read_elem_float32(b, p) },
        (ScalarType::F64, _) => quote! { #krate::codec::read_elem_float64(b, p) },
        (_, WIRE_UINT) => quote! {
            #krate::codec::read_elem_uint(b, p).map(|(v, np)| (v as #target_ty, np))
        },
        (_, WIRE_SINT) => quote! {
            #krate::codec::read_elem_sint(b, p).map(|(v, np)| (v as #target_ty, np))
        },
        (_, WIRE_FIXED32) => quote! {
            #krate::codec::read_elem_fixed32(b, p).map(|(v, np)| (v as #target_ty, np))
        },
        (_, WIRE_FIXED64) => quote! {
            #krate::codec::read_elem_fixed64(b, p).map(|(v, np)| (v as #target_ty, np))
        },
        (_, WIRE_SFIXED32) => quote! {
            #krate::codec::read_elem_sfixed32(b, p).map(|(v, np)| (v as #target_ty, np))
        },
        (_, WIRE_SFIXED64) => quote! {
            #krate::codec::read_elem_sfixed64(b, p).map(|(v, np)| (v as #target_ty, np))
        },
        _ => unreachable!(),
    }
}

fn gen_encode_field(krate: &syn::Path, cf: &CompiledField) -> TokenStream2 {
    let f_ident = &cf.ident;
    let f_id = cf.id;

    let body = match &cf.shape {
        FieldShape::Scalar { scalar, wire_wt } => {
            gen_write_scalar_field_expr(krate, f_id, *scalar, *wire_wt, quote!(&self.#f_ident))
        }
        FieldShape::OptScalar { scalar, wire_wt } => {
            let write_inner =
                gen_write_scalar_field_expr(krate, f_id, *scalar, *wire_wt, quote!(val));
            return quote! {
                if let ::core::option::Option::Some(ref val) = self.#f_ident {
                    #write_inner
                }
            };
        }
        FieldShape::SubMsg { boxed, .. } => {
            if *boxed {
                quote! {
                    #krate::codec::write_sub_msg_field(dst, #f_id, &*self.#f_ident, deterministic)?;
                }
            } else {
                quote! {
                    #krate::codec::write_sub_msg_field(dst, #f_id, &self.#f_ident, deterministic)?;
                }
            }
        }
        FieldShape::OptSubMsg { boxed, .. } => {
            if *boxed {
                return quote! {
                    if let ::core::option::Option::Some(ref sub) = self.#f_ident {
                        #krate::codec::write_sub_msg_field(dst, #f_id, &**sub, deterministic)?;
                    }
                };
            }
            return quote! {
                if let ::core::option::Option::Some(ref sub) = self.#f_ident {
                    #krate::codec::write_sub_msg_field(dst, #f_id, sub, deterministic)?;
                }
            };
        }
        FieldShape::ScalarVec { scalar, elem_wt } => {
            let item_ident = Ident::new("__item", Span::call_site());
            let write_elem = gen_write_elem_payload_expr(krate, *scalar, *elem_wt, &item_ident);
            quote! {
                #krate::codec::write_scalar_vec_field(
                    dst,
                    #f_id,
                    #elem_wt,
                    &self.#f_ident,
                    |dst, #item_ident| {
                        #write_elem
                        ::core::result::Result::Ok(())
                    },
                )?;
            }
        }
        FieldShape::SubMsgVec { boxed, .. } => {
            if *boxed {
                quote! {
                    #krate::codec::write_box_sub_msg_vec_field(dst, #f_id, &self.#f_ident, deterministic)?;
                }
            } else {
                quote! {
                    #krate::codec::write_sub_msg_vec_field(dst, #f_id, &self.#f_ident, deterministic)?;
                }
            }
        }
        FieldShape::Map {
            is_btree,
            key_scalar,
            key_wt,
            val,
        } => {
            let k_ident = Ident::new("__k", Span::call_site());
            let v_ident = Ident::new("__v", Span::call_site());
            let write_key = gen_write_elem_payload_expr(krate, *key_scalar, *key_wt, &k_ident);
            let (val_wt, write_val) = match val {
                MapValShape::Scalar { scalar, wire_wt } => {
                    let wv = gen_write_elem_payload_expr(krate, *scalar, *wire_wt, &v_ident);
                    (
                        *wire_wt,
                        quote! {
                            let _ = det;
                            #wv
                            ::core::result::Result::Ok(())
                        },
                    )
                }
                MapValShape::SubMsg { boxed, .. } => {
                    let call = if *boxed {
                        quote!((**#v_ident).encode_omnibuf_append(dst, det)?)
                    } else {
                        quote!((#v_ident).encode_omnibuf_append(dst, det)?)
                    };
                    (
                        WIRE_SUB_MSG,
                        quote! {
                            let elem_pos = dst.len();
                            dst.extend_from_slice(&[0, 0]);
                            #call;
                            #krate::wire::backpatch_container_len(dst, elem_pos);
                            ::core::result::Result::Ok(())
                        },
                    )
                }
            };

            if *is_btree {
                quote! {
                    #krate::codec::write_btree_map_field(
                        dst,
                        #f_id,
                        #key_wt,
                        #val_wt,
                        &self.#f_ident,
                        deterministic,
                        |dst, #k_ident| {
                            #write_key
                            ::core::result::Result::Ok(())
                        },
                        |dst, #v_ident, det| {
                            #write_val
                        },
                    )?;
                }
            } else {
                quote! {
                    #krate::codec::write_hash_map_field(
                        dst,
                        #f_id,
                        #key_wt,
                        #val_wt,
                        &self.#f_ident,
                        deterministic,
                        |dst, #k_ident| {
                            #write_key
                            ::core::result::Result::Ok(())
                        },
                        |dst, #v_ident, det| {
                            #write_val
                        },
                    )?;
                }
            }
        }
    };

    if cf.omit_empty {
        quote! {
            if !#krate::codec::IsEmpty::is_omnibuf_empty(&self.#f_ident) {
                #body
            }
        }
    } else {
        body
    }
}

fn gen_decode_scalar_value_expr(
    _krate: &syn::Path,
    scalar: ScalarType,
    wire_wt: u8,
) -> TokenStream2 {
    let target_ty = scalar_rust_type_tokens(scalar);
    match (scalar, wire_wt) {
        (ScalarType::String, _) => quote!(::std::borrow::ToOwned::to_owned(dec.read_str()?)),
        (ScalarType::Bytes, _) => quote!(dec.read_bytes()?.to_vec()),
        (ScalarType::F32, _) => quote!(dec.read_float32()?),
        (ScalarType::F64, _) => quote!(dec.read_float64()?),
        (_, WIRE_UINT) => quote!(dec.read_uint()? as #target_ty),
        (_, WIRE_SINT) => quote!(dec.read_sint()? as #target_ty),
        (_, WIRE_FIXED32) => quote!(dec.read_fixed32()? as #target_ty),
        (_, WIRE_FIXED64) => quote!(dec.read_fixed64()? as #target_ty),
        (_, WIRE_SFIXED32) => quote!(dec.read_sfixed32()? as #target_ty),
        (_, WIRE_SFIXED64) => quote!(dec.read_sfixed64()? as #target_ty),
        _ => unreachable!(),
    }
}

fn gen_decode_arm(krate: &syn::Path, cf: &CompiledField, idx: usize) -> TokenStream2 {
    let f_ident = &cf.ident;
    let f_id = cf.id;

    match &cf.shape {
        FieldShape::Scalar {
            scalar: ScalarType::Bool,
            ..
        } => {
            quote! {
                #f_id if wt == #krate::wire::WIRE_BOOL_FALSE || wt == #krate::wire::WIRE_BOOL_TRUE => {
                    seen[#idx] = true;
                    self.#f_ident = wt == #krate::wire::WIRE_BOOL_TRUE;
                }
            }
        }
        FieldShape::OptScalar {
            scalar: ScalarType::Bool,
            ..
        } => {
            quote! {
                #f_id if wt == #krate::wire::WIRE_BOOL_FALSE || wt == #krate::wire::WIRE_BOOL_TRUE => {
                    seen[#idx] = true;
                    self.#f_ident = ::core::option::Option::Some(wt == #krate::wire::WIRE_BOOL_TRUE);
                }
            }
        }
        FieldShape::Scalar { scalar, wire_wt } => {
            let read_val = gen_decode_scalar_value_expr(krate, *scalar, *wire_wt);
            quote! {
                #f_id if wt == #wire_wt => {
                    seen[#idx] = true;
                    self.#f_ident = #read_val;
                }
            }
        }
        FieldShape::OptScalar { scalar, wire_wt } => {
            let read_val = gen_decode_scalar_value_expr(krate, *scalar, *wire_wt);
            quote! {
                #f_id if wt == #wire_wt => {
                    seen[#idx] = true;
                    self.#f_ident = ::core::option::Option::Some(#read_val);
                }
            }
        }
        FieldShape::SubMsg { boxed, .. } => {
            let target = if *boxed {
                quote!(&mut *self.#f_ident)
            } else {
                quote!(&mut self.#f_ident)
            };
            quote! {
                #f_id if wt == #WIRE_SUB_MSG => {
                    let sub_merge = merge || seen[#idx];
                    seen[#idx] = true;
                    let sub_bytes = dec.read_container(0)?;
                    (#target).decode_omnibuf_at_depth(sub_bytes, depth + 1, sub_merge)?;
                }
            }
        }
        FieldShape::OptSubMsg { boxed, .. } => {
            if *boxed {
                quote! {
                    #f_id if wt == #WIRE_SUB_MSG => {
                        let sub_merge = merge || seen[#idx];
                        seen[#idx] = true;
                        let sub_bytes = dec.read_container(0)?;
                        let sub = self.#f_ident.get_or_insert_with(|| ::std::boxed::Box::new(::core::default::Default::default()));
                        sub.decode_omnibuf_at_depth(sub_bytes, depth + 1, sub_merge)?;
                    }
                }
            } else {
                quote! {
                    #f_id if wt == #WIRE_SUB_MSG => {
                        let sub_merge = merge || seen[#idx];
                        seen[#idx] = true;
                        let sub_bytes = dec.read_container(0)?;
                        let sub = self.#f_ident.get_or_insert_with(::core::default::Default::default);
                        sub.decode_omnibuf_at_depth(sub_bytes, depth + 1, sub_merge)?;
                    }
                }
            }
        }
        FieldShape::ScalarVec { scalar, elem_wt } => {
            let read_elem = gen_read_elem_payload_expr(krate, *scalar, *elem_wt);
            quote! {
                #f_id if wt == #WIRE_ARRAY => {
                    let reset = !merge && !seen[#idx];
                    seen[#idx] = true;
                    let pos = dec.position();
                    let next_pos = #krate::codec::read_scalar_vec_field(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        #elem_wt,
                        reset,
                        |b, p| #read_elem,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::SubMsgVec { boxed, .. } => {
            let fn_ident = if *boxed {
                quote!(read_box_sub_msg_vec_field)
            } else {
                quote!(read_sub_msg_vec_field)
            };
            quote! {
                #f_id if wt == #WIRE_ARRAY => {
                    let reset = !merge && !seen[#idx];
                    seen[#idx] = true;
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        reset,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::Map {
            is_btree,
            key_scalar,
            key_wt,
            val,
        } => {
            let read_key = gen_read_elem_payload_expr(krate, *key_scalar, *key_wt);
            let (val_wt, read_val) = match val {
                MapValShape::Scalar { scalar, wire_wt } => {
                    let rv = gen_read_elem_payload_expr(krate, *scalar, *wire_wt);
                    (*wire_wt, quote!(|b, p, _d| #rv))
                }
                MapValShape::SubMsg { ty, boxed } => {
                    if *boxed {
                        (
                            WIRE_SUB_MSG,
                            quote! {
                                |b, p, d| {
                                    let (sub_bytes, np) = #krate::wire::read_len_slice(b, p, 0)?;
                                    let mut sub: ::std::boxed::Box<#ty> = ::std::boxed::Box::new(::core::default::Default::default());
                                    sub.decode_omnibuf_at_depth(sub_bytes, d + 1, false)?;
                                    ::core::result::Result::Ok((sub, np))
                                }
                            },
                        )
                    } else {
                        (
                            WIRE_SUB_MSG,
                            quote! {
                                |b, p, d| {
                                    let (sub_bytes, np) = #krate::wire::read_len_slice(b, p, 0)?;
                                    let mut sub: #ty = ::core::default::Default::default();
                                    sub.decode_omnibuf_at_depth(sub_bytes, d + 1, false)?;
                                    ::core::result::Result::Ok((sub, np))
                                }
                            },
                        )
                    }
                }
            };
            let fn_ident = if *is_btree {
                quote!(read_btree_map_field)
            } else {
                quote!(read_hash_map_field)
            };
            quote! {
                #f_id if wt == #WIRE_MAP => {
                    let reset = !merge && !seen[#idx];
                    seen[#idx] = true;
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        #key_wt,
                        #val_wt,
                        reset,
                        |b, p| #read_key,
                        #read_val,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
    }
}

fn gen_clear_field(krate: &syn::Path, cf: &CompiledField, seen_idx: Option<usize>) -> TokenStream2 {
    let f_ident = &cf.ident;
    let stmt = match &cf.shape {
        FieldShape::Scalar {
            scalar: ScalarType::String,
            ..
        }
        | FieldShape::Scalar {
            scalar: ScalarType::Bytes,
            ..
        }
        | FieldShape::ScalarVec { .. }
        | FieldShape::SubMsgVec { .. }
        | FieldShape::Map { .. } => {
            quote! { self.#f_ident.clear(); }
        }
        FieldShape::Scalar { .. } => {
            quote! { self.#f_ident = ::core::default::Default::default(); }
        }
        FieldShape::OptScalar { .. } | FieldShape::OptSubMsg { .. } => {
            quote! { self.#f_ident = ::core::option::Option::None; }
        }
        FieldShape::SubMsg { .. } => {
            quote! { #krate::Message::clear_omnibuf(&mut self.#f_ident); }
        }
    };

    if let Some(idx) = seen_idx {
        quote! {
            if !seen[#idx] {
                #stmt
            }
        }
    } else {
        stmt
    }
}

fn gen_schema_field(
    krate: &syn::Path,
    cf: &CompiledField,
    f_id: u32,
    f_name: &str,
) -> TokenStream2 {
    let insert_name = quote! {
        meta.fields.insert(#f_id, ::std::string::String::from(#f_name));
    };

    let child_stmt = match &cf.shape {
        FieldShape::SubMsg { ty, .. } | FieldShape::OptSubMsg { ty, .. } => Some(quote! {
            if let ::core::option::Option::Some(child) = <#ty as #krate::Message>::build_schema_meta(active, depth + 1) {
                meta.children.insert(#f_id, child);
            }
        }),
        FieldShape::SubMsgVec { ty, .. } => Some(quote! {
            if let ::core::option::Option::Some(child) = <#ty as #krate::Message>::build_schema_meta(active, depth + 2) {
                meta.children.insert(#f_id, child);
            }
        }),
        FieldShape::Map {
            val: MapValShape::SubMsg { ty, .. },
            ..
        } => Some(quote! {
            if let ::core::option::Option::Some(child) = <#ty as #krate::Message>::build_schema_meta(active, depth + 2) {
                meta.children.insert(#f_id, child);
            }
        }),
        _ => None,
    };

    if let Some(cs) = child_stmt {
        quote! {
            #insert_name
            #cs
        }
    } else {
        insert_name
    }
}
