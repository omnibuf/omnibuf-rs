use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::punctuated::Punctuated;
use syn::{
    Attribute, Data, DeriveInput, Error, Expr, ExprLit, Field, Fields, GenericArgument, Ident, Lit,
    Meta, PathArguments, Result, Token, Type, Variant, parse_macro_input,
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

/// Derives `omnibuf::Message` for a Rust struct or `omnibuf::codec::Oneof` for a Rust enum.
///
/// Supports native `#[omnibuf(...)]` attributes, `prost`-generated `#[prost(...)]` attributes,
/// and `buffa` field wrappers (`MessageField<T>`, `EnumValue<E>`, `__buffa_*` metadata fields).
#[proc_macro_derive(OmniBuf, attributes(omnibuf, prost))]
pub fn derive_omnibuf(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_derive_omnibuf(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

struct ContainerConfig {
    type_name: String,
    crate_path: syn::Path,
}

#[derive(Default)]
struct FieldAttr {
    id: Option<u32>,
    tags: Vec<u32>,
    name: Option<String>,
    wire: Option<String>,
    key_wire: Option<String>,
    val_wire: Option<String>,
    omit_empty: bool,
    skip: bool,
    is_oneof: bool,
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

#[derive(Clone)]
enum ElemShape {
    Scalar {
        scalar: ScalarType,
        wire_wt: u8,
    },
    BuffaEnum {
        enum_ty: Box<Type>,
    },
    SubMsg {
        ty: Box<Type>,
        boxed: bool,
    },
    Vec(Box<ElemShape>),
    Map {
        is_btree: bool,
        key_scalar: ScalarType,
        key_wt: u8,
        val: Box<ElemShape>,
    },
}

impl ElemShape {
    fn wire_type(&self) -> u8 {
        match self {
            Self::Scalar { wire_wt, .. } => *wire_wt,
            Self::BuffaEnum { .. } => WIRE_SINT,
            Self::SubMsg { .. } => WIRE_SUB_MSG,
            Self::Vec(_) => WIRE_ARRAY,
            Self::Map { .. } => WIRE_MAP,
        }
    }

    fn leaf_submsg_type(&self) -> Option<&Type> {
        match self {
            Self::SubMsg { ty, .. } => Some(ty),
            Self::Vec(inner) => inner.leaf_submsg_type(),
            Self::Map { val, .. } => val.leaf_submsg_type(),
            _ => None,
        }
    }
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
    BuffaEnum {
        enum_ty: Box<Type>,
    },
    OptBuffaEnum {
        enum_ty: Box<Type>,
    },
    SubMsg {
        ty: Box<Type>,
        boxed: bool,
    },
    OptSubMsg {
        ty: Box<Type>,
        boxed: bool,
    },
    BuffaMessageField {
        ty: Box<Type>,
    },
    ScalarVec {
        scalar: ScalarType,
        elem_wt: u8,
    },
    BuffaEnumVec {
        enum_ty: Box<Type>,
    },
    SubMsgVec {
        ty: Box<Type>,
        boxed: bool,
    },
    NestedVec {
        elem: Box<ElemShape>,
    },
    Map {
        is_btree: bool,
        key_scalar: ScalarType,
        key_wt: u8,
        val: Box<ElemShape>,
    },
    Oneof {
        ty: Box<Type>,
        tags: Vec<u32>,
    },
}

struct CompiledField {
    ident: Ident,
    id: u32,
    schema_name: String,
    omit_empty: bool,
    shape: FieldShape,
}

enum OneofVariantShape {
    Scalar { scalar: ScalarType, wire_wt: u8 },
    BuffaEnum { enum_ty: Box<Type> },
    SubMsg { ty: Box<Type>, boxed: bool },
}

struct CompiledVariant {
    ident: Ident,
    id: u32,
    schema_name: String,
    shape: OneofVariantShape,
}

fn expand_derive_omnibuf(input: &DeriveInput) -> Result<TokenStream2> {
    let cfg = parse_container_attrs(&input.attrs, &input.ident)?;
    match &input.data {
        Data::Struct(data_struct) => expand_struct(input, data_struct, &cfg),
        Data::Enum(data_enum) => expand_oneof_enum(input, data_enum, &cfg),
        Data::Union(_) => Err(Error::new_spanned(
            &input.ident,
            "#[derive(OmniBuf)] is not supported on unions",
        )),
    }
}

fn expand_struct(
    input: &DeriveInput,
    data_struct: &syn::DataStruct,
    cfg: &ContainerConfig,
) -> Result<TokenStream2> {
    let krate = &cfg.crate_path;
    let fields = match &data_struct.fields {
        Fields::Named(named) => &named.named,
        Fields::Unit => return expand_empty_struct(input, cfg),
        Fields::Unnamed(_) => {
            return Err(Error::new_spanned(
                &input.ident,
                "#[derive(OmniBuf)] on structs requires named fields",
            ));
        }
    };

    let mut compiled = Vec::with_capacity(fields.len());
    let mut used_ids = HashSet::new();

    for field in fields {
        if let Some(cf) = compile_field(field, &mut used_ids)? {
            compiled.push(cf);
        }
    }

    compiled.sort_by_key(|f| f.id);

    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let num_fields = compiled.len();
    let type_name_lit = &cfg.type_name;

    let mut encode_stmts = Vec::with_capacity(num_fields);
    let mut min_size_stmts = Vec::with_capacity(num_fields);
    let mut decode_arms = Vec::with_capacity(num_fields + 2);
    let mut fallback_oneof_tries = Vec::new();
    let mut clear_all_stmts = Vec::with_capacity(num_fields);
    let mut is_empty_checks = Vec::with_capacity(num_fields);
    let mut schema_field_stmts = Vec::with_capacity(num_fields);
    let mut schema_child_stmts = Vec::with_capacity(num_fields);
    let mut schema_cyclic_stmts = Vec::new();
    let mut value_schema_child_stmts = Vec::new();

    for cf in &compiled {
        let f_ident = &cf.ident;
        encode_stmts.push(gen_encode_field(krate, cf));
        min_size_stmts.push(gen_min_wire_size_field(krate, cf));
        if let FieldShape::Oneof { ty, tags } = &cf.shape {
            if tags.is_empty() {
                fallback_oneof_tries.push(quote! {
                    if let ::core::option::Option::Some(__np) = <#ty as #krate::codec::Oneof>::decode_oneof_arm(
                        &mut self.#f_ident,
                        fnum,
                        wt,
                        dec.data(),
                        dec.position(),
                        depth,
                    )? {
                        dec.set_position(__np);
                        continue;
                    }
                });
            } else {
                decode_arms.push(quote! {
                    #(#tags)|* => {
                        if let ::core::option::Option::Some(__np) = <#ty as #krate::codec::Oneof>::decode_oneof_arm(
                            &mut self.#f_ident,
                            fnum,
                            wt,
                            dec.data(),
                            dec.position(),
                            depth,
                        )? {
                            dec.set_position(__np);
                        } else {
                            dec.skip_unknown(fnum, wt)?;
                        }
                    }
                });
            }
        } else {
            decode_arms.push(gen_decode_arm(krate, cf));
        }
        clear_all_stmts.push(gen_clear_field(krate, cf));
        is_empty_checks.push(gen_is_empty_check(krate, cf));
        let (sf, sc, cyc, val_sc) = gen_schema_parts(krate, cf);
        if let Some(s) = sf {
            schema_field_stmts.push(s);
        }
        if let Some(c) = sc {
            schema_child_stmts.push(c);
        }
        if let Some(cy) = cyc {
            schema_cyclic_stmts.push(cy);
        }
        if let Some(vsc) = val_sc {
            value_schema_child_stmts.push(vsc);
        }
    }

    let has_oneof = compiled
        .iter()
        .any(|cf| matches!(cf.shape, FieldShape::Oneof { .. }));
    let mut fast_decode_stmts = Vec::new();
    let use_fast_decode = !has_oneof && num_fields > 0 && num_fields <= 24;
    if use_fast_decode {
        for cf in &compiled {
            if let Some(stmt) = gen_fast_decode_stmt(krate, cf) {
                fast_decode_stmts.push(stmt);
            }
        }
    }

    let decode_body = if use_fast_decode {
        quote! {
            let mut dec = #krate::Decoder::with_depth(data, depth)?;
            if !merge {
                self.clear_omnibuf();
            }
            #(#fast_decode_stmts)*
            if dec.is_empty() {
                return ::core::result::Result::Ok(());
            }
            let __pos = dec.position();
            #krate::codec::cold_decode_fallback(|| {
                let mut dec = #krate::Decoder::with_depth(data, depth)?;
                dec.set_position(__pos);
                while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {
                    match fnum {
                        #(#decode_arms)*
                        _ => {
                            dec.skip_unknown(fnum, wt)?;
                        }
                    }
                }
                ::core::result::Result::Ok(())
            })
        }
    } else {
        quote! {
            let mut dec = #krate::Decoder::with_depth(data, depth)?;
            if !merge {
                self.clear_omnibuf();
            }
            while let ::core::option::Option::Some((fnum, wt)) = dec.next_tag()? {
                match fnum {
                    #(#decode_arms)*
                    _ => {
                        #(#fallback_oneof_tries)*
                        dec.skip_unknown(fnum, wt)?;
                    }
                }
            }
            ::core::result::Result::Ok(())
        }
    };

    let decode_inline_attr = if !has_oneof && num_fields > 0 && num_fields <= 8 {
        quote!(#[inline(always)])
    } else {
        quote!(#[inline])
    };

    Ok(quote! {
        impl #impl_generics #krate::codec::IsEmpty for #ident #ty_generics #where_clause {
            #[inline]
            fn is_omnibuf_empty(&self) -> bool {
                #(#is_empty_checks)*
                true
            }
        }

        impl #impl_generics #krate::Message for #ident #ty_generics #where_clause {
            #[inline]
            fn min_wire_size_bounded(&self, depth_rem: usize) -> usize {
                let _ = depth_rem;
                let mut __sz = 0usize;
                #(#min_size_stmts)*
                __sz
            }

            #[inline]
            fn encode_omnibuf_append(
                &self,
                dst: &mut ::std::vec::Vec<u8>,
                deterministic: bool,
            ) -> #krate::Result<()> {
                let _ = deterministic;
                #(#encode_stmts)*
                ::core::result::Result::Ok(())
            }

            #decode_inline_attr
            fn decode_omnibuf_at_depth(
                &mut self,
                data: &[u8],
                depth: usize,
                merge: bool,
            ) -> #krate::Result<()> {
                #decode_body
            }

            #[inline]
            fn clear_omnibuf(&mut self) {
                #(#clear_all_stmts)*
            }

            fn build_schema_meta(
                active: &mut ::std::collections::HashSet<::core::any::TypeId>,
                depth: usize,
            ) -> ::core::option::Option<#krate::SchemaMeta> {
                if depth >= #krate::MAX_NESTING_DEPTH {
                    return ::core::option::Option::None;
                }
                let type_id = ::core::any::TypeId::of::<Self>();
                let mut meta = #krate::SchemaMeta {
                    type_name: ::std::string::String::from(#type_name_lit),
                    fields: ::std::collections::BTreeMap::new(),
                    children: ::std::collections::BTreeMap::new(),
                };
                #(#schema_field_stmts)*
                if !active.insert(type_id) {
                    return ::core::option::Option::Some(meta);
                }
                #(#schema_child_stmts)*
                active.remove(&type_id);
                ::core::option::Option::Some(meta)
            }

            fn is_schema_cyclic(
                active: &mut ::std::collections::HashSet<::core::any::TypeId>,
                depth: usize,
            ) -> bool {
                if depth >= #krate::MAX_NESTING_DEPTH {
                    return false;
                }
                let type_id = ::core::any::TypeId::of::<Self>();
                if !active.insert(type_id) {
                    return true;
                }
                #(#schema_cyclic_stmts)*
                active.remove(&type_id);
                false
            }

            fn build_value_schema_meta(&self, depth: usize) -> ::core::option::Option<#krate::SchemaMeta> {
                if depth >= #krate::MAX_NESTING_DEPTH {
                    return ::core::option::Option::None;
                }
                let mut meta = #krate::SchemaMeta {
                    type_name: ::std::string::String::from(#type_name_lit),
                    fields: ::std::collections::BTreeMap::new(),
                    children: ::std::collections::BTreeMap::new(),
                };
                #(#schema_field_stmts)*
                if depth + 2 < #krate::MAX_NESTING_DEPTH {
                    #(#value_schema_child_stmts)*
                }
                ::core::option::Option::Some(meta)
            }
        }
    })
}

fn expand_empty_struct(input: &DeriveInput, cfg: &ContainerConfig) -> Result<TokenStream2> {
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
                _active: &mut ::std::collections::HashSet<::core::any::TypeId>,
                depth: usize,
            ) -> ::core::option::Option<#krate::SchemaMeta> {
                if depth >= #krate::MAX_NESTING_DEPTH {
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

fn expand_oneof_enum(
    input: &DeriveInput,
    data_enum: &syn::DataEnum,
    cfg: &ContainerConfig,
) -> Result<TokenStream2> {
    let krate = &cfg.crate_path;
    let ident = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let mut variants = Vec::with_capacity(data_enum.variants.len());
    let mut used_ids = HashSet::new();
    for var in &data_enum.variants {
        variants.push(compile_oneof_variant(var, &mut used_ids)?);
    }

    let mut encode_arms = Vec::with_capacity(variants.len());
    let mut min_size_arms = Vec::with_capacity(variants.len());
    let mut decode_arms = Vec::with_capacity(variants.len());
    let mut schema_field_stmts = Vec::with_capacity(variants.len());
    let mut schema_child_stmts = Vec::new();
    let mut schema_cyclic_stmts = Vec::new();
    let mut value_schema_arms = Vec::new();

    for cv in &variants {
        let v_ident = &cv.ident;
        let v_id = cv.id;
        let v_name = &cv.schema_name;

        schema_field_stmts.push(quote! {
            meta.fields.insert(#v_id, ::std::string::String::from(#v_name));
        });

        match &cv.shape {
            OneofVariantShape::Scalar { scalar, wire_wt } => {
                let write_stmt =
                    gen_write_scalar_field_expr(krate, v_id, *scalar, *wire_wt, quote!(__val));
                encode_arms.push(quote! {
                    Self::#v_ident(ref __val) => {
                        #write_stmt
                    }
                });
                let min_expr =
                    gen_scalar_min_size_expr(krate, v_id, *scalar, *wire_wt, quote!(__val));
                min_size_arms.push(quote! {
                    Self::#v_ident(ref __val) => {
                        let _ = __val;
                        #min_expr
                    }
                });

                if *scalar == ScalarType::Bool {
                    decode_arms.push(quote! {
                        #v_id if wt == #krate::wire::WIRE_BOOL_FALSE || wt == #krate::wire::WIRE_BOOL_TRUE => {
                            *slot = ::core::option::Option::Some(Self::#v_ident(wt == #krate::wire::WIRE_BOOL_TRUE));
                            return ::core::result::Result::Ok(::core::option::Option::Some(pos));
                        }
                    });
                } else {
                    let read_expr = gen_read_elem_payload_expr(krate, *scalar, *wire_wt);
                    decode_arms.push(quote! {
                        #v_id if wt == #wire_wt => {
                            let b = data;
                            let p = pos;
                            let (__val, __np) = (#read_expr)?;
                            *slot = ::core::option::Option::Some(Self::#v_ident(__val));
                            return ::core::result::Result::Ok(::core::option::Option::Some(__np));
                        }
                    });
                }
            }
            OneofVariantShape::BuffaEnum { enum_ty } => {
                let tw = tag_varint_width(v_id, WIRE_SINT);
                encode_arms.push(quote! {
                    Self::#v_ident(ref __val) => {
                        #krate::codec::write_buffa_enum_field(dst, #v_id, __val);
                    }
                });
                min_size_arms.push(quote! {
                    Self::#v_ident(_) => #tw + 1usize,
                });
                decode_arms.push(quote! {
                    #v_id if wt == #WIRE_SINT => {
                        let (__val, __np) = #krate::codec::read_buffa_enum_elem::<#enum_ty>(data, pos)?;
                        *slot = ::core::option::Option::Some(Self::#v_ident(__val));
                        return ::core::result::Result::Ok(::core::option::Option::Some(__np));
                    }
                });
            }
            OneofVariantShape::SubMsg { ty, boxed } => {
                let tw = tag_varint_width(v_id, WIRE_SUB_MSG);
                if *boxed {
                    encode_arms.push(quote! {
                        Self::#v_ident(ref __sub) => {
                            #krate::codec::write_sub_msg_field(dst, #v_id, &**__sub, deterministic)?;
                        }
                    });
                    min_size_arms.push(quote! {
                        Self::#v_ident(ref __sub) => {
                            let __s = if depth_rem > 0 {
                                <#ty as #krate::Message>::min_wire_size_bounded(&**__sub, depth_rem - 1)
                            } else {
                                0usize
                            };
                            #tw + #krate::wire::container_len_width(__s) + __s
                        }
                    });
                    decode_arms.push(quote! {
                        #v_id if wt == #WIRE_SUB_MSG => {
                            let (__sb, __np) = #krate::wire::read_len_slice(data, pos, 0)?;
                            if let ::core::option::Option::Some(Self::#v_ident(ref mut __existing)) = *slot {
                                <#ty as #krate::Message>::decode_omnibuf_at_depth(&mut **__existing, __sb, depth + 1, true)?;
                            } else {
                                let __sub: ::std::boxed::Box<#ty> = #krate::codec::read_box_sub_msg_value::<#ty>(__sb, depth + 1)?;
                                *slot = ::core::option::Option::Some(Self::#v_ident(__sub));
                            }
                            return ::core::result::Result::Ok(::core::option::Option::Some(__np));
                        }
                    });
                    value_schema_arms.push(quote! {
                        Self::#v_ident(ref __sub) => {
                            if let ::core::option::Option::Some(__child) = <#ty as #krate::Message>::build_value_schema_meta(&**__sub, depth + 2) {
                                meta.children.insert(#v_id, __child);
                            }
                        }
                    });
                } else {
                    encode_arms.push(quote! {
                        Self::#v_ident(ref __sub) => {
                            #krate::codec::write_sub_msg_field(dst, #v_id, __sub, deterministic)?;
                        }
                    });
                    min_size_arms.push(quote! {
                        Self::#v_ident(ref __sub) => {
                            let __s = if depth_rem > 0 {
                                <#ty as #krate::Message>::min_wire_size_bounded(__sub, depth_rem - 1)
                            } else {
                                0usize
                            };
                            #tw + #krate::wire::container_len_width(__s) + __s
                        }
                    });
                    decode_arms.push(quote! {
                        #v_id if wt == #WIRE_SUB_MSG => {
                            let (__sb, __np) = #krate::wire::read_len_slice(data, pos, 0)?;
                            if let ::core::option::Option::Some(Self::#v_ident(ref mut __existing)) = *slot {
                                <#ty as #krate::Message>::decode_omnibuf_at_depth(__existing, __sb, depth + 1, true)?;
                            } else {
                                let mut __sub: #ty = ::core::default::Default::default();
                                <#ty as #krate::Message>::decode_omnibuf_at_depth(&mut __sub, __sb, depth + 1, true)?;
                                *slot = ::core::option::Option::Some(Self::#v_ident(__sub));
                            }
                            return ::core::result::Result::Ok(::core::option::Option::Some(__np));
                        }
                    });
                    value_schema_arms.push(quote! {
                        Self::#v_ident(ref __sub) => {
                            if let ::core::option::Option::Some(__child) = <#ty as #krate::Message>::build_value_schema_meta(__sub, depth + 2) {
                                meta.children.insert(#v_id, __child);
                            }
                        }
                    });
                }
                schema_child_stmts.push(quote! {
                    if let ::core::option::Option::Some(__child) = <#ty as #krate::Message>::build_schema_meta(active, depth + 2) {
                        meta.children.insert(#v_id, __child);
                    }
                });
                schema_cyclic_stmts.push(quote! {
                    if <#ty as #krate::Message>::is_schema_cyclic(active, depth + 2) {
                        return true;
                    }
                });
            }
        }
    }

    Ok(quote! {
        impl #impl_generics #krate::codec::Oneof for #ident #ty_generics #where_clause {
            #[inline]
            fn min_wire_size_bounded(&self, depth_rem: usize) -> usize {
                let _ = depth_rem;
                match *self {
                    #(#min_size_arms)*
                }
            }

            #[inline]
            fn encode_oneof(
                &self,
                dst: &mut ::std::vec::Vec<u8>,
                deterministic: bool,
            ) -> #krate::Result<()> {
                let _ = deterministic;
                match *self {
                    #(#encode_arms)*
                }
                ::core::result::Result::Ok(())
            }

            #[inline]
            fn decode_oneof_arm(
                slot: &mut ::core::option::Option<Self>,
                fnum: u32,
                wt: u8,
                data: &[u8],
                pos: usize,
                depth: usize,
            ) -> #krate::Result<::core::option::Option<usize>> {
                let _ = (&slot, fnum, wt, data, pos, depth);
                match fnum {
                    #(#decode_arms)*
                    _ => ::core::result::Result::Ok(::core::option::Option::None),
                }
            }

            fn register_schema_fields(meta: &mut #krate::SchemaMeta) {
                let _ = &meta;
                #(#schema_field_stmts)*
            }

            fn register_schema_meta(
                meta: &mut #krate::SchemaMeta,
                active: &mut ::std::collections::HashSet<::core::any::TypeId>,
                depth: usize,
            ) {
                let _ = (&meta, &active, depth);
                #(#schema_child_stmts)*
            }

            fn is_schema_cyclic(
                active: &mut ::std::collections::HashSet<::core::any::TypeId>,
                depth: usize,
            ) -> bool {
                let _ = (&active, depth);
                #(#schema_cyclic_stmts)*
                false
            }

            fn register_value_schema_meta(&self, meta: &mut #krate::SchemaMeta, depth: usize) {
                let _ = (&meta, depth);
                if depth + 2 < #krate::MAX_NESTING_DEPTH {
                    match *self {
                        #(#value_schema_arms)*
                        #[allow(unreachable_patterns)]
                        _ => {}
                    }
                }
            }
        }
    })
}

fn compile_oneof_variant(var: &Variant, used_ids: &mut HashSet<u32>) -> Result<CompiledVariant> {
    let Fields::Unnamed(unnamed) = &var.fields else {
        return Err(Error::new_spanned(
            var,
            "#[derive(OmniBuf)] oneof enum variants must be single-element tuple variants `Variant(T)`",
        ));
    };
    if unnamed.unnamed.len() != 1 {
        return Err(Error::new_spanned(
            var,
            "#[derive(OmniBuf)] oneof enum variants must contain exactly 1 inner field",
        ));
    }
    let inner_ty = &unnamed.unnamed.first().unwrap().ty;
    let attr = parse_attrs_slice(&var.attrs)?;
    let id = attr.id.ok_or_else(|| {
        Error::new_spanned(
            var,
            "missing field number on oneof variant; add `#[omnibuf(id = N)]` or `#[prost(..., tag = \"N\")]`",
        )
    })?;
    validate_field_number(id, used_ids, var)?;

    let raw_vident = var.ident.to_string();
    let clean_vident = raw_vident.strip_prefix("r#").unwrap_or(&raw_vident);
    let schema_name = match attr.name {
        Some(n) => n,
        None => to_snake_case(clean_vident),
    };

    let shape = if is_vec_u8(inner_ty) && matches!(attr.wire.as_deref(), None | Some("bytes")) {
        OneofVariantShape::Scalar {
            scalar: ScalarType::Bytes,
            wire_wt: WIRE_BYTES,
        }
    } else if let Some(scalar) = parse_primitive_scalar(inner_ty) {
        let wire_wt = resolve_scalar_wire(scalar, attr.wire.as_deref(), inner_ty)?;
        OneofVariantShape::Scalar { scalar, wire_wt }
    } else if let Some(enum_ty) = unwrap_named_single(inner_ty, "EnumValue") {
        OneofVariantShape::BuffaEnum {
            enum_ty: Box::new(enum_ty.clone()),
        }
    } else if let Some(boxed_inner) = unwrap_named_single(inner_ty, "Box") {
        OneofVariantShape::SubMsg {
            ty: Box::new(boxed_inner.clone()),
            boxed: true,
        }
    } else {
        if let Some(w) = attr.wire.as_deref()
            && w != "submsg"
        {
            return Err(Error::new_spanned(
                inner_ty,
                format!("unsupported wire override {w:?} for message oneof variant"),
            ));
        }
        OneofVariantShape::SubMsg {
            ty: Box::new(inner_ty.clone()),
            boxed: false,
        }
    };

    Ok(CompiledVariant {
        ident: var.ident.clone(),
        id,
        schema_name,
        shape,
    })
}

fn parse_container_attrs(attrs: &[Attribute], ident: &Ident) -> Result<ContainerConfig> {
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
                        "unsupported #[omnibuf(...)] container attribute (expected `name = \"...\"` or `crate = \"...\"`)",
                    ));
                }
            }
        }
    }

    Ok(ContainerConfig {
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

fn parse_tags_list(s: &str, span_tokens: &impl quote::ToTokens) -> Result<Vec<u32>> {
    let mut tags = Vec::new();
    for part in s.split(',') {
        let t = part.trim();
        if t.is_empty() {
            continue;
        }
        let n = t.parse::<u32>().map_err(|e| {
            Error::new_spanned(span_tokens, format!("invalid oneof tag {t:?}: {e}"))
        })?;
        tags.push(n);
    }
    Ok(tags)
}

/// Parses `buffa` `/// Field N: \`name\`` doc comments first, then `#[prost(...)]`, and layers `#[omnibuf(...)]` on top.
fn parse_attrs_slice(attrs: &[Attribute]) -> Result<FieldAttr> {
    let mut out = FieldAttr::default();

    for attr in attrs {
        if attr.path().is_ident("doc") {
            parse_buffa_doc_attr(attr, &mut out);
        }
    }

    for attr in attrs {
        if attr.path().is_ident("prost") {
            parse_prost_attr(attr, &mut out)?;
        }
    }

    for attr in attrs {
        if attr.path().is_ident("omnibuf") {
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
                        } else if left.path.is_ident("tags") {
                            let s = lit_str_from_expr(&assign.right)?;
                            out.tags = parse_tags_list(&s, &assign.right)?;
                        } else if left.path.is_ident("name") {
                            out.name = Some(lit_str_from_expr(&assign.right)?);
                        } else if left.path.is_ident("wire") {
                            out.wire = Some(lit_str_from_expr(&assign.right)?);
                        } else if left.path.is_ident("key_wire") {
                            out.key_wire = Some(lit_str_from_expr(&assign.right)?);
                        } else if left.path.is_ident("val_wire") {
                            out.val_wire = Some(lit_str_from_expr(&assign.right)?);
                        } else if left.path.is_ident("oneof") {
                            let _ = lit_str_from_expr(&assign.right)?;
                            out.is_oneof = true;
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
                    Expr::Path(p) if p.path.is_ident("oneof") => {
                        out.is_oneof = true;
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

    Ok(out)
}

fn parse_buffa_doc_attr(attr: &Attribute, out: &mut FieldAttr) {
    if let Meta::NameValue(nv) = &attr.meta
        && let Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) = &nv.value
    {
        for line in s.value().lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("Field ")
                && let Some((num_str, name_part)) = rest.split_once(':')
                && let Ok(doc_id) = num_str.trim().parse::<u32>()
            {
                out.id = Some(doc_id);
                let name_trimmed = name_part.trim();
                if name_trimmed.len() >= 2
                    && name_trimmed.starts_with('`')
                    && name_trimmed.ends_with('`')
                {
                    out.name = Some(name_trimmed[1..name_trimmed.len() - 1].to_owned());
                }
            }
        }
    }
}

fn parse_prost_attr(attr: &Attribute, out: &mut FieldAttr) -> Result<()> {
    let nested = attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
    for meta in nested {
        match meta {
            Meta::NameValue(nv) if nv.path.is_ident("tag") => {
                out.id = Some(lit_u32_from_expr(&nv.value)?);
            }
            Meta::NameValue(nv) if nv.path.is_ident("tags") => {
                let s = lit_str_from_expr(&nv.value)?;
                out.tags = parse_tags_list(&s, &nv.value)?;
            }
            Meta::NameValue(nv) if nv.path.is_ident("oneof") => {
                out.is_oneof = true;
            }
            Meta::NameValue(nv) if nv.path.is_ident("enumeration") => {
                out.wire = Some("sint".to_owned());
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

fn validate_field_number(
    id: u32,
    used_ids: &mut HashSet<u32>,
    spanned: &impl quote::ToTokens,
) -> Result<()> {
    if id == 0 {
        return Err(Error::new_spanned(
            spanned,
            "field number 0 is reserved for inline SchemaMeta (Field #0)",
        ));
    }
    if id > MAX_FIELD_NUMBER {
        return Err(Error::new_spanned(
            spanned,
            format!("field number {id} exceeds MAX_FIELD_NUMBER ({MAX_FIELD_NUMBER})"),
        ));
    }
    if (19_000..=19_999).contains(&id) {
        return Err(Error::new_spanned(
            spanned,
            format!("field number {id} falls in Protobuf reserved range 19000..=19999"),
        ));
    }
    if !used_ids.insert(id) {
        return Err(Error::new_spanned(
            spanned,
            format!("duplicate OmniBuf field number {id}"),
        ));
    }
    Ok(())
}

fn compile_field(field: &Field, used_ids: &mut HashSet<u32>) -> Result<Option<CompiledField>> {
    let ident = field
        .ident
        .clone()
        .ok_or_else(|| Error::new_spanned(field, "expected named field"))?;
    let raw_ident = ident.to_string();
    let clean_ident = raw_ident.strip_prefix("r#").unwrap_or(&raw_ident);

    let attr = parse_attrs_slice(&field.attrs)?;
    if attr.skip {
        return Ok(None);
    }

    // Automatically skip buffa's internal metadata fields (`__buffa_unknown_fields`, `__buffa_cached_size`).
    if clean_ident.starts_with("__buffa_") && attr.id.is_none() && !attr.is_oneof {
        return Ok(None);
    }

    if attr.is_oneof || (attr.id.is_none() && is_buffa_oneof_option_type(&field.ty)) {
        let Some(inner_oneof_ty) = unwrap_named_single(&field.ty, "Option") else {
            return Err(Error::new_spanned(
                &field.ty,
                "oneof struct fields must have type `Option<OneofEnum>`",
            ));
        };
        for &tag in &attr.tags {
            validate_field_number(tag, used_ids, field)?;
        }
        let sort_id = attr
            .tags
            .iter()
            .copied()
            .min()
            .or(attr.id)
            .unwrap_or(u32::MAX - 1);
        return Ok(Some(CompiledField {
            ident,
            id: sort_id,
            schema_name: attr.name.unwrap_or_else(|| clean_ident.to_owned()),
            omit_empty: false,
            shape: FieldShape::Oneof {
                ty: Box::new(inner_oneof_ty.clone()),
                tags: attr.tags,
            },
        }));
    }

    let id = attr.id.ok_or_else(|| {
        Error::new_spanned(
            field,
            "missing OmniBuf field number; add `#[omnibuf(id = N)]` or `#[omnibuf(skip)]`",
        )
    })?;
    validate_field_number(id, used_ids, field)?;

    let schema_name = attr.name.unwrap_or_else(|| clean_ident.to_owned());
    let shape = classify_field_type(
        &field.ty,
        attr.wire.as_deref(),
        attr.key_wire.as_deref(),
        attr.val_wire.as_deref(),
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

fn first_generic_type(args: &PathArguments) -> Option<&Type> {
    if let PathArguments::AngleBracketed(ab) = args
        && let Some(GenericArgument::Type(inner)) = ab.args.first()
    {
        return Some(inner);
    }
    None
}

fn unwrap_named_single<'a>(ty: &'a Type, expected_name: &str) -> Option<&'a Type> {
    let (ident, args) = last_type_segment(ty)?;
    if ident == expected_name {
        single_generic_type(args)
    } else {
        None
    }
}

fn is_buffa_oneof_option_type(ty: &Type) -> bool {
    let Some(inner) = unwrap_named_single(ty, "Option") else {
        return false;
    };
    if let Type::Path(tp) = inner {
        let segs: Vec<_> = tp
            .path
            .segments
            .iter()
            .map(|s| s.ident.to_string())
            .collect();
        return segs
            .windows(2)
            .any(|w| w[0] == "__buffa" && w[1] == "oneof");
    }
    false
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

/// Validates and resolves `wire = "..."` overrides, rejecting narrowing or sign-corrupting combinations.
fn resolve_scalar_wire(
    scalar: ScalarType,
    wire_opt: Option<&str>,
    spanned: &impl quote::ToTokens,
) -> Result<u8> {
    match scalar {
        ScalarType::U8 | ScalarType::U16 | ScalarType::U32 => match wire_opt {
            None | Some("uint") => Ok(WIRE_UINT),
            Some("fixed32") => Ok(WIRE_FIXED32),
            Some("fixed64") => Ok(WIRE_FIXED64),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("incompatible wire override {other:?} for unsigned integer field"),
            )),
        },
        ScalarType::U64 | ScalarType::Usize => match wire_opt {
            None | Some("uint") => Ok(WIRE_UINT),
            Some("fixed64") => Ok(WIRE_FIXED64),
            Some("fixed32") => Err(Error::new_spanned(
                spanned,
                "narrowing wire = \"fixed32\" override is not allowed on 64-bit unsigned integer",
            )),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("incompatible wire override {other:?} for 64-bit unsigned integer field"),
            )),
        },
        ScalarType::I8 | ScalarType::I16 | ScalarType::I32 => match wire_opt {
            None | Some("sint") => Ok(WIRE_SINT),
            Some("sfixed32") => Ok(WIRE_SFIXED32),
            Some("sfixed64") => Ok(WIRE_SFIXED64),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("incompatible wire override {other:?} for signed integer field"),
            )),
        },
        ScalarType::I64 | ScalarType::Isize => match wire_opt {
            None | Some("sint") => Ok(WIRE_SINT),
            Some("sfixed64") => Ok(WIRE_SFIXED64),
            Some("sfixed32") => Err(Error::new_spanned(
                spanned,
                "narrowing wire = \"sfixed32\" override is not allowed on 64-bit signed integer",
            )),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("incompatible wire override {other:?} for 64-bit signed integer field"),
            )),
        },
        ScalarType::F32 => match wire_opt {
            None | Some("float32") => Ok(WIRE_FLOAT32),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("unsupported wire override {other:?} for f32"),
            )),
        },
        ScalarType::F64 => match wire_opt {
            None | Some("float64") => Ok(WIRE_FLOAT64),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("unsupported wire override {other:?} for f64"),
            )),
        },
        ScalarType::Bool => match wire_opt {
            None | Some("bool") => Ok(WIRE_BOOL_FALSE),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("unsupported wire override {other:?} for bool"),
            )),
        },
        ScalarType::String => match wire_opt {
            None | Some("string") => Ok(WIRE_STRING),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("unsupported wire override {other:?} for String"),
            )),
        },
        ScalarType::Bytes => match wire_opt {
            None | Some("bytes") => Ok(WIRE_BYTES),
            Some(other) => Err(Error::new_spanned(
                spanned,
                format!("unsupported wire override {other:?} for Vec<u8>"),
            )),
        },
    }
}

fn classify_elem_shape(ty: &Type, wire_opt: Option<&str>) -> Result<ElemShape> {
    if is_vec_u8(ty) && matches!(wire_opt, None | Some("bytes")) {
        return Ok(ElemShape::Scalar {
            scalar: ScalarType::Bytes,
            wire_wt: WIRE_BYTES,
        });
    }
    if let Some(scalar) = parse_primitive_scalar(ty) {
        let wire_wt = resolve_scalar_wire(scalar, wire_opt, ty)?;
        return Ok(ElemShape::Scalar { scalar, wire_wt });
    }
    if let Some((ident, args)) = last_type_segment(ty) {
        let name = ident.to_string();
        if name == "EnumValue"
            && let Some(enum_ty) = single_generic_type(args)
        {
            return Ok(ElemShape::BuffaEnum {
                enum_ty: Box::new(enum_ty.clone()),
            });
        }
        if name == "Vec"
            && let Some(inner) = single_generic_type(args)
        {
            let inner_shape = classify_elem_shape(inner, wire_opt)?;
            return Ok(ElemShape::Vec(Box::new(inner_shape)));
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
            let key_wt = resolve_scalar_wire(key_scalar, None, k_ty)?;
            let val_shape = classify_elem_shape(v_ty, wire_opt)?;
            return Ok(ElemShape::Map {
                is_btree,
                key_scalar,
                key_wt,
                val: Box::new(val_shape),
            });
        }
        if name == "Box"
            && let Some(boxed_inner) = single_generic_type(args)
        {
            return Ok(ElemShape::SubMsg {
                ty: Box::new(boxed_inner.clone()),
                boxed: true,
            });
        }
    }
    if let Some(w) = wire_opt
        && w != "submsg"
    {
        return Err(Error::new_spanned(
            ty,
            format!("incompatible wire override {w:?} for submessage type"),
        ));
    }
    Ok(ElemShape::SubMsg {
        ty: Box::new(ty.clone()),
        boxed: false,
    })
}

fn classify_field_type(
    ty: &Type,
    wire_opt: Option<&str>,
    key_wire_opt: Option<&str>,
    val_wire_opt: Option<&str>,
) -> Result<FieldShape> {
    if is_vec_u8(ty) && matches!(wire_opt, None | Some("bytes")) {
        return Ok(FieldShape::Scalar {
            scalar: ScalarType::Bytes,
            wire_wt: WIRE_BYTES,
        });
    }

    if let Some(scalar) = parse_primitive_scalar(ty) {
        let wire_wt = resolve_scalar_wire(scalar, wire_opt, ty)?;
        return Ok(FieldShape::Scalar { scalar, wire_wt });
    }

    if let Some((ident, args)) = last_type_segment(ty) {
        let name = ident.to_string();

        if name == "MessageField"
            && let Some(inner_msg) = first_generic_type(args)
        {
            return Ok(FieldShape::BuffaMessageField {
                ty: Box::new(inner_msg.clone()),
            });
        }

        if name == "EnumValue"
            && let Some(enum_ty) = single_generic_type(args)
        {
            return Ok(FieldShape::BuffaEnum {
                enum_ty: Box::new(enum_ty.clone()),
            });
        }

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
                let wire_wt = resolve_scalar_wire(scalar, wire_opt, inner)?;
                return Ok(FieldShape::OptScalar { scalar, wire_wt });
            }
            if let Some(enum_ty) = unwrap_named_single(inner, "EnumValue") {
                return Ok(FieldShape::OptBuffaEnum {
                    enum_ty: Box::new(enum_ty.clone()),
                });
            }
            if let Some(boxed_inner) = unwrap_named_single(inner, "Box") {
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
            let elem_shape = classify_elem_shape(elem_ty, wire_opt)?;
            return Ok(match elem_shape {
                ElemShape::Scalar { scalar, wire_wt } => FieldShape::ScalarVec {
                    scalar,
                    elem_wt: wire_wt,
                },
                ElemShape::BuffaEnum { enum_ty } => FieldShape::BuffaEnumVec { enum_ty },
                ElemShape::SubMsg { ty, boxed } => FieldShape::SubMsgVec { ty, boxed },
                other => FieldShape::NestedVec {
                    elem: Box::new(other),
                },
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
            let key_wt = resolve_scalar_wire(key_scalar, key_wire_opt, k_ty)?;
            let val_shape = classify_elem_shape(v_ty, val_wire_opt)?;

            return Ok(FieldShape::Map {
                is_btree,
                key_scalar,
                key_wt,
                val: Box::new(val_shape),
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

    if let Some(w) = wire_opt
        && w != "submsg"
    {
        return Err(Error::new_spanned(
            ty,
            format!("incompatible wire override {w:?} for submessage field"),
        ));
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

fn is_checked_narrow_int(scalar: ScalarType) -> bool {
    matches!(
        scalar,
        ScalarType::U8
            | ScalarType::U16
            | ScalarType::Usize
            | ScalarType::I8
            | ScalarType::I16
            | ScalarType::Isize
    )
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
            #krate::wire::append_bytes_elem(dst, (#item_ident).as_bytes());
        },
        (ScalarType::Bytes, _) => quote! {
            #krate::wire::append_bytes_elem(dst, (#item_ident).as_slice());
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

fn gen_convert_decoded_int(
    krate: &syn::Path,
    scalar: ScalarType,
    raw_expr: TokenStream2,
) -> TokenStream2 {
    let target_ty = scalar_rust_type_tokens(scalar);
    if is_checked_narrow_int(scalar) {
        quote! {
            <#target_ty as ::core::convert::TryFrom<_>>::try_from(#raw_expr)
                .map_err(|_| #krate::Error::parse("integer value out of range for target field type"))?
        }
    } else {
        quote!((#raw_expr) as #target_ty)
    }
}

fn gen_read_elem_payload_expr(krate: &syn::Path, scalar: ScalarType, wire_wt: u8) -> TokenStream2 {
    let target_ty = scalar_rust_type_tokens(scalar);
    let checked = is_checked_narrow_int(scalar);

    let map_int = |call: TokenStream2| {
        if checked {
            quote! {
                #call.and_then(|(v, np)| {
                    <#target_ty as ::core::convert::TryFrom<_>>::try_from(v)
                        .map(| cv | (cv, np))
                        .map_err(|_| #krate::Error::parse("integer element out of range for target type"))
                })
            }
        } else {
            quote! { #call.map(|(v, np)| (v as #target_ty, np)) }
        }
    };

    match (scalar, wire_wt) {
        (ScalarType::Bool, _) => quote! { #krate::codec::read_elem_bool(b, p) },
        (ScalarType::String, _) => quote! { #krate::codec::read_elem_string(b, p) },
        (ScalarType::Bytes, _) => quote! { #krate::codec::read_elem_bytes(b, p) },
        (ScalarType::F32, _) => quote! { #krate::codec::read_elem_float32(b, p) },
        (ScalarType::F64, _) => quote! { #krate::codec::read_elem_float64(b, p) },
        (_, WIRE_UINT) => map_int(quote!(#krate::codec::read_elem_uint(b, p))),
        (_, WIRE_SINT) => map_int(quote!(#krate::codec::read_elem_sint(b, p))),
        (_, WIRE_FIXED32) => map_int(quote!(#krate::codec::read_elem_fixed32(b, p))),
        (_, WIRE_FIXED64) => map_int(quote!(#krate::codec::read_elem_fixed64(b, p))),
        (_, WIRE_SFIXED32) => map_int(quote!(#krate::codec::read_elem_sfixed32(b, p))),
        (_, WIRE_SFIXED64) => map_int(quote!(#krate::codec::read_elem_sfixed64(b, p))),
        _ => unreachable!(),
    }
}

/// Generates a closure `|dst, val, det| -> Result<()>` for writing an arbitrary `ElemShape`.
fn gen_elem_writer_closure(krate: &syn::Path, shape: &ElemShape, depth_idx: usize) -> TokenStream2 {
    let val_ident = Ident::new(&format!("__ev{depth_idx}"), Span::call_site());
    let det_ident = Ident::new(&format!("__edet{depth_idx}"), Span::call_site());

    match shape {
        ElemShape::Scalar { scalar, wire_wt } => {
            let body = gen_write_elem_payload_expr(krate, *scalar, *wire_wt, &val_ident);
            quote! {
                |dst, #val_ident, #det_ident| {
                    let _ = #det_ident;
                    #body
                    ::core::result::Result::Ok(())
                }
            }
        }
        ElemShape::BuffaEnum { .. } => quote! {
            |dst, #val_ident, #det_ident| {
                let _ = #det_ident;
                #krate::wire::append_varint(
                    dst,
                    #krate::wire::encode_zigzag(i64::from((#val_ident).to_i32())),
                );
                ::core::result::Result::Ok(())
            }
        },
        ElemShape::SubMsg { boxed, .. } => {
            if *boxed {
                quote! {
                    |dst, #val_ident, #det_ident| {
                        #krate::codec::write_sub_msg_elem(dst, &**#val_ident, #det_ident)
                    }
                }
            } else {
                quote! {
                    |dst, #val_ident, #det_ident| {
                        #krate::codec::write_sub_msg_elem(dst, #val_ident, #det_ident)
                    }
                }
            }
        }
        ElemShape::Vec(inner) => {
            let inner_wt = inner.wire_type();
            let inner_closure = gen_elem_writer_closure(krate, inner, depth_idx + 1);
            quote! {
                |dst, #val_ident, #det_ident| {
                    #krate::codec::write_vec_elem(dst, #inner_wt, #val_ident, #det_ident, #inner_closure)
                }
            }
        }
        ElemShape::Map {
            is_btree,
            key_scalar,
            key_wt,
            val,
        } => {
            let k_ident = Ident::new(&format!("__mk{depth_idx}"), Span::call_site());
            let write_key = gen_write_elem_payload_expr(krate, *key_scalar, *key_wt, &k_ident);
            let val_wt = val.wire_type();
            let val_closure = gen_elem_writer_closure(krate, val, depth_idx + 1);
            let fn_ident = if *is_btree {
                quote!(write_btree_map_elem)
            } else {
                quote!(write_hash_map_elem)
            };
            quote! {
                |dst, #val_ident, #det_ident| {
                    #krate::codec::#fn_ident(
                        dst,
                        #krate::codec::MapWireTypes::new(#key_wt, #val_wt),
                        #val_ident,
                        #det_ident,
                        |dst, #k_ident| {
                            #write_key
                            ::core::result::Result::Ok(())
                        },
                        #val_closure,
                    )
                }
            }
        }
    }
}

/// Generates a closure `|b, p, d| -> Result<(T, usize)>` for reading an arbitrary `ElemShape`.
fn gen_elem_reader_closure(krate: &syn::Path, shape: &ElemShape) -> TokenStream2 {
    match shape {
        ElemShape::Scalar { scalar, wire_wt } => {
            let rv = gen_read_elem_payload_expr(krate, *scalar, *wire_wt);
            quote!(|b, p, _d| #rv)
        }
        ElemShape::BuffaEnum { enum_ty } => {
            quote!(|b, p, _d| #krate::codec::read_buffa_enum_elem::<#enum_ty>(b, p))
        }
        ElemShape::SubMsg { ty, boxed } => {
            if *boxed {
                quote!(|b, p, d| #krate::codec::read_box_sub_msg_elem::<#ty>(b, p, d))
            } else {
                quote!(|b, p, d| #krate::codec::read_sub_msg_elem::<#ty>(b, p, d))
            }
        }
        ElemShape::Vec(inner) => {
            let inner_wt = inner.wire_type();
            let inner_reader = gen_elem_reader_closure(krate, inner);
            quote! {
                |b, p, d| #krate::codec::read_vec_elem(b, p, d, #inner_wt, #inner_reader)
            }
        }
        ElemShape::Map {
            is_btree,
            key_scalar,
            key_wt,
            val,
        } => {
            let read_key = gen_read_elem_payload_expr(krate, *key_scalar, *key_wt);
            let val_wt = val.wire_type();
            let val_reader = gen_elem_reader_closure(krate, val);
            let fn_ident = if *is_btree {
                quote!(read_btree_map_elem)
            } else {
                quote!(read_hash_map_elem)
            };
            quote! {
                |b, p, d| #krate::codec::#fn_ident(
                    b,
                    p,
                    d,
                    #key_wt,
                    #val_wt,
                    |b, p| #read_key,
                    #val_reader,
                )
            }
        }
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
        FieldShape::BuffaEnum { .. } => quote! {
            #krate::codec::write_buffa_enum_field(dst, #f_id, &self.#f_ident);
        },
        FieldShape::OptBuffaEnum { .. } => {
            return quote! {
                if let ::core::option::Option::Some(ref val) = self.#f_ident {
                    #krate::codec::write_buffa_enum_field(dst, #f_id, val);
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
        FieldShape::BuffaMessageField { .. } => {
            return quote! {
                #krate::codec::write_buffa_message_field(dst, #f_id, &self.#f_ident, deterministic)?;
            };
        }
        FieldShape::ScalarVec { scalar, elem_wt } => {
            let item_ident = Ident::new("__item", Span::call_site());
            if *elem_wt == WIRE_UINT {
                quote! {
                    #krate::codec::write_varint_vec_field(
                        dst,
                        #f_id,
                        #elem_wt,
                        &self.#f_ident,
                        |#item_ident| (*#item_ident) as u64,
                    )?;
                }
            } else if *elem_wt == WIRE_SINT {
                quote! {
                    #krate::codec::write_varint_vec_field(
                        dst,
                        #f_id,
                        #elem_wt,
                        &self.#f_ident,
                        |#item_ident| #krate::wire::encode_zigzag((*#item_ident) as i64),
                    )?;
                }
            } else {
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
        }
        FieldShape::BuffaEnumVec { .. } => quote! {
            #krate::codec::write_buffa_enum_vec_field(dst, #f_id, &self.#f_ident)?;
        },
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
        FieldShape::NestedVec { elem } => {
            let elem_wt = elem.wire_type();
            let elem_writer = gen_elem_writer_closure(krate, elem, 0);
            quote! {
                #krate::codec::write_vec_field(
                    dst,
                    #f_id,
                    #elem_wt,
                    &self.#f_ident,
                    deterministic,
                    #elem_writer,
                )?;
            }
        }
        FieldShape::Map {
            is_btree,
            key_scalar,
            key_wt,
            val,
        } => {
            let k_ident = Ident::new("__k", Span::call_site());
            let write_key = gen_write_elem_payload_expr(krate, *key_scalar, *key_wt, &k_ident);
            let val_wt = val.wire_type();
            let val_writer = gen_elem_writer_closure(krate, val, 0);
            let fn_ident = if *is_btree {
                quote!(write_btree_map_field)
            } else {
                quote!(write_hash_map_field)
            };
            quote! {
                #krate::codec::#fn_ident(
                    dst,
                    #f_id,
                    #krate::codec::MapWireTypes::new(#key_wt, #val_wt),
                    &self.#f_ident,
                    deterministic,
                    |dst, #k_ident| {
                        #write_key
                        ::core::result::Result::Ok(())
                    },
                    #val_writer,
                )?;
            }
        }
        FieldShape::Oneof { ty, .. } => {
            return quote! {
                if let ::core::option::Option::Some(ref __active) = self.#f_ident {
                    <#ty as #krate::codec::Oneof>::encode_oneof(__active, dst, deterministic)?;
                }
            };
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

const fn tag_varint_width(field_num: u32, wt: u8) -> usize {
    let tag = ((field_num as u64) << 4) | ((wt & 0x0F) as u64);
    if tag <= 127 {
        1
    } else if tag <= 16_383 {
        2
    } else if tag <= 536_870_911 {
        4
    } else {
        9
    }
}

fn gen_scalar_min_size_expr(
    krate: &syn::Path,
    f_id: u32,
    scalar: ScalarType,
    wire_wt: u8,
    val_expr: TokenStream2,
) -> TokenStream2 {
    let tw = tag_varint_width(f_id, wire_wt);
    match (scalar, wire_wt) {
        (ScalarType::Bool, _) => quote!(#tw),
        (ScalarType::String, _) => quote!({
            let __l = (#val_expr).len();
            #tw + #krate::wire::varint_len(__l as u64) + __l
        }),
        (ScalarType::Bytes, _) => quote!({
            let __l = (#val_expr).len();
            #tw + #krate::wire::varint_len(__l as u64) + __l
        }),
        (_, WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32) => quote!(#tw + 4usize),
        (_, WIRE_FIXED64 | WIRE_SFIXED64 | WIRE_FLOAT64) => quote!(#tw + 8usize),
        _ => quote!(#tw + 1usize),
    }
}

fn gen_min_wire_size_field(krate: &syn::Path, cf: &CompiledField) -> TokenStream2 {
    let f_ident = &cf.ident;
    let f_id = cf.id;

    let add_stmt = match &cf.shape {
        FieldShape::Scalar { scalar, wire_wt } => {
            let expr =
                gen_scalar_min_size_expr(krate, f_id, *scalar, *wire_wt, quote!(&self.#f_ident));
            quote! { __sz += #expr; }
        }
        FieldShape::OptScalar { scalar, wire_wt } => {
            let expr = gen_scalar_min_size_expr(krate, f_id, *scalar, *wire_wt, quote!(__val));
            return quote! {
                if let ::core::option::Option::Some(ref __val) = self.#f_ident {
                    let _ = __val;
                    __sz += #expr;
                }
            };
        }
        FieldShape::BuffaEnum { .. } => {
            let tw = tag_varint_width(f_id, WIRE_SINT);
            quote! { __sz += #tw + 1usize; }
        }
        FieldShape::OptBuffaEnum { .. } => {
            let tw = tag_varint_width(f_id, WIRE_SINT);
            return quote! {
                if self.#f_ident.is_some() {
                    __sz += #tw + 1usize;
                }
            };
        }
        FieldShape::SubMsg { ty, boxed } => {
            let tw = tag_varint_width(f_id, WIRE_SUB_MSG);
            let sub_ref = if *boxed {
                quote!(&*self.#f_ident)
            } else {
                quote!(&self.#f_ident)
            };
            quote! {
                let __sub = if depth_rem > 0 {
                    <#ty as #krate::Message>::min_wire_size_bounded(#sub_ref, depth_rem - 1)
                } else {
                    0usize
                };
                __sz += #tw + #krate::wire::container_len_width(__sub) + __sub;
            }
        }
        FieldShape::OptSubMsg { ty, boxed } => {
            let tw = tag_varint_width(f_id, WIRE_SUB_MSG);
            let sub_ref = if *boxed { quote!(&**__s) } else { quote!(__s) };
            return quote! {
                if let ::core::option::Option::Some(ref __s) = self.#f_ident {
                    let __sub = if depth_rem > 0 {
                        <#ty as #krate::Message>::min_wire_size_bounded(#sub_ref, depth_rem - 1)
                    } else {
                        0usize
                    };
                    __sz += #tw + #krate::wire::container_len_width(__sub) + __sub;
                }
            };
        }
        FieldShape::BuffaMessageField { .. } => {
            return quote! {
                __sz += #krate::codec::buffa_message_field_min_wire_size(#f_id, &self.#f_ident, depth_rem);
            };
        }
        FieldShape::ScalarVec { scalar, elem_wt } => {
            let tw = tag_varint_width(f_id, WIRE_ARRAY);
            let elems_expr = match (scalar, *elem_wt) {
                (ScalarType::String, _) | (ScalarType::Bytes, _) => quote! {
                    self.#f_ident
                        .iter()
                        .map(|__x| {
                            let __l = __x.len();
                            #krate::wire::varint_len(__l as u64) + __l
                        })
                        .sum::<usize>()
                },
                (_, WIRE_FIXED32 | WIRE_SFIXED32 | WIRE_FLOAT32) => quote!(__c * 4usize),
                (_, WIRE_FIXED64 | WIRE_SFIXED64 | WIRE_FLOAT64) => quote!(__c * 8usize),
                _ => quote!(__c),
            };
            quote! {
                let __c = self.#f_ident.len();
                let __b = 1usize + #krate::wire::varint_len(__c as u64) + (#elems_expr);
                __sz += #tw + #krate::wire::container_len_width(__b) + __b;
            }
        }
        FieldShape::BuffaEnumVec { .. } => {
            let tw = tag_varint_width(f_id, WIRE_ARRAY);
            quote! {
                let __c = self.#f_ident.len();
                let __b = 1usize + #krate::wire::varint_len(__c as u64) + __c;
                __sz += #tw + #krate::wire::container_len_width(__b) + __b;
            }
        }
        FieldShape::SubMsgVec { ty, boxed } => {
            let tw = tag_varint_width(f_id, WIRE_ARRAY);
            let elem_ref = if *boxed { quote!(&**__m) } else { quote!(__m) };
            quote! {
                let __c = self.#f_ident.len();
                let __eb: usize = if depth_rem > 0 {
                    self.#f_ident
                        .iter()
                        .map(|__m| {
                            let __s = <#ty as #krate::Message>::min_wire_size_bounded(#elem_ref, depth_rem - 1);
                            #krate::wire::container_len_width(__s) + __s
                        })
                        .sum()
                } else {
                    __c * 2usize
                };
                let __b = 1usize + #krate::wire::varint_len(__c as u64) + __eb;
                __sz += #tw + #krate::wire::container_len_width(__b) + __b;
            }
        }
        FieldShape::NestedVec { .. } => {
            let tw = tag_varint_width(f_id, WIRE_ARRAY);
            quote! {
                let __c = self.#f_ident.len();
                let __b = 1usize + #krate::wire::varint_len(__c as u64) + __c * 2usize;
                __sz += #tw + #krate::wire::container_len_width(__b) + __b;
            }
        }
        FieldShape::Map { .. } => {
            let tw = tag_varint_width(f_id, WIRE_MAP);
            quote! {
                let __c = self.#f_ident.len();
                let __b = 2usize + #krate::wire::varint_len(__c as u64) + __c * 2usize;
                __sz += #tw + #krate::wire::container_len_width(__b) + __b;
            }
        }
        FieldShape::Oneof { ty, .. } => {
            return quote! {
                if let ::core::option::Option::Some(ref __active) = self.#f_ident {
                    __sz += <#ty as #krate::codec::Oneof>::min_wire_size_bounded(__active, depth_rem);
                }
            };
        }
    };

    if cf.omit_empty {
        quote! {
            if !#krate::codec::IsEmpty::is_omnibuf_empty(&self.#f_ident) {
                #add_stmt
            }
        }
    } else {
        add_stmt
    }
}

fn gen_decode_scalar_value_expr(
    krate: &syn::Path,
    scalar: ScalarType,
    wire_wt: u8,
) -> TokenStream2 {
    match (scalar, wire_wt) {
        (ScalarType::String, _) => quote!(::std::borrow::ToOwned::to_owned(dec.read_str()?)),
        (ScalarType::Bytes, _) => quote!(dec.read_bytes()?.to_vec()),
        (ScalarType::F32, _) => quote!(dec.read_float32()?),
        (ScalarType::F64, _) => quote!(dec.read_float64()?),
        (_, WIRE_UINT) => gen_convert_decoded_int(krate, scalar, quote!(dec.read_uint()?)),
        (_, WIRE_SINT) => gen_convert_decoded_int(krate, scalar, quote!(dec.read_sint()?)),
        (_, WIRE_FIXED32) => gen_convert_decoded_int(krate, scalar, quote!(dec.read_fixed32()?)),
        (_, WIRE_FIXED64) => gen_convert_decoded_int(krate, scalar, quote!(dec.read_fixed64()?)),
        (_, WIRE_SFIXED32) => gen_convert_decoded_int(krate, scalar, quote!(dec.read_sfixed32()?)),
        (_, WIRE_SFIXED64) => gen_convert_decoded_int(krate, scalar, quote!(dec.read_sfixed64()?)),
        _ => unreachable!(),
    }
}

fn gen_fast_decode_stmt(krate: &syn::Path, cf: &CompiledField) -> Option<TokenStream2> {
    let f_ident = &cf.ident;
    let f_id = cf.id;

    let wrap_tag = |wt: u8, body: TokenStream2| -> Option<TokenStream2> {
        let tag = (u64::from(f_id) << 4) | u64::from(wt);
        if tag <= 127 {
            let b = ((tag as u8) << 1) | 1;
            Some(quote! {
                if dec.consume_tag1(#b) {
                    #body
                }
            })
        } else if tag <= 16_383 {
            let u = ((tag as u16) << 2) | 2;
            Some(quote! {
                if dec.consume_tag2(#u) {
                    #body
                }
            })
        } else {
            None
        }
    };

    match &cf.shape {
        FieldShape::Scalar {
            scalar: ScalarType::Bool,
            ..
        } => {
            let tf = (u64::from(f_id) << 4) | u64::from(WIRE_BOOL_FALSE);
            let tt = (u64::from(f_id) << 4) | 3u64;
            if tt <= 127 {
                let bf = ((tf as u8) << 1) | 1;
                let bt = ((tt as u8) << 1) | 1;
                Some(quote! {
                    if let ::core::option::Option::Some(__b) = dec.consume_bool_tag1(#bf, #bt) {
                        self.#f_ident = __b;
                    }
                })
            } else if tt <= 16_383 {
                let uf = ((tf as u16) << 2) | 2;
                let ut = ((tt as u16) << 2) | 2;
                Some(quote! {
                    if let ::core::option::Option::Some(__b) = dec.consume_bool_tag2(#uf, #ut) {
                        self.#f_ident = __b;
                    }
                })
            } else {
                None
            }
        }
        FieldShape::OptScalar {
            scalar: ScalarType::Bool,
            ..
        } => {
            let tf = (u64::from(f_id) << 4) | u64::from(WIRE_BOOL_FALSE);
            let tt = (u64::from(f_id) << 4) | 3u64;
            if tt <= 127 {
                let bf = ((tf as u8) << 1) | 1;
                let bt = ((tt as u8) << 1) | 1;
                Some(quote! {
                    if let ::core::option::Option::Some(__b) = dec.consume_bool_tag1(#bf, #bt) {
                        self.#f_ident = ::core::option::Option::Some(__b);
                    }
                })
            } else if tt <= 16_383 {
                let uf = ((tf as u16) << 2) | 2;
                let ut = ((tt as u16) << 2) | 2;
                Some(quote! {
                    if let ::core::option::Option::Some(__b) = dec.consume_bool_tag2(#uf, #ut) {
                        self.#f_ident = ::core::option::Option::Some(__b);
                    }
                })
            } else {
                None
            }
        }
        FieldShape::Scalar {
            scalar: ScalarType::String,
            wire_wt,
        } => wrap_tag(
            *wire_wt,
            quote! {
                let s = dec.read_str()?;
                #krate::codec::assign_str(&mut self.#f_ident, s);
            },
        ),
        FieldShape::Scalar {
            scalar: ScalarType::Bytes,
            wire_wt,
        } => wrap_tag(
            *wire_wt,
            quote! {
                let b = dec.read_bytes()?;
                #krate::codec::assign_bytes(&mut self.#f_ident, b);
            },
        ),
        FieldShape::Scalar { scalar, wire_wt } => {
            let read_val = gen_decode_scalar_value_expr(krate, *scalar, *wire_wt);
            wrap_tag(*wire_wt, quote! { self.#f_ident = #read_val; })
        }
        FieldShape::OptScalar { scalar, wire_wt } => {
            let read_val = gen_decode_scalar_value_expr(krate, *scalar, *wire_wt);
            wrap_tag(
                *wire_wt,
                quote! { self.#f_ident = ::core::option::Option::Some(#read_val); },
            )
        }
        FieldShape::BuffaEnum { enum_ty } => wrap_tag(
            WIRE_SINT,
            quote! {
                let pos = dec.position();
                let (v, next_pos) = #krate::codec::read_buffa_enum_elem::<#enum_ty>(dec.data(), pos)?;
                self.#f_ident = v;
                dec.set_position(next_pos);
            },
        ),
        FieldShape::OptBuffaEnum { enum_ty } => wrap_tag(
            WIRE_SINT,
            quote! {
                let pos = dec.position();
                let (v, next_pos) = #krate::codec::read_buffa_enum_elem::<#enum_ty>(dec.data(), pos)?;
                self.#f_ident = ::core::option::Option::Some(v);
                dec.set_position(next_pos);
            },
        ),
        FieldShape::SubMsg { boxed, .. } => {
            let target = if *boxed {
                quote!(&mut *self.#f_ident)
            } else {
                quote!(&mut self.#f_ident)
            };
            wrap_tag(
                WIRE_SUB_MSG,
                quote! {
                    let sub_bytes = dec.read_container(0)?;
                    (#target).decode_omnibuf_at_depth(sub_bytes, depth + 1, true)?;
                },
            )
        }
        FieldShape::OptSubMsg { boxed, .. } => {
            let fn_ident = if *boxed {
                quote!(read_opt_box_sub_msg_field)
            } else {
                quote!(read_opt_sub_msg_field)
            };
            wrap_tag(
                WIRE_SUB_MSG,
                quote! {
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        true,
                    )?;
                    dec.set_position(next_pos);
                },
            )
        }
        FieldShape::BuffaMessageField { .. } => wrap_tag(
            WIRE_SUB_MSG,
            quote! {
                let pos = dec.position();
                let next_pos = #krate::codec::read_buffa_message_field(
                    &mut self.#f_ident,
                    dec.data(),
                    pos,
                    depth,
                    true,
                )?;
                dec.set_position(next_pos);
            },
        ),
        FieldShape::ScalarVec {
            scalar: ScalarType::U32,
            elem_wt: WIRE_UINT,
        } => wrap_tag(
            WIRE_ARRAY,
            quote! {
                let pos = dec.position();
                let next_pos = #krate::codec::read_uint32_vec_field(
                    &mut self.#f_ident,
                    dec.data(),
                    pos,
                    depth,
                    false,
                )?;
                dec.set_position(next_pos);
            },
        ),
        FieldShape::ScalarVec {
            scalar: ScalarType::U64,
            elem_wt: WIRE_UINT,
        } => wrap_tag(
            WIRE_ARRAY,
            quote! {
                let pos = dec.position();
                let next_pos = #krate::codec::read_uint64_vec_field(
                    &mut self.#f_ident,
                    dec.data(),
                    pos,
                    depth,
                    false,
                )?;
                dec.set_position(next_pos);
            },
        ),
        FieldShape::ScalarVec {
            scalar: ScalarType::String,
            ..
        } => wrap_tag(
            WIRE_ARRAY,
            quote! {
                let pos = dec.position();
                let next_pos = #krate::codec::read_string_vec_field(
                    &mut self.#f_ident,
                    dec.data(),
                    pos,
                    depth,
                    false,
                )?;
                dec.set_position(next_pos);
            },
        ),
        FieldShape::ScalarVec { scalar, elem_wt } => {
            let read_elem = gen_read_elem_payload_expr(krate, *scalar, *elem_wt);
            wrap_tag(
                WIRE_ARRAY,
                quote! {
                    let pos = dec.position();
                    let next_pos = #krate::codec::read_scalar_vec_field(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        #elem_wt,
                        false,
                        |b, p| #read_elem,
                    )?;
                    dec.set_position(next_pos);
                },
            )
        }
        FieldShape::BuffaEnumVec { enum_ty } => wrap_tag(
            WIRE_ARRAY,
            quote! {
                let pos = dec.position();
                let next_pos = #krate::codec::read_scalar_vec_field(
                    &mut self.#f_ident,
                    dec.data(),
                    pos,
                    depth,
                    #WIRE_SINT,
                    false,
                    |b, p| #krate::codec::read_buffa_enum_elem::<#enum_ty>(b, p),
                )?;
                dec.set_position(next_pos);
            },
        ),
        FieldShape::SubMsgVec { boxed, .. } => {
            let fn_ident = if *boxed {
                quote!(read_box_sub_msg_vec_field)
            } else {
                quote!(read_sub_msg_vec_field)
            };
            wrap_tag(
                WIRE_ARRAY,
                quote! {
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        false,
                    )?;
                    dec.set_position(next_pos);
                },
            )
        }
        FieldShape::NestedVec { elem } => {
            let elem_wt = elem.wire_type();
            let elem_reader = gen_elem_reader_closure(krate, elem);
            wrap_tag(
                WIRE_ARRAY,
                quote! {
                    let pos = dec.position();
                    let next_pos = #krate::codec::read_vec_field(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        #elem_wt,
                        false,
                        #elem_reader,
                    )?;
                    dec.set_position(next_pos);
                },
            )
        }
        FieldShape::Map {
            is_btree,
            key_scalar,
            key_wt,
            val,
        } => {
            let read_key = gen_read_elem_payload_expr(krate, *key_scalar, *key_wt);
            let val_wt = val.wire_type();
            let val_reader = gen_elem_reader_closure(krate, val);
            let fn_ident = if *is_btree {
                quote!(read_btree_map_field)
            } else {
                quote!(read_hash_map_field)
            };
            wrap_tag(
                WIRE_MAP,
                quote! {
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        #krate::codec::MapReadCtx {
                            data: dec.data(),
                            pos,
                            depth,
                            wire_types: #krate::codec::MapWireTypes::new(#key_wt, #val_wt),
                            reset: false,
                        },
                        |b, p| #read_key,
                        #val_reader,
                    )?;
                    dec.set_position(next_pos);
                },
            )
        }
        FieldShape::Oneof { .. } => None,
    }
}

fn gen_decode_arm(krate: &syn::Path, cf: &CompiledField) -> TokenStream2 {
    let f_ident = &cf.ident;
    let f_id = cf.id;

    match &cf.shape {
        FieldShape::Scalar {
            scalar: ScalarType::Bool,
            ..
        } => {
            quote! {
                #f_id if wt == #krate::wire::WIRE_BOOL_FALSE || wt == #krate::wire::WIRE_BOOL_TRUE => {
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
                    self.#f_ident = ::core::option::Option::Some(wt == #krate::wire::WIRE_BOOL_TRUE);
                }
            }
        }
        FieldShape::Scalar {
            scalar: ScalarType::String,
            wire_wt,
        } => {
            quote! {
                #f_id if wt == #wire_wt => {
                    let s = dec.read_str()?;
                    #krate::codec::assign_str(&mut self.#f_ident, s);
                }
            }
        }
        FieldShape::Scalar {
            scalar: ScalarType::Bytes,
            wire_wt,
        } => {
            quote! {
                #f_id if wt == #wire_wt => {
                    let b = dec.read_bytes()?;
                    #krate::codec::assign_bytes(&mut self.#f_ident, b);
                }
            }
        }
        FieldShape::Scalar { scalar, wire_wt } => {
            let read_val = gen_decode_scalar_value_expr(krate, *scalar, *wire_wt);
            quote! {
                #f_id if wt == #wire_wt => {
                    self.#f_ident = #read_val;
                }
            }
        }
        FieldShape::OptScalar { scalar, wire_wt } => {
            let read_val = gen_decode_scalar_value_expr(krate, *scalar, *wire_wt);
            quote! {
                #f_id if wt == #wire_wt => {
                    self.#f_ident = ::core::option::Option::Some(#read_val);
                }
            }
        }
        FieldShape::BuffaEnum { enum_ty } => {
            quote! {
                #f_id if wt == #WIRE_SINT => {
                    let pos = dec.position();
                    let (v, next_pos) = #krate::codec::read_buffa_enum_elem::<#enum_ty>(dec.data(), pos)?;
                    self.#f_ident = v;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::OptBuffaEnum { enum_ty } => {
            quote! {
                #f_id if wt == #WIRE_SINT => {
                    let pos = dec.position();
                    let (v, next_pos) = #krate::codec::read_buffa_enum_elem::<#enum_ty>(dec.data(), pos)?;
                    self.#f_ident = ::core::option::Option::Some(v);
                    dec.set_position(next_pos);
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
                    let sub_bytes = dec.read_container(0)?;
                    (#target).decode_omnibuf_at_depth(sub_bytes, depth + 1, true)?;
                }
            }
        }
        FieldShape::OptSubMsg { boxed, .. } => {
            let fn_ident = if *boxed {
                quote!(read_opt_box_sub_msg_field)
            } else {
                quote!(read_opt_sub_msg_field)
            };
            quote! {
                #f_id if wt == #WIRE_SUB_MSG => {
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        true,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::BuffaMessageField { .. } => {
            quote! {
                #f_id if wt == #WIRE_SUB_MSG => {
                    let pos = dec.position();
                    let next_pos = #krate::codec::read_buffa_message_field(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        true,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::ScalarVec { scalar, elem_wt } => {
            let read_elem = gen_read_elem_payload_expr(krate, *scalar, *elem_wt);
            quote! {
                #f_id if wt == #WIRE_ARRAY => {
                    let pos = dec.position();
                    let next_pos = #krate::codec::read_scalar_vec_field(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        #elem_wt,
                        false,
                        |b, p| #read_elem,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::BuffaEnumVec { enum_ty } => {
            quote! {
                #f_id if wt == #WIRE_ARRAY => {
                    let pos = dec.position();
                    let next_pos = #krate::codec::read_scalar_vec_field(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        #WIRE_SINT,
                        false,
                        |b, p| #krate::codec::read_buffa_enum_elem::<#enum_ty>(b, p),
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
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        false,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::NestedVec { elem } => {
            let elem_wt = elem.wire_type();
            let elem_reader = gen_elem_reader_closure(krate, elem);
            quote! {
                #f_id if wt == #WIRE_ARRAY => {
                    let pos = dec.position();
                    let next_pos = #krate::codec::read_vec_field(
                        &mut self.#f_ident,
                        dec.data(),
                        pos,
                        depth,
                        #elem_wt,
                        false,
                        #elem_reader,
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
            let val_wt = val.wire_type();
            let val_reader = gen_elem_reader_closure(krate, val);
            let fn_ident = if *is_btree {
                quote!(read_btree_map_field)
            } else {
                quote!(read_hash_map_field)
            };
            quote! {
                #f_id if wt == #WIRE_MAP => {
                    let pos = dec.position();
                    let next_pos = #krate::codec::#fn_ident(
                        &mut self.#f_ident,
                        #krate::codec::MapReadCtx {
                            data: dec.data(),
                            pos,
                            depth,
                            wire_types: #krate::codec::MapWireTypes::new(#key_wt, #val_wt),
                            reset: false,
                        },
                        |b, p| #read_key,
                        #val_reader,
                    )?;
                    dec.set_position(next_pos);
                }
            }
        }
        FieldShape::Oneof { .. } => unreachable!(),
    }
}

fn gen_is_empty_check(krate: &syn::Path, cf: &CompiledField) -> TokenStream2 {
    let f_ident = &cf.ident;
    if matches!(cf.shape, FieldShape::Oneof { .. }) {
        quote! {
            if self.#f_ident.is_some() {
                return false;
            }
        }
    } else {
        quote! {
            if !#krate::codec::IsEmpty::is_omnibuf_empty(&self.#f_ident) {
                return false;
            }
        }
    }
}

fn gen_clear_field(krate: &syn::Path, cf: &CompiledField) -> TokenStream2 {
    let f_ident = &cf.ident;
    match &cf.shape {
        FieldShape::Scalar {
            scalar: ScalarType::String | ScalarType::Bytes,
            ..
        } => quote! { self.#f_ident.clear(); },
        FieldShape::ScalarVec { .. }
        | FieldShape::BuffaEnumVec { .. }
        | FieldShape::SubMsgVec { .. }
        | FieldShape::NestedVec { .. }
        | FieldShape::Map { .. } => {
            quote! { if !self.#f_ident.is_empty() { self.#f_ident.clear(); } }
        }
        FieldShape::Scalar { .. }
        | FieldShape::BuffaEnum { .. }
        | FieldShape::BuffaMessageField { .. } => {
            quote! { self.#f_ident = ::core::default::Default::default(); }
        }
        FieldShape::OptScalar { .. }
        | FieldShape::OptBuffaEnum { .. }
        | FieldShape::OptSubMsg { .. }
        | FieldShape::Oneof { .. } => {
            quote! { if self.#f_ident.is_some() { self.#f_ident = ::core::option::Option::None; } }
        }
        FieldShape::SubMsg { boxed, .. } => {
            if *boxed {
                quote! { #krate::Message::clear_omnibuf(&mut *self.#f_ident); }
            } else {
                quote! { #krate::Message::clear_omnibuf(&mut self.#f_ident); }
            }
        }
    }
}

fn gen_elem_value_schema_stmt(
    krate: &syn::Path,
    shape: &ElemShape,
    val_expr: TokenStream2,
    depth_idx: usize,
) -> TokenStream2 {
    match shape {
        ElemShape::Scalar { .. } | ElemShape::BuffaEnum { .. } => quote! {},
        ElemShape::SubMsg { ty, boxed } => {
            let sub_ref = if *boxed {
                quote!(&**#val_expr)
            } else {
                val_expr
            };
            quote! {
                if let ::core::option::Option::Some(__cm) = <#ty as #krate::Message>::build_value_schema_meta(#sub_ref, depth + 2) {
                    __child = ::core::option::Option::Some(#krate::field0::merge_schema_meta(__child, __cm));
                }
            }
        }
        ElemShape::Vec(inner) => {
            let item_ident = Ident::new(&format!("__vs_item_{depth_idx}"), Span::call_site());
            let inner_stmt =
                gen_elem_value_schema_stmt(krate, inner, quote!(#item_ident), depth_idx + 1);
            quote! {
                for #item_ident in #val_expr {
                    #inner_stmt
                }
            }
        }
        ElemShape::Map { val, .. } => {
            let val_ident = Ident::new(&format!("__vs_val_{depth_idx}"), Span::call_site());
            let inner_stmt =
                gen_elem_value_schema_stmt(krate, val, quote!(#val_ident), depth_idx + 1);
            quote! {
                for #val_ident in (#val_expr).values() {
                    #inner_stmt
                }
            }
        }
    }
}

#[allow(clippy::type_complexity)]
fn gen_schema_parts(
    krate: &syn::Path,
    cf: &CompiledField,
) -> (
    Option<TokenStream2>,
    Option<TokenStream2>,
    Option<TokenStream2>,
    Option<TokenStream2>,
) {
    let f_id = cf.id;
    let f_name = &cf.schema_name;
    let f_ident = &cf.ident;

    if let FieldShape::Oneof { ty, .. } = &cf.shape {
        let oneof_fields = quote! {
            <#ty as #krate::codec::Oneof>::register_schema_fields(&mut meta);
        };
        let oneof_children = quote! {
            <#ty as #krate::codec::Oneof>::register_schema_meta(&mut meta, active, depth);
        };
        let oneof_cyclic = quote! {
            if <#ty as #krate::codec::Oneof>::is_schema_cyclic(active, depth) {
                active.remove(&type_id);
                return true;
            }
        };
        let oneof_value = quote! {
            if let ::core::option::Option::Some(ref __ov) = self.#f_ident {
                <#ty as #krate::codec::Oneof>::register_value_schema_meta(__ov, &mut meta, depth);
            }
        };
        return (
            Some(oneof_fields),
            Some(oneof_children),
            Some(oneof_cyclic),
            Some(oneof_value),
        );
    }

    let insert_name = Some(quote! {
        meta.fields.insert(#f_id, ::std::string::String::from(#f_name));
    });

    let child_ty: Option<&Type> = match &cf.shape {
        FieldShape::SubMsg { ty, .. }
        | FieldShape::OptSubMsg { ty, .. }
        | FieldShape::BuffaMessageField { ty }
        | FieldShape::SubMsgVec { ty, .. } => Some(ty),
        FieldShape::NestedVec { elem } => elem.leaf_submsg_type(),
        FieldShape::Map { val, .. } => val.leaf_submsg_type(),
        _ => None,
    };

    let child_stmt = child_ty.map(|ty| {
        quote! {
            if let ::core::option::Option::Some(child) = <#ty as #krate::Message>::build_schema_meta(active, depth + 2) {
                meta.children.insert(#f_id, child);
            }
        }
    });

    let cyclic_stmt = child_ty.map(|ty| {
        quote! {
            if <#ty as #krate::Message>::is_schema_cyclic(active, depth + 2) {
                active.remove(&type_id);
                return true;
            }
        }
    });

    let value_stmt = match &cf.shape {
        FieldShape::SubMsg { ty, boxed } => {
            let sub_ref = if *boxed {
                quote!(&*self.#f_ident)
            } else {
                quote!(&self.#f_ident)
            };
            let insert_expr = quote! {
                if let ::core::option::Option::Some(__cm) = <#ty as #krate::Message>::build_value_schema_meta(#sub_ref, depth + 2) {
                    meta.children.insert(#f_id, __cm);
                }
            };
            if cf.omit_empty {
                Some(quote! {
                    if !#krate::codec::IsEmpty::is_omnibuf_empty(&self.#f_ident) {
                        #insert_expr
                    }
                })
            } else {
                Some(insert_expr)
            }
        }
        FieldShape::OptSubMsg { ty, boxed } => {
            let sub_ref = if *boxed {
                quote!(&**__sub)
            } else {
                quote!(__sub)
            };
            Some(quote! {
                if let ::core::option::Option::Some(ref __sub) = self.#f_ident {
                    if let ::core::option::Option::Some(__cm) = <#ty as #krate::Message>::build_value_schema_meta(#sub_ref, depth + 2) {
                        meta.children.insert(#f_id, __cm);
                    }
                }
            })
        }
        FieldShape::BuffaMessageField { .. } => Some(quote! {
            if let ::core::option::Option::Some(__cm) = #krate::codec::buffa_message_field_value_schema_meta(&self.#f_ident, depth + 2) {
                meta.children.insert(#f_id, __cm);
            }
        }),
        FieldShape::SubMsgVec { ty, boxed } => {
            let elem_ref = if *boxed {
                quote!(&**__elem)
            } else {
                quote!(__elem)
            };
            Some(quote! {
                if !self.#f_ident.is_empty() {
                    let mut __child: ::core::option::Option<#krate::SchemaMeta> = ::core::option::Option::None;
                    for __elem in &self.#f_ident {
                        if let ::core::option::Option::Some(__cm) = <#ty as #krate::Message>::build_value_schema_meta(#elem_ref, depth + 2) {
                            __child = ::core::option::Option::Some(#krate::field0::merge_schema_meta(__child, __cm));
                        }
                    }
                    if let ::core::option::Option::Some(__c) = __child {
                        meta.children.insert(#f_id, __c);
                    }
                }
            })
        }
        FieldShape::NestedVec { elem } if elem.leaf_submsg_type().is_some() => {
            let loop_body = gen_elem_value_schema_stmt(krate, elem, quote!(__elem), 0);
            Some(quote! {
                if !self.#f_ident.is_empty() {
                    let mut __child: ::core::option::Option<#krate::SchemaMeta> = ::core::option::Option::None;
                    for __elem in &self.#f_ident {
                        #loop_body
                    }
                    if let ::core::option::Option::Some(__c) = __child {
                        meta.children.insert(#f_id, __c);
                    }
                }
            })
        }
        FieldShape::Map { val, .. } if val.leaf_submsg_type().is_some() => {
            let loop_body = gen_elem_value_schema_stmt(krate, val, quote!(__val), 0);
            Some(quote! {
                if !self.#f_ident.is_empty() {
                    let mut __child: ::core::option::Option<#krate::SchemaMeta> = ::core::option::Option::None;
                    for __val in self.#f_ident.values() {
                        #loop_body
                    }
                    if let ::core::option::Option::Some(__c) = __child {
                        meta.children.insert(#f_id, __c);
                    }
                }
            })
        }
        _ => None,
    };

    (insert_name, child_stmt, cyclic_stmt, value_stmt)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_narrowing_and_sign_corrupting_wire_overrides_and_invalid_field_numbers() {
        let cases: &[DeriveInput] = &[
            syn::parse_quote! {
                struct NarrowU64 {
                    #[omnibuf(id = 1, wire = "fixed32")]
                    x: u64,
                }
            },
            syn::parse_quote! {
                struct NarrowI64 {
                    #[omnibuf(id = 1, wire = "sfixed32")]
                    x: i64,
                }
            },
            syn::parse_quote! {
                struct SignMismatchUnsigned {
                    #[omnibuf(id = 1, wire = "sint")]
                    x: u32,
                }
            },
            syn::parse_quote! {
                struct SignMismatchSigned {
                    #[omnibuf(id = 1, wire = "uint")]
                    x: i32,
                }
            },
            syn::parse_quote! {
                struct ReservedFieldZero {
                    #[omnibuf(id = 0)]
                    x: u32,
                }
            },
            syn::parse_quote! {
                struct DuplicateFieldId {
                    #[omnibuf(id = 1)]
                    a: u32,
                    #[omnibuf(id = 1)]
                    b: u32,
                }
            },
            syn::parse_quote! {
                struct FloatMapKey {
                    #[omnibuf(id = 1)]
                    m: HashMap<f64, u32>,
                }
            },
        ];

        for (i, input) in cases.iter().enumerate() {
            assert!(
                expand_derive_omnibuf(input).is_err(),
                "expected compile-time error for invalid derive case #{i}"
            );
        }
    }
}
