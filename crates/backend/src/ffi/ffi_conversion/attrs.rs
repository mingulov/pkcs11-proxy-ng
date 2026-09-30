//! Attribute materialization at the FFI edge: owned CK_ATTRIBUTE
//! arrays for input templates (incl. structural nested templates,
//! ADR-0011 D8/D4) and exact-query buffers.

use super::*;
use crate::ffi::native_allocation::NativeAllocation;

pub(in crate::ffi) struct FfiAttrs {
    /// The ready-to-pass attribute array. Pointers inside borrow from
    /// `_backing`/`_ulong_backing`/`_secret_backing`/`_nested_backing`
    /// (all owned by `self`).
    pub(in crate::ffi) attrs: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    /// True when the caller passed a NULL template pointer (Wave 3.5 D2):
    /// the FFI call receives NULL, not the empty array's address.
    pub(in crate::ffi) null_template: bool,
    /// Backing byte storage for `Bool` values (single bytes;
    /// alignment-free, so a byte `Vec` is sound here).
    _backing: Vec<Vec<u8>>,
    /// Typed backing for `Ulong` values. A provider may read an integer
    /// attribute's `pValue` via an aligned `CK_ULONG` load, so byte-`Vec`
    /// backing (align 1) would be UB on read — the same misalignment
    /// Miri caught for single-ulong `pParameter` (mechanism.rs). Values
    /// are non-secret (types, lengths), matching the plain `_backing`.
    _ulong_backing: Vec<NativeAllocation<cryptoki_sys::CK_ULONG>>,
    /// Wiping backing for `Bytes`/`String` values (ADR-0013 §5). The
    /// `SecretBytes` source cannot serve a stored raw pointer
    /// (closure-scoped access), so each value is copied once into a
    /// `Zeroizing` buffer that is wiped when this owner drops. The source
    /// `SecretBytes` is unaffected and wipes on its own drop.
    _secret_backing: Vec<Zeroizing<Vec<u8>>>,
    /// Backing storage for nested `CK_ATTRIBUTE[]` template VALUES (the
    /// input direction of CKF_ARRAY_ATTRIBUTE attributes): each entry pins
    /// a native sub-attribute array plus its sub-value buffers.
    _nested_backing: Vec<NestedTemplateBacking>,
}

impl FfiAttrs {
    /// `None` values produce a null `pValue` / zero `ulValueLen` (size-query pattern).
    /// `Ulong` values are converted to the correct platform-native `CK_ULONG` width;
    /// a value the native width cannot hold is rejected (D4), never truncated.
    ///
    /// A `None` template is the caller's NULL template pointer (Wave 3.5 D2):
    /// the materialized array is empty AND flagged, so `ffi_attr_ptr`
    /// passes NULL to the provider instead of (ptr, 0).
    pub(in crate::ffi) fn from_opt_slice(template: Option<&[CkAttribute]>) -> CkResult<Self> {
        match template {
            None => Ok(Self {
                attrs: Vec::new(),
                null_template: true,
                _backing: Vec::new(),
                _ulong_backing: Vec::new(),
                _secret_backing: Vec::new(),
                _nested_backing: Vec::new(),
            }),
            Some(attrs) => Self::from_slice(attrs),
        }
    }

    pub(in crate::ffi) fn from_slice(template: &[CkAttribute]) -> CkResult<Self> {
        let mut attrs = Vec::with_capacity(template.len());
        let mut backing: Vec<Vec<u8>> = Vec::new();
        let mut ulong_backing: Vec<NativeAllocation<cryptoki_sys::CK_ULONG>> = Vec::new();
        let mut secret_backing: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut nested_backing: Vec<NestedTemplateBacking> = Vec::new();

        for attr in template {
            let (pvalue, len): (*mut _, cryptoki_sys::CK_ULONG) = match &attr.value {
                None => (std::ptr::null_mut(), 0),
                // T2run: owned writable backing, never a shared
                // read-only static. This seam also feeds
                // `C_GetAttributeValue` (e.g. the known-public probe),
                // which WRITES one byte through `pValue`; a static
                // byte segfaults the backend write (observed daemon
                // SIGSEGV inside SoftHSM).
                Some(CkAttributeValue::Bool(b)) => {
                    let bytes = vec![u8::from(*b)];
                    let ptr = bytes.as_ptr() as *mut _;
                    backing.push(bytes);
                    (ptr, 1)
                }
                Some(CkAttributeValue::Ulong(u)) => {
                    let alloc = NativeAllocation::new(narrow_wire_ulong(*u)?);
                    let len =
                        std::mem::size_of::<cryptoki_sys::CK_ULONG>() as cryptoki_sys::CK_ULONG;
                    let ptr = alloc.root() as *mut _;
                    ulong_backing.push(alloc);
                    (ptr, len)
                }
                // T4-AUDIT site 4: pass NULL for empty values. An empty
                // slice's `as_ptr()` is a dangling non-null pointer; the
                // same NULL+0 encoding `None` uses (and nested sub-values
                // use below) is the backend-safe empty shape.
                Some(CkAttributeValue::Bytes(b)) => Self::push_secret_value(&mut secret_backing, b),
                Some(CkAttributeValue::String(s)) => {
                    Self::push_secret_value(&mut secret_backing, s)
                }
                Some(CkAttributeValue::NestedTemplate(subs)) => {
                    // Rebuild a native CK_ATTRIBUTE[] the backend can walk:
                    // the wire carries the template STRUCTURALLY (client
                    // struct bytes never cross — their pointers are
                    // meaningless in this address space). Sub-values follow
                    // the same materialization rules as top-level ones
                    // (native ulong width, checked narrowing per D4).
                    let backing_entry = Self::materialize_nested_template(subs)?;
                    let ptr = backing_entry.template_ptr();
                    let byte_len = (subs.len() * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>())
                        as cryptoki_sys::CK_ULONG;
                    nested_backing.push(backing_entry);
                    (ptr as *mut _, byte_len)
                }
            };
            attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(attr.attr_type.0)?,
                pValue: pvalue,
                ulValueLen: len,
            });
        }

        Ok(Self {
            attrs,
            null_template: false,
            _backing: backing,
            _ulong_backing: ulong_backing,
            _secret_backing: secret_backing,
            _nested_backing: nested_backing,
        })
    }

    /// Copies a secret attribute value into owned wiping backing and returns
    /// the `(pValue, ulValueLen)` pair, preserving the T4-AUDIT NULL+0 empty
    /// encoding. Pushing to `backing` moves only `Vec` headers; previously
    /// captured heap pointers stay valid.
    fn push_secret_value(
        backing: &mut Vec<Zeroizing<Vec<u8>>>,
        value: &SecretBytes,
    ) -> (*mut std::ffi::c_void, cryptoki_sys::CK_ULONG) {
        if value.is_empty() {
            return (std::ptr::null_mut(), 0);
        }
        let owned = value.expose(|bytes| Zeroizing::new(bytes.to_vec()));
        let len = owned.len() as cryptoki_sys::CK_ULONG;
        let ptr = owned.as_ptr() as *mut _;
        backing.push(owned);
        (ptr, len)
    }
}

/// Backing storage for a single nested `CK_ATTRIBUTE[]` template.
///
/// The boxed slice is pinned at a stable heap address so that the parent
/// attribute's `pValue` pointer remains valid through the FFI call.
/// Sub-buffers hold the `pValue` data for each nested attribute.
struct NestedTemplateBacking {
    /// The nested `CK_ATTRIBUTE` array at a stable heap address.
    _template: std::pin::Pin<Box<[cryptoki_sys::CK_ATTRIBUTE]>>,
    /// Input-direction sub-buffers for each nested attribute's `pValue`.
    /// Wiping (ADR-0013 §5): sub-values may carry secret key material.
    /// Byte-`Vec` backing is sound here: the provider only READS these
    /// value bytes (bytewise, alignment-free); nested `Ulong` sub-values
    /// the provider may load through a typed pointer live in
    /// `_ulong_buffers` instead.
    _sub_buffers: Vec<Zeroizing<Vec<u8>>>,
    /// Typed backing for nested `Ulong` sub-values (same misalignment
    /// rationale as `FfiAttrs::_ulong_backing`; values non-secret).
    _ulong_buffers: Vec<NativeAllocation<cryptoki_sys::CK_ULONG>>,
    /// Query-direction sub-buffers: provider-WRITTEN output, which the
    /// provider may store through a typed `CK_ULONG` pointer, so these
    /// are `CK_ULONG`-aligned (S3/T5) — never mere output bytes. Wiping
    /// (ADR-0013 §5): the provider may write key material here.
    _query_sub_buffers: Vec<AlignedQueryBuffer>,
}

impl NestedTemplateBacking {
    /// Stable address of the pinned native sub-attribute array.
    ///
    /// ALIASING MODEL: callers capture this pointer and then move the
    /// owner into the backing `Vec`. The pinned box contents never move,
    /// so the pointer stays valid — but the move invalidates the shared
    /// reborrow tag under Stacked Borrows. This suite therefore runs
    /// under `-Zmiri-tree-borrows` (see nightly.yml), which accepts the
    /// sound Pin-stabilized idiom while still catching spatial/temporal
    /// UB (it caught a real pParameter misalignment in mechanism.rs).
    fn template_ptr(&self) -> *const cryptoki_sys::CK_ATTRIBUTE {
        self._template.as_ptr()
    }
}

impl FfiAttrs {
    /// Build the pinned native `CK_ATTRIBUTE[]` for a nested template VALUE.
    fn materialize_nested_template(subs: &[CkAttribute]) -> CkResult<NestedTemplateBacking> {
        let mut sub_buffers: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(subs.len());
        let mut ulong_buffers: Vec<NativeAllocation<cryptoki_sys::CK_ULONG>> = Vec::new();
        let mut native: Vec<cryptoki_sys::CK_ATTRIBUTE> = Vec::with_capacity(subs.len());
        for sub in subs {
            let (pvalue, len): (*mut std::ffi::c_void, cryptoki_sys::CK_ULONG) = match &sub.value {
                None => (std::ptr::null_mut(), 0),
                Some(CkAttributeValue::Bool(b)) => {
                    let bytes = Zeroizing::new(vec![u8::from(*b)]);
                    let ptr = bytes.as_ptr() as *mut _;
                    sub_buffers.push(bytes);
                    (ptr, 1)
                }
                Some(CkAttributeValue::Ulong(u)) => {
                    let alloc = NativeAllocation::new(narrow_wire_ulong(*u)?);
                    let ulen =
                        std::mem::size_of::<cryptoki_sys::CK_ULONG>() as cryptoki_sys::CK_ULONG;
                    let ptr = alloc.root() as *mut _;
                    ulong_buffers.push(alloc);
                    (ptr, ulen)
                }
                Some(CkAttributeValue::Bytes(b)) => {
                    let bytes = b.expose(|raw| Zeroizing::new(raw.to_vec()));
                    Self::push_nested_value(&mut sub_buffers, bytes)
                }
                Some(CkAttributeValue::String(s)) => {
                    let bytes = s.expose(|raw| Zeroizing::new(raw.to_vec()));
                    Self::push_nested_value(&mut sub_buffers, bytes)
                }
                // D8: refused at the deserialization edge; defensively
                // reject here too rather than recurse.
                Some(CkAttributeValue::NestedTemplate(_)) => {
                    return Err(CkRv::ATTRIBUTE_VALUE_INVALID);
                }
            };
            native.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(sub.attr_type.0)?,
                pValue: pvalue,
                ulValueLen: len,
            });
        }
        Ok(NestedTemplateBacking {
            _template: std::pin::Pin::new(native.into_boxed_slice()),
            _sub_buffers: sub_buffers,
            _ulong_buffers: ulong_buffers,
            // Input direction: no provider-written sub-output.
            _query_sub_buffers: Vec::new(),
        })
    }

    /// Pushes a nested byte sub-value, preserving the NULL+0 empty
    /// encoding the old shared path gave empty buffers.
    fn push_nested_value(
        sub_buffers: &mut Vec<Zeroizing<Vec<u8>>>,
        bytes: Zeroizing<Vec<u8>>,
    ) -> (*mut std::ffi::c_void, cryptoki_sys::CK_ULONG) {
        if bytes.is_empty() {
            sub_buffers.push(bytes);
            return (std::ptr::null_mut(), 0);
        }
        let len = bytes.len() as cryptoki_sys::CK_ULONG;
        let ptr = bytes.as_ptr() as *mut _;
        sub_buffers.push(bytes);
        (ptr, len)
    }
}

/// Provider-written attribute-query output buffer: `CK_ULONG`-aligned
/// wiping storage (S3/T5).
///
/// A provider may write an integer attribute through a typed `CK_ULONG`
/// pointer, so byte-`Vec` backing (align 1) is UB on that store (Miri
/// confirmed). A `Vec<CK_ULONG>` base is `CK_ULONG`-aligned by
/// construction; the element count rounds the byte extent up, so the byte
/// view still covers the advertised capacity plus the fixed scalar
/// scratch. `Zeroizing` wipes the allocation on drop (ADR-0013 §5); the
/// heap address is stable across `Vec`-header moves, as before.
struct AlignedQueryBuffer(Zeroizing<Vec<cryptoki_sys::CK_ULONG>>);

impl AlignedQueryBuffer {
    /// Raw base for the query's `pValue`. The caller captures this address
    /// and then moves the owner into backing storage; the heap allocation
    /// never moves, so the pointer stays valid (same Tree Borrows idiom as
    /// the other materializers in this module).
    fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        self.0.as_mut_ptr() as *mut std::ffi::c_void
    }

    /// Raw base for matching a buffer against its advertised `pValue`.
    fn as_ptr(&self) -> *const std::ffi::c_void {
        self.0.as_ptr() as *const std::ffi::c_void
    }

    /// Byte view over the whole allocation (rounded-up extent, never less
    /// than the advertised capacity). Readback still slices only the
    /// provider-reported length bounded by the advertised capacity.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: the `Vec<CK_ULONG>` owns `len * size_of::<CK_ULONG>()`
        // initialized bytes at `as_ptr()`; a `u8` view needs no alignment.
        unsafe {
            std::slice::from_raw_parts(
                self.0.as_ptr() as *const u8,
                self.0.len() * std::mem::size_of::<cryptoki_sys::CK_ULONG>(),
            )
        }
    }

    /// Mutable byte view over the whole allocation (tests only).
    #[cfg(test)]
    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: same allocation as `as_bytes`, exclusively borrowed.
        unsafe {
            std::slice::from_raw_parts_mut(
                self.0.as_mut_ptr() as *mut u8,
                self.0.len() * std::mem::size_of::<cryptoki_sys::CK_ULONG>(),
            )
        }
    }

    /// Byte length of the whole allocation (tests only).
    #[cfg(test)]
    fn byte_len(&self) -> usize {
        self.as_bytes().len()
    }
}

/// Owns raw `CK_ATTRIBUTE` buffers for exact `C_GetAttributeValue` semantics.
///
/// For attributes with `CKF_ARRAY_ATTRIBUTE`, stores additional nested template
/// arrays and their sub-buffers. Pointer stability is ensured by using pinned
/// `Box<[CK_ATTRIBUTE]>` for nested templates and pre-allocated
/// `CK_ULONG`-aligned buffers for all provider-written output.
pub(in crate::ffi) struct FfiAttributeQueries {
    pub(in crate::ffi) attrs: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    original: Vec<cryptoki_sys::CK_ATTRIBUTE>,
    nested_originals: Vec<Vec<cryptoki_sys::CK_ATTRIBUTE>>,
    /// Provider-written output buffers. Wiping (ADR-0013 §5): the provider
    /// may write key material here; leftovers are wiped on drop.
    _buffers: Vec<AlignedQueryBuffer>,
    _nested: Vec<NestedTemplateBacking>,
}

impl FfiAttributeQueries {
    pub(in crate::ffi) fn from_queries(queries: &[CkAttributeQuery]) -> CkResult<Self> {
        let mut attrs = Vec::with_capacity(queries.len());
        let mut buffers = Vec::new();
        let mut nested_backings = Vec::new();

        for query in queries {
            if query.buffer_present
                && query.buffer_len > super::super::call_helpers::MAX_OUTPUT_BUFFER_BYTES
            {
                return Err(CkRv::HOST_MEMORY);
            }
            if let Some(nested_queries) = &query.nested {
                if !query.attr_type.is_attribute_template()
                    || nested_queries.iter().any(|sub| sub.nested.is_some())
                {
                    return Err(CkRv::ARGUMENTS_BAD);
                }
                // CKF_ARRAY_ATTRIBUTE: allocate a nested CK_ATTRIBUTE[] template
                Self::build_nested_attr(query, nested_queries, &mut attrs, &mut nested_backings)?;
            } else {
                // Flat attribute: allocate a simple byte buffer
                let ul_value_len = cryptoki_sys::CK_ULONG::try_from(query.buffer_len)
                    .map_err(|_| CkRv::HOST_MEMORY)?;
                let (pvalue, len) = if query.buffer_present {
                    let mut buffer = Self::output_buffer(query.buffer_len)?;
                    let ptr = buffer.as_mut_ptr();
                    buffers.push(buffer);
                    (ptr, ul_value_len)
                } else {
                    (std::ptr::null_mut(), 0)
                };

                attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                    type_: narrow_wire_ulong(query.attr_type.0)?,
                    pValue: pvalue,
                    ulValueLen: len,
                });
            }
        }

        let original = attrs.clone();
        let nested_originals = nested_backings.iter().map(|b| b._template.to_vec()).collect();
        Ok(Self { attrs, original, nested_originals, _buffers: buffers, _nested: nested_backings })
    }

    /// Read only immutable allocation owners, never provider-replaced pointers.
    /// An oversized scalar remains an effect but cannot enlarge an owned slice.
    pub(in crate::ffi) fn readback(
        &self,
        queries: &[CkAttributeQuery],
        rv: CkRv,
    ) -> Vec<CkAttributeQueryResult> {
        let mut results =
            super::super::mapping::exact_attribute_results_from_ffi(queries, &self.attrs, rv);
        let values_defined = pkcs11_proxy_ng_types::attribute_outputs_defined(rv);
        for (((query, native), original), result) in
            queries.iter().zip(&self.attrs).zip(&self.original).zip(&mut results)
        {
            if native.pValue != original.pValue || native.pValue.is_null() {
                continue;
            }
            if let Some(nested_queries) = &query.nested {
                let Some((index, backing)) = self._nested.iter().enumerate().find(|(_, b)| {
                    b._template.as_ptr().cast::<std::ffi::c_void>() == original.pValue
                }) else {
                    continue;
                };
                let stride = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>();
                let Ok(length) = usize::try_from(result.returned_len) else {
                    continue;
                };
                if result.returned_len > query.buffer_len
                    || length > backing._template.len() * stride
                    || length % stride != 0
                {
                    continue;
                }
                let count = length / stride;
                let mut nested = super::super::mapping::exact_attribute_results_from_ffi(
                    &nested_queries[..count.min(nested_queries.len())],
                    &backing._template[..count],
                    rv,
                );
                for (((sub, old), out), query) in backing
                    ._template
                    .iter()
                    .zip(&self.nested_originals[index])
                    .zip(&mut nested)
                    .zip(nested_queries)
                {
                    // Nested type is output-bearing only when attribute results are defined.
                    out.attr_type = if values_defined {
                        CkAttributeType(sub.type_ as u64)
                    } else {
                        CkAttributeType(0)
                    };
                    out.apply_type = values_defined;
                    if values_defined
                        && !out.attr_type.is_attribute_template()
                        && sub.pValue == old.pValue
                        && query.buffer_present
                        && out.returned_len <= query.buffer_len
                    {
                        out.value = owned_attribute_bytes(
                            &backing._query_sub_buffers,
                            old.pValue,
                            out.returned_len,
                        );
                    }
                }
                result.nested = Some(nested);
            } else if values_defined
                && query.buffer_present
                && result.returned_len <= query.buffer_len
            {
                result.value =
                    owned_attribute_bytes(&self._buffers, original.pValue, result.returned_len);
            }
        }
        results
    }

    /// Keep pointer presence separate from the advertised capacity. Some native
    /// providers write fixed-size scalar values before checking ulValueLen. Give
    /// even short/empty queries real writable storage for a CK_ULONG or CK_DATE;
    /// boolean values also fit. This is bounded padding, not protection against
    /// arbitrary provider overruns. Readback still uses the advertised capacity.
    /// The storage is CK_ULONG-aligned: a provider may store an integer
    /// attribute through a typed pointer (S3/T5).
    fn output_buffer(capacity: u64) -> CkResult<AlignedQueryBuffer> {
        let capacity = usize::try_from(capacity).map_err(|_| CkRv::HOST_MEMORY)?;
        let extent = capacity.max(
            std::mem::size_of::<cryptoki_sys::CK_ULONG>()
                .max(std::mem::size_of::<cryptoki_sys::CK_DATE>()),
        );
        let units = extent.div_ceil(std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        let mut buffer = Zeroizing::new(Vec::new());
        buffer.try_reserve_exact(units).map_err(|_| CkRv::HOST_MEMORY)?;
        buffer.resize(units, 0);
        Ok(AlignedQueryBuffer(buffer))
    }

    /// Build a `CK_ATTRIBUTE` entry for a nested template attribute.
    ///
    /// Allocates a pinned `CK_ATTRIBUTE[]` array for the sub-template and
    /// byte buffers for each sub-attribute's `pValue`. The parent attribute's
    /// `pValue` points to the nested array and `ulValueLen` is set to
    /// `count * size_of::<CK_ATTRIBUTE>()`.
    fn build_nested_attr(
        query: &CkAttributeQuery,
        nested_queries: &[CkAttributeQuery],
        attrs: &mut Vec<cryptoki_sys::CK_ATTRIBUTE>,
        nested_backings: &mut Vec<NestedTemplateBacking>,
    ) -> CkResult<()> {
        if !query.buffer_present {
            // Size query or empty nested: pValue=NULL, ulValueLen carries the
            // requested/expected length.
            attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: narrow_wire_ulong(query.attr_type.0)?,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            });
            return Ok(());
        }

        let native_len = nested_queries
            .len()
            .checked_mul(std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>())
            .ok_or(CkRv::HOST_MEMORY)?;
        if query.buffer_len != native_len as u64 {
            return Err(CkRv::ARGUMENTS_BAD);
        }

        // Allocate sub-buffers first, collecting stable pointers
        let mut sub_buffers: Vec<AlignedQueryBuffer> = Vec::with_capacity(nested_queries.len());
        let mut sub_attrs: Vec<cryptoki_sys::CK_ATTRIBUTE> =
            Vec::with_capacity(nested_queries.len());

        for sub_query in nested_queries {
            if sub_query.buffer_present
                && sub_query.buffer_len > super::super::call_helpers::MAX_OUTPUT_BUFFER_BYTES
            {
                return Err(CkRv::HOST_MEMORY);
            }
            let sub_ul_value_len = cryptoki_sys::CK_ULONG::try_from(sub_query.buffer_len)
                .map_err(|_| CkRv::HOST_MEMORY)?;

            let (sub_pvalue, sub_len) = if sub_query.buffer_present {
                let mut sub_buf = Self::output_buffer(sub_query.buffer_len)?;
                let ptr = sub_buf.as_mut_ptr();
                sub_buffers.push(sub_buf);
                (ptr, sub_ul_value_len)
            } else {
                (std::ptr::null_mut(), 0)
            };

            sub_attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                // F7/D5: forward the caller-preset nested query type
                // verbatim. Backends such as SoftHSM select the sub-query
                // by it; forcing 0 rewrites the caller's query.
                type_: narrow_wire_ulong(sub_query.attr_type.0)?,
                pValue: sub_pvalue,
                ulValueLen: sub_len,
            });
        }

        // An empty present template still needs a real aligned address. The
        // dummy entry is storage only: the native length and readback bounds
        // remain those of the original (empty) query.
        if sub_attrs.is_empty() {
            sub_attrs.push(cryptoki_sys::CK_ATTRIBUTE {
                type_: 0,
                pValue: std::ptr::null_mut(),
                ulValueLen: 0,
            });
        }
        let mut template_box: std::pin::Pin<Box<[cryptoki_sys::CK_ATTRIBUTE]>> =
            sub_attrs.into_boxed_slice().into();
        let template_ptr = template_box.as_mut_ptr() as *mut std::ffi::c_void;
        let template_byte_len =
            cryptoki_sys::CK_ULONG::try_from(native_len).map_err(|_| CkRv::HOST_MEMORY)?;

        attrs.push(cryptoki_sys::CK_ATTRIBUTE {
            type_: narrow_wire_ulong(query.attr_type.0)?,
            pValue: template_ptr,
            ulValueLen: template_byte_len,
        });

        nested_backings.push(NestedTemplateBacking {
            _template: template_box,
            // Query direction: no input sub-values; sub-output lives in
            // `_query_sub_buffers`.
            _sub_buffers: Vec::new(),
            _ulong_buffers: Vec::new(),
            // Query path: sub-buffers are provider-written output the
            // provider may store through a typed CK_ULONG pointer, so
            // they are CK_ULONG-aligned (S3/T5).
            _query_sub_buffers: sub_buffers,
        });

        Ok(())
    }
}

fn owned_attribute_bytes(
    buffers: &[AlignedQueryBuffer],
    pointer: *mut std::ffi::c_void,
    length: u64,
) -> Option<SecretBytes> {
    let length = usize::try_from(length).ok()?;
    let buffer = buffers
        .iter()
        .find(|buffer| !pointer.is_null() && buffer.as_ptr().cast_mut() == pointer)?;
    buffer.as_bytes().get(..length).map(SecretBytes::copy_from_slice)
}

#[cfg(test)]
mod ffi_attrs_narrowing_tests {
    use pkcs11_proxy_ng_types::{CkAttribute, CkAttributeType, CkAttributeValue, CkRv};

    use super::FfiAttrs;

    fn ulong_template(value: u64) -> [CkAttribute; 1] {
        [CkAttribute {
            attr_type: CkAttributeType::CLASS,
            value: Some(CkAttributeValue::Ulong(value)),
        }]
    }

    fn materialized_ulong(attrs: &FfiAttrs) -> cryptoki_sys::CK_ULONG {
        let attr = &attrs.attrs[0];
        assert_eq!(attr.ulValueLen as usize, std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        let mut bytes = [0u8; std::mem::size_of::<cryptoki_sys::CK_ULONG>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                attr.pValue as *const u8,
                bytes.as_mut_ptr(),
                bytes.len(),
            );
        }
        cryptoki_sys::CK_ULONG::from_ne_bytes(bytes)
    }

    #[test]
    fn ulong_attribute_materializes_at_native_width_value_preserving() {
        let template = ulong_template(1);
        let attrs = FfiAttrs::from_slice(&template).expect("in-range value converts");
        assert_eq!(materialized_ulong(&attrs), 1);
    }

    #[test]
    fn ulong_attribute_pvalue_supports_typed_ck_ulong_read() {
        // A provider may read an integer attribute's pValue via an aligned
        // CK_ULONG load; byte-Vec backing (align 1) would be UB on that
        // read (same class as the single-ulong pParameter misalignment
        // Miri caught in mechanism.rs). The typed read below fires under
        // Miri on misaligned backing and passes on NativeAllocation.
        let template = ulong_template(0x0A0B_0C0D);
        let attrs = FfiAttrs::from_slice(&template).expect("in-range value converts");
        // E0793: CK_ATTRIBUTE is packed on Windows; copy fields by value.
        let (pvalue, len) = (attrs.attrs[0].pValue, attrs.attrs[0].ulValueLen);
        assert_eq!(len as usize, std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        let value = unsafe { *(pvalue as *const cryptoki_sys::CK_ULONG) };
        assert_eq!(value as u64, 0x0A0B_0C0D);
    }

    #[test]
    fn nested_ulong_subvalue_supports_typed_ck_ulong_read() {
        // Same aligned-load rule for nested-template Ulong sub-values.
        let template = [CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(4)),
            }])),
        }];
        let attrs = FfiAttrs::from_slice(&template).expect("nested template converts");
        let (pvalue, len) = (attrs.attrs[0].pValue, attrs.attrs[0].ulValueLen);
        assert_eq!(len as usize, std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>());
        let sub = unsafe { *(pvalue as *const cryptoki_sys::CK_ATTRIBUTE) };
        assert_eq!(sub.ulValueLen as usize, std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        let value = unsafe { *(sub.pValue as *const cryptoki_sys::CK_ULONG) };
        assert_eq!(value as u64, 4);
    }

    #[test]
    fn nested_template_value_materializes_native_ck_attribute_array() {
        // Input direction of CKA_*_TEMPLATE: the wire carries a STRUCTURAL
        // template (never raw client struct bytes); the FFI edge rebuilds a
        // native CK_ATTRIBUTE[] the backend can dereference safely.
        let template = [CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![
                CkAttribute {
                    attr_type: CkAttributeType::CLASS,
                    value: Some(CkAttributeValue::Ulong(4)),
                },
                CkAttribute {
                    attr_type: CkAttributeType::EXTRACTABLE,
                    value: Some(CkAttributeValue::Bool(true)),
                },
            ])),
        }];
        let attrs = FfiAttrs::from_slice(&template).expect("nested template converts");
        let outer = &attrs.attrs[0];
        assert_eq!(
            outer.ulValueLen as usize,
            2 * std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>(),
            "outer length is the native template byte length"
        );
        let subs = unsafe {
            std::slice::from_raw_parts(outer.pValue as *const cryptoki_sys::CK_ATTRIBUTE, 2)
        };
        assert_eq!(subs[0].type_ as u64, CkAttributeType::CLASS.0);
        assert_eq!(subs[0].ulValueLen as usize, std::mem::size_of::<cryptoki_sys::CK_ULONG>());
        let mut class_bytes = [0u8; std::mem::size_of::<cryptoki_sys::CK_ULONG>()];
        unsafe {
            std::ptr::copy_nonoverlapping(
                subs[0].pValue as *const u8,
                class_bytes.as_mut_ptr(),
                class_bytes.len(),
            );
        }
        assert_eq!(cryptoki_sys::CK_ULONG::from_ne_bytes(class_bytes), 4);
        assert_eq!(subs[1].type_ as u64, CkAttributeType::EXTRACTABLE.0);
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = subs[1].ulValueLen;
        assert_eq!(ul_value_len, 1);
        assert_eq!(unsafe { *(subs[1].pValue as *const u8) }, 1);
    }

    #[test]
    fn nested_template_ulong_sub_value_wider_than_native_is_rejected() {
        // D4 applies to nested sub-values too.
        let template = [CkAttribute {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            value: Some(CkAttributeValue::NestedTemplate(vec![CkAttribute {
                attr_type: CkAttributeType::CLASS,
                value: Some(CkAttributeValue::Ulong(0x1_0000_0001)),
            }])),
        }];
        match FfiAttrs::from_slice(&template) {
            Ok(_) => assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 8),
            Err(rv) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 4);
                assert_eq!(rv, CkRv::FUNCTION_FAILED);
            }
        }
    }

    #[test]
    fn attribute_type_wider_than_native_is_rejected_not_truncated() {
        // 0x1_0000_0000 | CKA_CLASS truncates to CKA_CLASS on a narrow
        // host - the template would silently address a DIFFERENT
        // attribute than the client named. Reject instead.
        let template = [CkAttribute {
            attr_type: CkAttributeType(0x1_0000_0000),
            value: Some(CkAttributeValue::Bytes(vec![1].into())),
        }];
        match FfiAttrs::from_slice(&template) {
            Ok(attrs) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 8);
                assert_eq!(attrs.attrs[0].type_ as u64, 0x1_0000_0000);
            }
            Err(rv) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 4);
                assert_eq!(rv, CkRv::FUNCTION_FAILED);
            }
        }
    }

    #[test]
    fn empty_bytes_value_materializes_null_pvalue() {
        // T4-AUDIT site 4: `Some(Bytes(vec![]))` reaches this seam via the
        // in-repo CLI (`create-object --value ""` → `hex::decode("")` is
        // `Ok(vec![])`, no empty check) and must pass NULL, not the dangling
        // empty-slice pointer — the same encoding `None` already uses.
        let template = [CkAttribute {
            attr_type: CkAttributeType::VALUE,
            value: Some(CkAttributeValue::Bytes(Vec::new().into())),
        }];
        let attrs = FfiAttrs::from_slice(&template).expect("empty bytes convert");
        assert!(attrs.attrs[0].pValue.is_null());
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = attrs.attrs[0].ulValueLen;
        assert_eq!(ul_value_len, 0);
    }

    #[test]
    fn empty_string_value_materializes_null_pvalue() {
        // T4-AUDIT site 4: `Some(String(""))` reaches this seam via the
        // in-repo CLI (`create-object --label ""`, no empty check) and must
        // pass NULL, not the dangling empty-slice pointer.
        let template = [CkAttribute {
            attr_type: CkAttributeType::LABEL,
            value: Some(CkAttributeValue::String(String::new().into())),
        }];
        let attrs = FfiAttrs::from_slice(&template).expect("empty string converts");
        assert!(attrs.attrs[0].pValue.is_null());
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
        let ul_value_len = attrs.attrs[0].ulValueLen;
        assert_eq!(ul_value_len, 0);
    }

    #[test]
    fn bool_attribute_materializes_owned_writable_backing() {
        // T2run: `FfiAttrs` feeds `C_GetAttributeValue` (e.g. the
        // known-public probe), which WRITES one byte through `pValue`.
        // A shared read-only static byte segfaults the backend write
        // (daemon SIGSEGV inside SoftHSM). Each bool must materialize
        // its own writable byte with the value preserved.
        let template = [
            CkAttribute {
                attr_type: CkAttributeType::PRIVATE,
                value: Some(CkAttributeValue::Bool(false)),
            },
            CkAttribute {
                attr_type: CkAttributeType::TOKEN,
                value: Some(CkAttributeValue::Bool(false)),
            },
        ];
        let attrs = FfiAttrs::from_slice(&template).expect("bool values convert");
        // E0793: CK_ATTRIBUTE is packed on Windows; assert on by-value copies.
        let first = attrs.attrs[0].pValue;
        let second = attrs.attrs[1].pValue;
        assert_ne!(first, second, "identical bools must not share one backing byte");
        for attr in &attrs.attrs {
            // E0793: CK_ATTRIBUTE is packed on Windows; assert on a by-value copy.
            let ul_value_len = attr.ulValueLen;
            assert_eq!(ul_value_len, 1);
            assert_eq!(unsafe { *(attr.pValue as *const u8) }, 0);
            // The backend writes through this pointer; prove it is writable.
            unsafe { std::ptr::write_volatile(attr.pValue as *mut u8, 1) };
            assert_eq!(unsafe { *(attr.pValue as *const u8) }, 1);
        }
    }

    #[test]
    fn ulong_attribute_wider_than_native_is_rejected_not_truncated() {
        // Low word is 1: silent truncation would fabricate a plausible
        // small value. D4 (ADR-0011): value-preserving or a loud reject.
        let template = ulong_template(0x1_0000_0001);
        match FfiAttrs::from_slice(&template) {
            Ok(attrs) => {
                assert_eq!(
                    std::mem::size_of::<cryptoki_sys::CK_ULONG>(),
                    8,
                    "narrow CK_ULONG host must not accept a value > u32::MAX"
                );
                assert_eq!(materialized_ulong(&attrs) as u64, 0x1_0000_0001);
            }
            Err(rv) => {
                assert_eq!(std::mem::size_of::<cryptoki_sys::CK_ULONG>(), 4);
                assert_eq!(rv, CkRv::FUNCTION_FAILED);
            }
        }
    }
}

#[cfg(test)]
mod exact_query_storage_tests {
    use super::*;

    fn query(attr_type: CkAttributeType, present: bool, capacity: u64) -> CkAttributeQuery {
        CkAttributeQuery { attr_type, buffer_present: present, buffer_len: capacity, nested: None }
    }

    #[test]
    fn fixed_width_scratch_is_writable_without_enlarging_advertised_capacity() {
        // Catch both dangling empty Vec pointers and accidental promotion of
        // ulValueLen. Fixed-size native writes (seen in NSS) stay in owned storage;
        // extra scratch bytes never become caller-visible output.
        for attr_type in [
            CkAttributeType::PRIVATE,
            CkAttributeType::CLASS,
            CkAttributeType(cryptoki_sys::CKA_START_DATE as u64),
        ] {
            for capacity in [0, 1, 2] {
                let queries = [
                    query(attr_type, true, capacity),
                    query(CkAttributeType::LABEL, true, 16),
                    query(attr_type, false, 0),
                ];
                let mut ffi = FfiAttributeQueries::from_queries(&queries).unwrap();
                assert!(!ffi.attrs[0].pValue.is_null());
                assert!(ffi.attrs[2].pValue.is_null());
                assert_eq!(ffi.attrs[0].ulValueLen as u64, capacity);
                let extent = std::mem::size_of::<cryptoki_sys::CK_ULONG>()
                    .max(std::mem::size_of::<cryptoki_sys::CK_DATE>());
                assert!(ffi._buffers[0].byte_len() >= extent);
                ffi._buffers[1].as_bytes_mut().fill(0xa5);
                unsafe { std::ptr::write_bytes(ffi.attrs[0].pValue.cast::<u8>(), 0x5a, extent) };
                ffi.attrs[0].ulValueLen = extent as cryptoki_sys::CK_ULONG;
                let results = ffi.readback(&queries, CkRv::OK);
                assert!(results[0].value.is_none(), "scratch is not advertised output capacity");
                assert_eq!(results[0].returned_len, extent as u64);
                assert!(ffi._buffers[1].as_bytes().iter().all(|b| *b == 0xa5), "neighbor canary");
            }
        }
    }

    #[test]
    fn nested_scratch_preserves_zero_capacity_and_bounds_readback() {
        let stride = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>();
        let queries = [CkAttributeQuery {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            buffer_present: true,
            buffer_len: (2 * stride) as u64,
            nested: Some(vec![
                query(CkAttributeType::CLASS, true, 0),
                query(CkAttributeType::PRIVATE, false, 0),
            ]),
        }];
        let mut ffi = FfiAttributeQueries::from_queries(&queries).unwrap();
        let backing = &mut ffi._nested[0];
        assert!(!backing._template[0].pValue.is_null());
        assert!(backing._template[1].pValue.is_null());
        assert_eq!(backing._template[0].ulValueLen as u64, 0);
        let extent = std::mem::size_of::<cryptoki_sys::CK_ULONG>();
        assert!(backing._query_sub_buffers[0].byte_len() >= extent);
        unsafe { std::ptr::write_bytes(backing._template[0].pValue.cast::<u8>(), 0x5a, extent) };
        backing._template[0].ulValueLen = extent as cryptoki_sys::CK_ULONG;
        let result = ffi.readback(&queries, CkRv::OK);
        let children = result[0].nested.as_ref().unwrap();
        assert_eq!(children[0].returned_len, extent as u64);
        assert!(children[0].value.is_none());
        assert!(children[1].value.is_none());
    }

    #[test]
    fn provider_typed_ulong_write_into_top_level_query_outputs() {
        // S3/T5: a provider may write an integer attribute through a typed
        // CK_ULONG pointer. Byte-Vec backing (align 1) is UB on that store
        // unless the heap address happens to be CK_ULONG-aligned. Cover
        // ordinary, short and zero-capacity non-NULL buffers; the NULL
        // query has no storage so nothing is written through it. Under
        // Miri this fires on misaligned backing and passes on aligned
        // storage (same class Miri caught for pParameter in
        // mechanism.rs).
        let queries = [
            query(CkAttributeType::CLASS, true, 8),
            query(CkAttributeType::CLASS, true, 2),
            query(CkAttributeType::CLASS, true, 0),
            query(CkAttributeType::CLASS, false, 0),
        ];
        let ffi = FfiAttributeQueries::from_queries(&queries).unwrap();
        for (attr, q) in ffi.attrs.iter().zip(&queries) {
            // E0793: CK_ATTRIBUTE is packed on Windows; copy fields by value.
            let (pvalue, len) = (attr.pValue, attr.ulValueLen);
            if q.buffer_present {
                assert!(!pvalue.is_null());
                assert_eq!(len as u64, q.buffer_len);
                // Provider-style typed store; in-bounds for every shape:
                // even a zero-capacity query owns scratch for a CK_ULONG.
                unsafe { std::ptr::write(pvalue as *mut cryptoki_sys::CK_ULONG, 0x0A0B_0C0D) };
            } else {
                assert!(pvalue.is_null());
                assert_eq!(len, 0);
            }
        }
    }

    #[test]
    fn provider_typed_ulong_write_into_nested_query_outputs() {
        // Same provider-style typed store into nested
        // (CKF_ARRAY_ATTRIBUTE) sub-query buffers. The nested parent's own
        // pValue addresses the pinned CK_ATTRIBUTE array (natively
        // aligned), not bytes; a NULL parent carries no sub-storage.
        let stride = std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>();
        let subs = vec![
            query(CkAttributeType::CLASS, true, 8),
            query(CkAttributeType::CLASS, true, 1),
            query(CkAttributeType::CLASS, true, 0),
            query(CkAttributeType::CLASS, false, 0),
        ];
        let queries = [CkAttributeQuery {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            buffer_present: true,
            buffer_len: (subs.len() * stride) as u64,
            nested: Some(subs),
        }];
        let ffi = FfiAttributeQueries::from_queries(&queries).unwrap();
        let nested = queries[0].nested.as_ref().unwrap();
        let backing = &ffi._nested[0];
        for (i, sub_query) in nested.iter().enumerate() {
            // E0793: CK_ATTRIBUTE is packed on Windows; copy fields by value.
            let (pvalue, len) = (backing._template[i].pValue, backing._template[i].ulValueLen);
            if sub_query.buffer_present {
                assert!(!pvalue.is_null());
                assert_eq!(len as u64, sub_query.buffer_len);
                unsafe { std::ptr::write(pvalue as *mut cryptoki_sys::CK_ULONG, 0x0A0B_0C0D) };
            } else {
                assert!(pvalue.is_null());
                assert_eq!(len, 0);
            }
        }

        let null_parent = [CkAttributeQuery {
            attr_type: CkAttributeType::WRAP_TEMPLATE,
            buffer_present: false,
            buffer_len: 0,
            nested: Some(vec![query(CkAttributeType::CLASS, true, 8)]),
        }];
        let ffi_null = FfiAttributeQueries::from_queries(&null_parent).unwrap();
        // E0793: CK_ATTRIBUTE is packed on Windows; copy fields by value.
        let (pvalue, len) = (ffi_null.attrs[0].pValue, ffi_null.attrs[0].ulValueLen);
        assert!(pvalue.is_null());
        assert_eq!(len, 0);
        assert!(ffi_null._nested.is_empty(), "NULL parent owns no sub-storage");
    }

    #[test]
    fn empty_nested_parent_has_storage_but_no_readable_entries() {
        let queries = [CkAttributeQuery {
            nested: Some(vec![]),
            ..query(CkAttributeType::WRAP_TEMPLATE, true, 0)
        }];
        let mut ffi = FfiAttributeQueries::from_queries(&queries).unwrap();
        assert!(!ffi.attrs[0].pValue.is_null());
        assert_eq!(ffi.attrs[0].ulValueLen as u64, 0);
        assert!(!ffi._nested[0]._template.is_empty(), "must own a real aligned allocation");
        let results = ffi.readback(&queries, CkRv::OK);
        assert_eq!(results[0].nested.as_ref().unwrap().len(), 0);
        ffi.attrs[0].ulValueLen =
            std::mem::size_of::<cryptoki_sys::CK_ATTRIBUTE>() as cryptoki_sys::CK_ULONG;
        let results = ffi.readback(&queries, CkRv::BUFFER_TOO_SMALL);
        assert!(results[0].nested.is_none(), "padding must not invent returned children");
    }
}
