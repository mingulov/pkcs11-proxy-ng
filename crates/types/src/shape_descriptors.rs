//! Shared compiled mechanism-parameter shape descriptors (S2 §4).
//!
//! Immutable [`ShapeDescriptor`] + [`ShapeResolver`] tables describing every
//! classic parameter shape the proxy compiles: outer kind, native layout
//! per v1 ABI, first unsafe offset, layout fingerprint, virtual-handle
//! presence, operation contexts, alternate forms, and shared-length
//! companion sets (S2 §10/D3). [`MechanismRegistry`](crate::mechanism_registry::MechanismRegistry)
//! remains the mutable mechanism→compiled-shape binding layer over these
//! tables: TOML may bind a mechanism to an already compiled descriptor,
//! never create or alter one. Server Flat-eligibility rules live here as
//! pure functions ([`decide_flat`]); the daemon (R9) and shim (R11) consume
//! them without re-deciding policy.
//!
//! Layouts derive from one field sequence per shape via C layout rules,
//! parameterized by [`ParamAbi`] (LP64, ILP32, LLP64-pack1, ILP32-pack1 —
//! the v1 ABI set, discriminants mirroring the wire `MechanismParamAbi`).
//! The table holds field *classes*, never byte offsets, so all four ABIs
//! derive from the same reviewed source. Native sizes and offsets are
//! cross-checked against `cryptoki-sys` on the host ABI in tests.
//!
//! Canonical fingerprint encoding (S2 §3 tuple, byte-exact): FNV-1a 64
//! over `le32(len(shape)) + shape + le32(len(form)) + form +
//! le32(ulong_size) + le32(byte_order) + le32(native_size) +
//! le32(leaf_count) + [le32(offset) + le32(size)]* + le32(pad_count) +
//! [le32(offset) + le32(size)]*`, where leaves are flattened fields at
//! absolute offsets (nested structs expanded) and pads are the explicit
//! padding ranges (inter-field gaps plus tail). All integers
//! little-endian; `form` is empty for primary forms.
//!
//! Classification notes (derived requirements, reviewed at R7):
//!
//! - [`OuterKind::NestedOrOutput`] shapes are never Flat-eligible: S2 §8
//!   assigns the tail (key-mat, KEA, KIP, OTP/SP800-108, Skipjack,
//!   output-bearing PRFs) typed envelopes only, while the S2 §4 server
//!   rules enumerate Flat eligibility for the other four kinds (absence
//!   of permission is denial per S2 §2 principle 1).
//! - `rsa_aes_key_wrap` is [`OuterKind::PointerStruct`], not nested: S2 §8
//!   lists "RSA-AES-wrap nesting" under the Flat-covered input shapes,
//!   and its nested OAEP pointer sits past the safe prefix (`first_unsafe
//!   = 8`), so Flat never reaches it (S2 §4 parenthetical).
//! - `object_handle` is [`OuterKind::ScalarStruct`] with
//!   `first_unsafe = Some(0)`: the uniform prefix rule (declared length
//!   at or below the first unsafe offset, when one exists) additionally
//!   guards handle-bearing scalars, per S2 §10 "Flat cannot reach
//!   pointer/handle fields".
//! - Form selection (wrap layouts, `gcm_compat`, dual structs) uses the
//!   *selector's* local ABI sizes; cross-ABI disagreement fails closed
//!   via the fingerprint/ABI checks, never silently (struct prefixes
//!   require exact ABI equality, S2 §3).

use crate::mechanism::CkMechanismType;
use crate::mechanism_registry::MechanismRegistry;

// ─── Native ABI ──────────────────────────────────────────────────────────────

/// Native C ABI of a v1 edge for mechanism-parameter layout purposes.
///
/// Discriminants mirror the wire `MechanismParamAbi` (R2/R6) deliberately
/// so R9's conversion is a direct map; the wire `UNSPECIFIED = 0` has no
/// native counterpart (a message without an ABI never reaches layout
/// code — R9 rejects it first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParamAbi {
    /// LP64 little-endian (Linux x86_64/aarch64): 8-byte `CK_ULONG` and
    /// pointers, natural alignment.
    Lp64NativeLe = 1,
    /// ILP32 little-endian: 4-byte `CK_ULONG` and pointers, natural
    /// alignment.
    Ilp32NativeLe = 2,
    /// LLP64 little-endian, 1-byte packed (Windows-style PKCS#11
    /// headers): 4-byte `CK_ULONG`, 8-byte pointers, alignment 1.
    Llp64Packed1Le = 3,
    /// ILP32 little-endian, 1-byte packed: 4-byte `CK_ULONG` and
    /// pointers, alignment 1. The true native win32
    /// (i686-pc-windows-msvc) layout: cryptoki-sys ships no
    /// x86-windows bindings, so win32 falls back to its generic
    /// bindings whose structs carry `#[cfg_attr(windows, repr(packed))]`.
    Ilp32Packed1Le = 4,
}

impl ParamAbi {
    /// Native `CK_ULONG` width in bytes under this ABI.
    pub const fn ulong_size(self) -> usize {
        match self {
            Self::Lp64NativeLe => 8,
            Self::Ilp32NativeLe | Self::Llp64Packed1Le | Self::Ilp32Packed1Le => 4,
        }
    }

    /// Native pointer width in bytes under this ABI.
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::Lp64NativeLe | Self::Llp64Packed1Le => 8,
            Self::Ilp32NativeLe | Self::Ilp32Packed1Le => 4,
        }
    }

    /// Whether fields pack with alignment 1 (the two packed ABIs only).
    pub const fn packed(self) -> bool {
        match self {
            Self::Llp64Packed1Le | Self::Ilp32Packed1Le => true,
            Self::Lp64NativeLe | Self::Ilp32NativeLe => false,
        }
    }

    /// Byte-order code for the fingerprint tuple (0 = little-endian;
    /// all v1 ABIs are little-endian).
    pub const fn byte_order_code(self) -> u32 {
        let _ = self;
        0
    }

    /// This build target's v1 ABI, or `None` where no v1 ABI exists
    /// (big-endian targets have no little-endian layout).
    ///
    /// Both Windows families are packed-1 (Windows-style PKCS#11
    /// headers): 64-bit Windows is LLP64-pack1 (4-byte `CK_ULONG`,
    /// 8-byte pointers) and 32-bit Windows is ILP32-pack1 (4-byte
    /// `CK_ULONG` and pointers). A width-blind `cfg!(windows)` here
    /// mis-sized every pointer-bearing struct on win32, and a
    /// packing-blind win32 fallback to `Ilp32NativeLe` mis-sized every
    /// packing-sensitive struct there instead.
    pub const fn native() -> Option<Self> {
        if !cfg!(target_endian = "little") {
            None
        } else if cfg!(all(windows, target_pointer_width = "64")) {
            Some(Self::Llp64Packed1Le)
        } else if cfg!(all(windows, target_pointer_width = "32")) {
            Some(Self::Ilp32Packed1Le)
        } else if cfg!(target_pointer_width = "64") {
            Some(Self::Lp64NativeLe)
        } else {
            Some(Self::Ilp32NativeLe)
        }
    }
}

// ─── Layout engine (const fns over field sequences) ──────────────────────────

/// One field of a C parameter struct, by layout class.
///
/// Every OASIS scalar in the compiled shapes is either `CK_ULONG`-width
/// (including all `CK_*_TYPE` enums, `CK_FLAGS`, `CK_RV`) or a single byte
/// (`CK_BYTE`, `CK_CHAR`, `CK_UTF8CHAR`, `CK_BBOOL`); there are no 16-bit
/// or wider-than-pointer fields. Handles share `CK_ULONG` width but are a
/// distinct class: a flat prefix must never carry a virtual-handle value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldClass {
    /// `CK_ULONG`-width scalar (safe prefix content).
    Ulong,
    /// `CK_OBJECT_HANDLE` (unsafe: virtual-handle value).
    Handle,
    /// Any native pointer (unsafe).
    Pointer,
    /// Single byte (`CK_BYTE`/`CK_BBOOL`/…).
    U8,
    /// Fixed `[u8; N]` array (embedded IV/counter blocks).
    Bytes(u16),
    /// Inline nested struct, given by its own field sequence (depth 1
    /// only: inner lists must not contain `Nested` — test-enforced).
    Nested(&'static [FieldClass]),
}

/// `usize::div_ceil` is not usable in `const fn`, so keep the manual form.
#[allow(clippy::manual_div_ceil)]
const fn align_up(offset: usize, align: usize) -> usize {
    (offset + (align - 1)) / align * align
}

/// Size and alignment of one non-nested field under `abi`.
const fn flat_size_align(field: FieldClass, abi: ParamAbi) -> (usize, usize) {
    match field {
        FieldClass::Ulong | FieldClass::Handle => {
            let size = abi.ulong_size();
            (size, if abi.packed() { 1 } else { size })
        }
        FieldClass::Pointer => {
            let size = abi.pointer_size();
            (size, if abi.packed() { 1 } else { size })
        }
        FieldClass::U8 => (1, 1),
        FieldClass::Bytes(n) => (n as usize, 1),
        FieldClass::Nested(_) => panic!("nested field in flat layout context"),
    }
}

/// Size and alignment of an inline nested struct under `abi`.
const fn nested_size_align(inner: &[FieldClass], abi: ParamAbi) -> (usize, usize) {
    let mut size = 0usize;
    let mut align = 1usize;
    let mut i = 0usize;
    while i < inner.len() {
        let (field_size, field_align) = flat_size_align(inner[i], abi);
        size = align_up(size, field_align) + field_size;
        if field_align > align {
            align = field_align;
        }
        i += 1;
    }
    (align_up(size, align), align)
}

const fn field_size_align(field: FieldClass, abi: ParamAbi) -> (usize, usize) {
    match field {
        FieldClass::Nested(inner) => nested_size_align(inner, abi),
        flat => flat_size_align(flat, abi),
    }
}

/// Native struct size under `abi` for a field sequence.
pub const fn native_size_of(fields: &[FieldClass], abi: ParamAbi) -> usize {
    let mut size = 0usize;
    let mut align = 1usize;
    let mut i = 0usize;
    while i < fields.len() {
        let (field_size, field_align) = field_size_align(fields[i], abi);
        size = align_up(size, field_align) + field_size;
        if field_align > align {
            align = field_align;
        }
        i += 1;
    }
    align_up(size, align)
}

/// Native offset of top-level field `index` under `abi`.
///
/// Panics when `index` is out of range (test/R8 tooling only; the
/// daemon/shim paths never index by position).
pub const fn field_offset_of(fields: &[FieldClass], abi: ParamAbi, index: usize) -> usize {
    let mut offset = 0usize;
    let mut i = 0usize;
    while i < index {
        let (field_size, field_align) = field_size_align(fields[i], abi);
        offset = align_up(offset, field_align) + field_size;
        i += 1;
    }
    let (_, align) = field_size_align(fields[index], abi);
    align_up(offset, align)
}

/// Offset of the first pointer/handle/nested-unsafe leaf under `abi`, or
/// `None` when the sequence carries no unsafe field. A Flat prefix is
/// confined at or below this offset (S2 §4/§10).
pub const fn first_unsafe_offset_of(fields: &[FieldClass], abi: ParamAbi) -> Option<usize> {
    let mut offset = 0usize;
    let mut i = 0usize;
    while i < fields.len() {
        let field = fields[i];
        let (_, align) = field_size_align(field, abi);
        let start = align_up(offset, align);
        match field {
            FieldClass::Pointer | FieldClass::Handle => return Some(start),
            FieldClass::Nested(inner) => {
                let mut inner_offset = 0usize;
                let mut j = 0usize;
                while j < inner.len() {
                    let nested_field = inner[j];
                    let (nested_size, nested_align) = flat_size_align(nested_field, abi);
                    let nested_start = align_up(inner_offset, nested_align);
                    match nested_field {
                        FieldClass::Pointer | FieldClass::Handle => {
                            return Some(start + nested_start);
                        }
                        FieldClass::Nested(_) => {
                            panic!("nested struct deeper than one level");
                        }
                        _ => {}
                    }
                    inner_offset = nested_start + nested_size;
                    j += 1;
                }
            }
            _ => {}
        }
        let (field_size, _) = field_size_align(field, abi);
        offset = start + field_size;
        i += 1;
    }
    None
}

/// Whether any field (including nested leaves) is a virtual handle.
pub const fn contains_handle_in(fields: &[FieldClass]) -> bool {
    let mut i = 0usize;
    while i < fields.len() {
        match fields[i] {
            FieldClass::Handle => return true,
            FieldClass::Nested(inner) => {
                let mut j = 0usize;
                while j < inner.len() {
                    match inner[j] {
                        FieldClass::Handle => return true,
                        FieldClass::Nested(_) => {
                            panic!("nested struct deeper than one level");
                        }
                        _ => {}
                    }
                    j += 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

// ─── Layout fingerprint (FNV-1a 64, const) ───────────────────────────────────

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0100_0000_01b3;

/// Fixed fingerprint for ABI-independent outer kinds (parameterless,
/// byte-buffer): the ASCII bytes `ABIEXMPT` as little-endian u64. Both
/// edges skip ABI matching for these forms (S2 §3).
pub const ABI_EXEMPT_FINGERPRINT: u64 = 0x5450_4d58_4549_4241;

const fn fnv_byte(hash: u64, byte: u8) -> u64 {
    (hash ^ byte as u64).wrapping_mul(FNV_PRIME)
}

const fn fnv_le32(mut hash: u64, value: u32) -> u64 {
    hash = fnv_byte(hash, (value & 0xFF) as u8);
    hash = fnv_byte(hash, ((value >> 8) & 0xFF) as u8);
    hash = fnv_byte(hash, ((value >> 16) & 0xFF) as u8);
    fnv_byte(hash, ((value >> 24) & 0xFF) as u8)
}

const fn fnv_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    let mut i = 0usize;
    while i < bytes.len() {
        hash = fnv_byte(hash, bytes[i]);
        i += 1;
    }
    hash
}

const fn leaf_count_of(fields: &[FieldClass]) -> usize {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < fields.len() {
        match fields[i] {
            FieldClass::Nested(inner) => count += inner.len(),
            _ => count += 1,
        }
        i += 1;
    }
    count
}

const fn hash_leaves(mut hash: u64, fields: &[FieldClass], abi: ParamAbi) -> u64 {
    let mut offset = 0usize;
    let mut i = 0usize;
    while i < fields.len() {
        let field = fields[i];
        let (field_size, field_align) = field_size_align(field, abi);
        let start = align_up(offset, field_align);
        match field {
            FieldClass::Nested(inner) => {
                let mut inner_offset = 0usize;
                let mut j = 0usize;
                while j < inner.len() {
                    let (nested_size, nested_align) = flat_size_align(inner[j], abi);
                    let nested_start = align_up(inner_offset, nested_align);
                    hash = fnv_le32(hash, (start + nested_start) as u32);
                    hash = fnv_le32(hash, nested_size as u32);
                    inner_offset = nested_start + nested_size;
                    j += 1;
                }
            }
            _ => {
                hash = fnv_le32(hash, start as u32);
                hash = fnv_le32(hash, field_size as u32);
            }
        }
        offset = start + field_size;
        i += 1;
    }
    hash
}

/// Number of explicit padding ranges (inter-leaf gaps plus tail).
const fn pad_count_of(fields: &[FieldClass], abi: ParamAbi) -> usize {
    let native = native_size_of(fields, abi);
    let mut count = 0usize;
    let mut prev_end = 0usize;
    let mut offset = 0usize;
    let mut i = 0usize;
    while i < fields.len() {
        let field = fields[i];
        let (field_size, field_align) = field_size_align(field, abi);
        let start = align_up(offset, field_align);
        match field {
            FieldClass::Nested(inner) => {
                let mut inner_offset = 0usize;
                let mut j = 0usize;
                while j < inner.len() {
                    let (nested_size, nested_align) = flat_size_align(inner[j], abi);
                    let leaf_start = start + align_up(inner_offset, nested_align);
                    if leaf_start > prev_end {
                        count += 1;
                    }
                    prev_end = leaf_start + nested_size;
                    inner_offset = align_up(inner_offset, nested_align) + nested_size;
                    j += 1;
                }
            }
            _ => {
                if start > prev_end {
                    count += 1;
                }
                prev_end = start + field_size;
            }
        }
        offset = start + field_size;
        i += 1;
    }
    if native > prev_end {
        count += 1;
    }
    count
}

const fn hash_pads(mut hash: u64, fields: &[FieldClass], abi: ParamAbi) -> u64 {
    let native = native_size_of(fields, abi);
    let mut prev_end = 0usize;
    let mut offset = 0usize;
    let mut i = 0usize;
    while i < fields.len() {
        let field = fields[i];
        let (field_size, field_align) = field_size_align(field, abi);
        let start = align_up(offset, field_align);
        match field {
            FieldClass::Nested(inner) => {
                let mut inner_offset = 0usize;
                let mut j = 0usize;
                while j < inner.len() {
                    let (nested_size, nested_align) = flat_size_align(inner[j], abi);
                    let leaf_start = start + align_up(inner_offset, nested_align);
                    if leaf_start > prev_end {
                        hash = fnv_le32(hash, prev_end as u32);
                        hash = fnv_le32(hash, (leaf_start - prev_end) as u32);
                    }
                    prev_end = leaf_start + nested_size;
                    inner_offset = align_up(inner_offset, nested_align) + nested_size;
                    j += 1;
                }
            }
            _ => {
                if start > prev_end {
                    hash = fnv_le32(hash, prev_end as u32);
                    hash = fnv_le32(hash, (start - prev_end) as u32);
                }
                prev_end = start + field_size;
            }
        }
        offset = start + field_size;
        i += 1;
    }
    if native > prev_end {
        hash = fnv_le32(hash, prev_end as u32);
        hash = fnv_le32(hash, (native - prev_end) as u32);
    }
    hash
}

/// FNV-1a 64 over the canonical `(shape-id, ulong-size, byte-order,
/// [(field-offset, field-size)...])` tuple (S2 §3), `const`-evaluable so
/// both edges derive identical values at compile time from this table.
/// `form` is empty for primary forms, the alternate name otherwise.
/// Bare (parameterless/byte-buffer) forms never call this — they use
/// [`ABI_EXEMPT_FINGERPRINT`] via [`ResolvedShape::fingerprint`].
pub const fn layout_fingerprint(
    shape: &str,
    form: &str,
    abi: ParamAbi,
    fields: &[FieldClass],
) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    let shape_bytes = shape.as_bytes();
    hash = fnv_le32(hash, shape_bytes.len() as u32);
    hash = fnv_bytes(hash, shape_bytes);
    let form_bytes = form.as_bytes();
    hash = fnv_le32(hash, form_bytes.len() as u32);
    hash = fnv_bytes(hash, form_bytes);
    hash = fnv_le32(hash, abi.ulong_size() as u32);
    hash = fnv_le32(hash, abi.byte_order_code());
    hash = fnv_le32(hash, native_size_of(fields, abi) as u32);
    hash = fnv_le32(hash, leaf_count_of(fields) as u32);
    hash = hash_leaves(hash, fields, abi);
    hash = fnv_le32(hash, pad_count_of(fields, abi) as u32);
    hash_pads(hash, fields, abi)
}

// ─── Descriptors ─────────────────────────────────────────────────────────────

/// Outer parameter kind of a shape (S2 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OuterKind {
    /// No parameter: the mechanism takes NULL/empty params. May still
    /// carry arbitrary flat bytes to the cap (degenerate caller input).
    Parameterless,
    /// Raw bytes with no struct (IV/nonce blobs, GMAC short form).
    /// ABI-independent.
    ByteBuffer,
    /// Scalar-only struct (no pointers/handles, except the single-handle
    /// `object_handle` form guarded by `first_unsafe = 0`).
    ScalarStruct,
    /// Struct with pointer/handle fields; Flat confined to the safe
    /// prefix at or below [`first_unsafe_offset_of`].
    PointerStruct,
    /// Nested-struct pointers, output pointers, counted struct arrays,
    /// or role-dependent in/out buffers (S2 §8 tail). Typed envelopes
    /// only — never Flat.
    NestedOrOutput,
}

/// Issue #37: whether a registry shape may travel the message-opaque
/// channel (exact caller bytes, no layout handling). The channel
/// establishes neither layout nor ABI, so only byte-buffer forms may
/// ride it: every form (primary plus length-selected alternates) must
/// be [`OuterKind::ByteBuffer`] or [`OuterKind::Parameterless`].
/// Pointer-bearing struct forms embed client addresses; forwarding
/// their image hands the provider stale pointers (daemon SIGSEGV —
/// observed with `CK_CHACHA20_PARAMS` on `C_MessageEncryptInit`).
/// Scalar structs are refused too (no layout/ABI proof, plus the
/// handle-bearing `object_handle` exception), as are shapes without a
/// compiled descriptor: an unknown layout may hide pointers, so
/// vendor byte-buffer mechanisms need an explicit reviewed binding.
/// Callers fail fast (clean `MECHANISM_PARAM_INVALID`), including for
/// empty inits — an install that can never complete must never start,
/// which transitively closes Begin/Next/OneShot follow-ups.
pub fn message_opaque_admits_shape(shape_name: Option<&str>) -> bool {
    fn form_admits(kind: OuterKind) -> bool {
        matches!(kind, OuterKind::ByteBuffer | OuterKind::Parameterless)
    }
    match shape_name.and_then(ShapeResolver::descriptor) {
        None => false,
        Some(descriptor) => {
            form_admits(descriptor.outer_kind)
                && descriptor.alternate_forms.iter().all(|form| form_admits(form.outer_kind))
        }
    }
}

/// Issue #37: mechanism-level message-opaque admission. Materialized
/// bytes ride only byte-buffer shapes ([`message_opaque_admits_shape`]
/// — strict, so parameterless mechanisms with attacker bytes still
/// refuse). Empty requests additionally admit registry-declared
/// parameterless mechanisms (e.g. AES_ECB), whose empty init is their
/// normal form. Unknown mechanisms (no shape entry, not
/// parameterless) fail closed in both cases.
pub fn message_opaque_admits_mechanism(
    registry: &crate::MechanismRegistry,
    mech_type: u64,
    materialized: bool,
) -> bool {
    if message_opaque_admits_shape(registry.param_shape(mech_type)) {
        return true;
    }
    !materialized && registry.is_parameterless(mech_type)
}

/// Operation context selecting the parameter layout (S2 §4: the resolver
/// takes mechanism + operation + length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// Every non-wrap use (inits, derive, generate, unwrap, …).
    General,
    /// `C_WrapKey`: GCM/CCM select their wrap layouts by exact size.
    WrapKey,
}

/// Operation contexts for shapes usable under every operation.
pub const ALL_OPERATIONS: &[Operation] = &[Operation::General, Operation::WrapKey];

/// Operation contexts for the WrapKey-selected wrap layouts.
pub const WRAP_ONLY_OPERATIONS: &[Operation] = &[Operation::WrapKey];

/// Pointers governed by one shared length field (S2 §10/D3): when a NULL
/// pointer carries a huge length, a non-NULL companion sharing that
/// length must still be materialized and stays capped. Indices are field
/// positions (ABI-independent); `length_field` is a `Ulong` field and
/// `pointers` are `Pointer` fields (test-enforced).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedLengthGroup {
    /// Index of the governing length field.
    pub length_field: u8,
    /// Indices of the governed pointer fields (≥ 2).
    pub pointers: &'static [u8],
}

/// Length-selected alternate form of a shape (union member).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlternateForm {
    /// Form name (part of the fingerprint shape-id as `name#form`).
    pub name: &'static str,
    /// Outer kind of this form.
    pub outer_kind: OuterKind,
    /// Field sequence of this form.
    pub fields: &'static [FieldClass],
    /// Companion sets of this form (empty in v1).
    pub shared_length_groups: &'static [SharedLengthGroup],
    /// Whether this form's fields embed a virtual handle.
    pub contains_virtual_handle: bool,
}

/// Immutable compiled descriptor for one parameter shape (S2 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShapeDescriptor {
    /// Shape name (the TOML `[[params]]` binding key).
    pub name: &'static str,
    /// Outer kind of the primary form.
    pub outer_kind: OuterKind,
    /// Field sequence of the primary form (empty for
    /// parameterless/byte-buffer forms, which carry no layout).
    pub fields: &'static [FieldClass],
    /// Length-selected alternate forms (≤ 1 in v1).
    pub alternate_forms: &'static [AlternateForm],
    /// Operations this shape applies to.
    pub operations: &'static [Operation],
    /// Shared-length companion sets (S2 §10/D3).
    pub shared_length_groups: &'static [SharedLengthGroup],
    /// Whether the primary form's fields embed a virtual handle.
    pub contains_virtual_handle: bool,
}

// Shared field sequences (one struct, two shapes): CK_GCM_PARAMS backs
// both "gcm" and the "gcm_compat" struct form; both TLS/WTLS random-data
// structs share the same pointer/length layout.
const GCM_FIELDS: &[FieldClass] = {
    use FieldClass::{Pointer, Ulong};
    &[Pointer, Ulong, Ulong, Pointer, Ulong, Ulong]
};

const RANDOM_DATA_INNER_FIELDS: &[FieldClass] = {
    use FieldClass::{Pointer, Ulong};
    &[Pointer, Ulong, Pointer, Ulong]
};

// Row constructors: one line per common shape; the seven special rows
// (unions, wrap-only ops, companion sets) use struct literals.
const fn bare_shape(name: &'static str, outer_kind: OuterKind) -> ShapeDescriptor {
    ShapeDescriptor {
        name,
        outer_kind,
        fields: &[],
        alternate_forms: &[],
        operations: ALL_OPERATIONS,
        shared_length_groups: &[],
        contains_virtual_handle: false,
    }
}

const fn scalar_shape(name: &'static str, fields: &'static [FieldClass]) -> ShapeDescriptor {
    ShapeDescriptor {
        name,
        outer_kind: OuterKind::ScalarStruct,
        fields,
        alternate_forms: &[],
        operations: ALL_OPERATIONS,
        shared_length_groups: &[],
        contains_virtual_handle: false,
    }
}

const fn pointer_shape(name: &'static str, fields: &'static [FieldClass]) -> ShapeDescriptor {
    ShapeDescriptor {
        name,
        outer_kind: OuterKind::PointerStruct,
        fields,
        alternate_forms: &[],
        operations: ALL_OPERATIONS,
        shared_length_groups: &[],
        contains_virtual_handle: false,
    }
}

const fn pointer_shape_with_handle(
    name: &'static str,
    fields: &'static [FieldClass],
) -> ShapeDescriptor {
    ShapeDescriptor {
        name,
        outer_kind: OuterKind::PointerStruct,
        fields,
        alternate_forms: &[],
        operations: ALL_OPERATIONS,
        shared_length_groups: &[],
        contains_virtual_handle: true,
    }
}

const fn nested_shape(name: &'static str, fields: &'static [FieldClass]) -> ShapeDescriptor {
    ShapeDescriptor {
        name,
        outer_kind: OuterKind::NestedOrOutput,
        fields,
        alternate_forms: &[],
        operations: ALL_OPERATIONS,
        shared_length_groups: &[],
        contains_virtual_handle: false,
    }
}

const fn nested_shape_with_handle(
    name: &'static str,
    fields: &'static [FieldClass],
) -> ShapeDescriptor {
    ShapeDescriptor {
        name,
        outer_kind: OuterKind::NestedOrOutput,
        fields,
        alternate_forms: &[],
        operations: ALL_OPERATIONS,
        shared_length_groups: &[],
        contains_virtual_handle: true,
    }
}

/// The compiled shape table: every classic parameter shape the proxy
/// compiles (S2 §4). Sorted by name (binary search); 68 entries — 56
/// registry-bound, 11 reader-only/operation-selected, and the synthetic
/// parameterless marker. Field comments cite the OASIS struct and its
/// field order; sizes/offsets are cross-checked against `cryptoki-sys`.
pub const SHAPE_DESCRIPTORS: &[ShapeDescriptor] = {
    use FieldClass::{Bytes, Handle, Nested, Pointer, U8, Ulong};
    use OuterKind::ByteBuffer;
    &[
        // CK_AES_CBC_ENCRYPT_DATA_PARAMS: iv[16], pData, length.
        pointer_shape("aes_cbc_encrypt_data", &[Bytes(16), Pointer, Ulong]),
        // CK_AES_CTR_PARAMS: ulCounterBits, cb[16].
        scalar_shape("aes_ctr", &[Ulong, Bytes(16)]),
        // CK_ARIA_CBC_ENCRYPT_DATA_PARAMS: iv[16], pData, length.
        pointer_shape("aria_cbc_encrypt_data", &[Bytes(16), Pointer, Ulong]),
        // CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS: iv[16], pData, length.
        pointer_shape("camellia_cbc_encrypt_data", &[Bytes(16), Pointer, Ulong]),
        // CK_CAMELLIA_CTR_PARAMS: ulCounterBits, cb[16].
        scalar_shape("camellia_ctr", &[Ulong, Bytes(16)]),
        // CK_CCM_PARAMS: ulDataLen, pNonce, ulNonceLen, pAAD, ulAADLen, ulMACLen.
        pointer_shape("ccm", &[Ulong, Pointer, Ulong, Pointer, Ulong, Ulong]),
        // CK_CCM_WRAP_PARAMS: + ulNonceFixedBits, nonceGenerator. WrapKey-only.
        ShapeDescriptor {
            name: "ccm_wrap",
            outer_kind: OuterKind::PointerStruct,
            fields: &[Ulong, Pointer, Ulong, Ulong, Ulong, Pointer, Ulong, Ulong],
            alternate_forms: &[],
            operations: WRAP_ONLY_OPERATIONS,
            shared_length_groups: &[],
            contains_virtual_handle: false,
        },
        // CK_CHACHA20_PARAMS: pBlockCounter, blockCounterBits, pNonce, ulNonceBits.
        pointer_shape("chacha20", &[Pointer, Ulong, Pointer, Ulong]),
        // CK_DES_CBC_ENCRYPT_DATA_PARAMS: iv[8], pData, length.
        pointer_shape("des_cbc_encrypt_data", &[Bytes(8), Pointer, Ulong]),
        // CK_ECDH1_DERIVE_PARAMS: kdf, ulSharedDataLen, pSharedData, ulPublicDataLen, pPublicData.
        pointer_shape("ecdh1_derive", &[Ulong, Ulong, Pointer, Ulong, Pointer]),
        // CK_ECDH2_DERIVE_PARAMS: + ulPrivateDataLen, hPrivateData, ulPublicDataLen2, pPublicData2.
        pointer_shape_with_handle(
            "ecdh2_derive",
            &[Ulong, Ulong, Pointer, Ulong, Pointer, Ulong, Handle, Ulong, Pointer],
        ),
        // CK_ECDH_AES_KEY_WRAP_PARAMS: ulAESKeyBits, kdf, ulSharedDataLen, pSharedData.
        pointer_shape("ecdh_aes_key_wrap", &[Ulong, Ulong, Ulong, Pointer]),
        // CK_ECMQV_DERIVE_PARAMS: ECDH2 + publicKey handle.
        pointer_shape_with_handle(
            "ecmqv_derive",
            &[Ulong, Ulong, Pointer, Ulong, Pointer, Ulong, Handle, Ulong, Pointer, Handle],
        ),
        // CK_EDDSA_PARAMS: phFlag, ulContextDataLen, pContextData.
        pointer_shape("eddsa", &[U8, Ulong, Pointer]),
        // CK_EXTRACT_PARAMS: single CK_ULONG bit position.
        scalar_shape("extract", &[Ulong]),
        // CK_GCM_PARAMS: pIv, ulIvLen, ulIvBits, pAAD, ulAADLen, ulTagBits.
        pointer_shape("gcm", GCM_FIELDS),
        // GMAC dual encoding: short buffers are flat IV bytes, struct-sized
        // buffers are CK_GCM_PARAMS (selected by length).
        ShapeDescriptor {
            name: "gcm_compat",
            outer_kind: ByteBuffer,
            fields: &[],
            alternate_forms: &[AlternateForm {
                name: "struct",
                outer_kind: OuterKind::PointerStruct,
                fields: GCM_FIELDS,
                shared_length_groups: &[],
                contains_virtual_handle: false,
            }],
            operations: ALL_OPERATIONS,
            shared_length_groups: &[],
            contains_virtual_handle: false,
        },
        // CK_GCM_WRAP_PARAMS: pIv, ulIvLen, ulIvFixedBits, ivGenerator, pAAD, ulAADLen, ulTagBits.
        ShapeDescriptor {
            name: "gcm_wrap",
            outer_kind: OuterKind::PointerStruct,
            fields: &[Pointer, Ulong, Ulong, Ulong, Pointer, Ulong, Ulong],
            alternate_forms: &[],
            operations: WRAP_ONLY_OPERATIONS,
            shared_length_groups: &[],
            contains_virtual_handle: false,
        },
        // CK_GOSTR3410_DERIVE_PARAMS: kdf, pPublicData, ulPublicDataLen, pUKM, ulUKMLen.
        pointer_shape("gostr3410_derive", &[Ulong, Pointer, Ulong, Pointer, Ulong]),
        // CK_GOSTR3410_KEY_WRAP_PARAMS: pWrapOID, ulWrapOIDLen, pUKM, ulUKMLen, hKey.
        pointer_shape_with_handle("gostr3410_key_wrap", &[Pointer, Ulong, Pointer, Ulong, Handle]),
        // CK_HKDF_PARAMS: bExtract, bExpand, prfHashMechanism, ulSaltType, pSalt, ulSaltLen,
        // hSaltKey, pInfo, ulInfoLen.
        pointer_shape_with_handle(
            "hkdf",
            &[U8, U8, Ulong, Ulong, Pointer, Ulong, Handle, Pointer, Ulong],
        ),
        // CK_IKE1_EXTENDED_DERIVE_PARAMS: prfMechanism, bHasKeygxy, hKeygxy, pExtraData, ulExtraDataLen.
        pointer_shape_with_handle("ike1_extended_derive", &[Ulong, U8, Handle, Pointer, Ulong]),
        // CK_IKE1_PRF_DERIVE_PARAMS: prfMechanism, bHasPrevKey, hKeygxy, hPrevKey, pCKYi,
        // ulCKYiLen, pCKYr, ulCKYrLen, keyNumber.
        pointer_shape_with_handle(
            "ike1_prf_derive",
            &[Ulong, U8, Handle, Handle, Pointer, Ulong, Pointer, Ulong, U8],
        ),
        // CK_IKE2_PRF_PLUS_DERIVE_PARAMS: prfMechanism, bHasSeedKey, hSeedKey, pSeedData, ulSeedDataLen.
        pointer_shape_with_handle("ike2_prf_plus_derive", &[Ulong, U8, Handle, Pointer, Ulong]),
        // CK_IKE_PRF_DERIVE_PARAMS: prfMechanism, bDataAsKey, bRekey, pNi, ulNiLen, pNr, ulNrLen, hNewKey.
        pointer_shape_with_handle(
            "ike_prf_derive",
            &[Ulong, U8, U8, Pointer, Ulong, Pointer, Ulong, Handle],
        ),
        // Raw IV/nonce bytes: no struct.
        bare_shape("iv", ByteBuffer),
        // CK_KEA_DERIVE_PARAMS: isSender, ulRandomLen, RandomA, RandomB, ulPublicDataLen,
        // PublicData. RandomA/RandomB share ulRandomLen (S2 §10/D3 companions); the buffers are
        // role-dependent in/out (tail shape).
        ShapeDescriptor {
            name: "kea_derive",
            outer_kind: OuterKind::NestedOrOutput,
            fields: &[U8, Ulong, Pointer, Pointer, Ulong, Pointer],
            alternate_forms: &[],
            operations: ALL_OPERATIONS,
            shared_length_groups: &[SharedLengthGroup { length_field: 1, pointers: &[2, 3] }],
            contains_virtual_handle: false,
        },
        // CK_KEY_DERIVATION_STRING_DATA: pData, ulLen.
        pointer_shape("key_derivation_string", &[Pointer, Ulong]),
        // CK_KEY_WRAP_SET_OAEP_PARAMS: bBC, pX, ulXLen.
        pointer_shape("key_wrap_set_oaep", &[U8, Pointer, Ulong]),
        // CK_KIP_PARAMS: pMechanism (nested), hKey, pSeed, ulSeedLen.
        nested_shape_with_handle("kip", &[Pointer, Handle, Pointer, Ulong]),
        // Local KMAC mirror (no OASIS struct): h_key, ul_mac_length, p_customization_string,
        // ul_customization_string_len.
        pointer_shape_with_handle("kmac", &[Handle, Ulong, Pointer, Ulong]),
        // CK_MAC_GENERAL_PARAMS: single CK_ULONG length.
        scalar_shape("mac_general", &[Ulong]),
        // Local ML-DSA-mu mirror (no OASIS struct): h_key, p_tr, ul_tr_len, p_ctx, ul_ctx_len.
        pointer_shape_with_handle("mu_gen", &[Handle, Pointer, Ulong, Pointer, Ulong]),
        // CK_OBJECT_HANDLE: single handle (scalar class, unsafe at 0).
        ShapeDescriptor {
            name: "object_handle",
            outer_kind: OuterKind::ScalarStruct,
            fields: &[Handle],
            alternate_forms: &[],
            operations: ALL_OPERATIONS,
            shared_length_groups: &[],
            contains_virtual_handle: true,
        },
        // CK_OTP_PARAMS: pParams (array of CK_OTP_PARAM), ulCount.
        nested_shape("otp", &[Pointer, Ulong]),
        // Synthetic marker for the parameterless-listing rule (never TOML-bound).
        bare_shape("parameterless", OuterKind::Parameterless),
        // CK_PBE_PARAMS: pInitVector, pPassword, ulPasswordLen, pSalt, ulSaltLen, ulIteration.
        pointer_shape("pbe", &[Pointer, Pointer, Ulong, Pointer, Ulong, Ulong]),
        // CK_PKCS5_PBKD2_PARAMS2: saltSource, pSaltSourceData, ulSaltSourceDataLen, iterations, prf,
        // pPrfData, ulPrfDataLen, pPassword, ulPasswordLen.
        pointer_shape(
            "pkcs5_pbkd2",
            &[Ulong, Pointer, Ulong, Ulong, Ulong, Pointer, Ulong, Pointer, Ulong],
        ),
        // CK_RC2_CBC_PARAMS: ulEffectiveBits, iv[8].
        scalar_shape("rc2_cbc", &[Ulong, Bytes(8)]),
        // CK_RC2_MAC_GENERAL_PARAMS: ulEffectiveBits, ulMacLength.
        scalar_shape("rc2_mac_general", &[Ulong, Ulong]),
        // CK_RC5_PARAMS: ulWordsize, ulRounds.
        scalar_shape("rc5", &[Ulong, Ulong]),
        // CK_RC5_CBC_PARAMS: ulWordsize, ulRounds, pIv, ulIvLen.
        pointer_shape("rc5_cbc", &[Ulong, Ulong, Pointer, Ulong]),
        // CK_RC5_MAC_GENERAL_PARAMS: ulWordsize, ulRounds, ulMacLength.
        scalar_shape("rc5_mac_general", &[Ulong, Ulong, Ulong]),
        // CK_RSA_AES_KEY_WRAP_PARAMS: ulAESKeyBits, pOAEPParams (nested, past the safe prefix).
        pointer_shape("rsa_aes_key_wrap", &[Ulong, Pointer]),
        // CK_RSA_PKCS_OAEP_PARAMS: hashAlg, mgf, source, pSourceData, ulSourceDataLen.
        pointer_shape("rsa_oaep", &[Ulong, Ulong, Ulong, Pointer, Ulong]),
        // CK_RSA_PKCS_PSS_PARAMS: hashAlg, mgf, sLen.
        scalar_shape("rsa_pss", &[Ulong, Ulong, Ulong]),
        // CK_SALSA20_PARAMS: pBlockCounter, pNonce, ulNonceBits.
        pointer_shape("salsa20", &[Pointer, Pointer, Ulong]),
        // CK_SALSA20_CHACHA20_POLY1305_PARAMS: pNonce, ulNonceLen, pAAD, ulAADLen.
        pointer_shape("salsa20_chacha20_poly1305", &[Pointer, Ulong, Pointer, Ulong]),
        // CK_SEED_CBC_ENCRYPT_DATA_PARAMS: iv[16], pData, length.
        pointer_shape("seed_cbc_encrypt_data", &[Bytes(16), Pointer, Ulong]),
        // CK_SIGN_ADDITIONAL_CONTEXT: hedgeVariant, pContext, ulContextLen; the generic hash variant
        // appends a trailing hash mechanism (selected by length).
        ShapeDescriptor {
            name: "sign_additional_context",
            outer_kind: OuterKind::PointerStruct,
            fields: &[Ulong, Pointer, Ulong],
            alternate_forms: &[AlternateForm {
                name: "hash",
                outer_kind: OuterKind::PointerStruct,
                fields: &[Ulong, Pointer, Ulong, Ulong],
                shared_length_groups: &[],
                contains_virtual_handle: false,
            }],
            operations: ALL_OPERATIONS,
            shared_length_groups: &[],
            contains_virtual_handle: false,
        },
        // CK_SKIPJACK_PRIVATE_WRAP_PARAMS: password/public lengths + pointers, ulPAndGLen, ulQLen,
        // ulRandomLen, pRandomA, pPrimeP, pBaseG, pSubprimeQ. pPrimeP/pBaseG share ulPAndGLen.
        ShapeDescriptor {
            name: "skipjack_private_wrap",
            outer_kind: OuterKind::NestedOrOutput,
            fields: &[
                Ulong, Pointer, Ulong, Pointer, Ulong, Ulong, Ulong, Pointer, Pointer, Pointer,
                Pointer,
            ],
            alternate_forms: &[],
            operations: ALL_OPERATIONS,
            shared_length_groups: &[SharedLengthGroup { length_field: 4, pointers: &[8, 9] }],
            contains_virtual_handle: false,
        },
        // CK_SKIPJACK_RELAYX_PARAMS: seven (length, pointer) wrap pairs.
        nested_shape(
            "skipjack_relayx",
            &[
                Ulong, Pointer, Ulong, Pointer, Ulong, Pointer, Ulong, Pointer, Ulong, Pointer,
                Ulong, Pointer, Ulong, Pointer,
            ],
        ),
        // CK_SP800_108_FEEDBACK_KDF_PARAMS: prfType, ulNumberOfDataParams, pDataParams, ulIVLen, pIV,
        // ulAdditionalDerivedKeys, pAdditionalDerivedKeys (output array).
        nested_shape(
            "sp800_108_feedback_kdf",
            &[Ulong, Ulong, Pointer, Ulong, Pointer, Ulong, Pointer],
        ),
        // CK_SP800_108_KDF_PARAMS: prfType, ulNumberOfDataParams, pDataParams,
        // ulAdditionalDerivedKeys, pAdditionalDerivedKeys (output array).
        nested_shape("sp800_108_kdf", &[Ulong, Ulong, Pointer, Ulong, Pointer]),
        // CK_SSL3_KEY_MAT_PARAMS: ulMacSizeInBits, ulKeySizeInBits, ulIVSizeInBits, bIsExport,
        // RandomInfo (inline), pReturnedKeyMaterial (output). The TLS 1.2 superset appends
        // prfHashMechanism (selected by length).
        ShapeDescriptor {
            name: "ssl3_key_mat",
            outer_kind: OuterKind::NestedOrOutput,
            fields: &[Ulong, Ulong, Ulong, U8, Nested(RANDOM_DATA_INNER_FIELDS), Pointer],
            alternate_forms: &[AlternateForm {
                name: "tls12",
                outer_kind: OuterKind::NestedOrOutput,
                fields: &[
                    Ulong,
                    Ulong,
                    Ulong,
                    U8,
                    Nested(RANDOM_DATA_INNER_FIELDS),
                    Pointer,
                    Ulong,
                ],
                shared_length_groups: &[],
                contains_virtual_handle: false,
            }],
            operations: ALL_OPERATIONS,
            shared_length_groups: &[],
            contains_virtual_handle: false,
        },
        // CK_SSL3_MASTER_KEY_DERIVE_PARAMS: RandomInfo (inline), pVersion.
        pointer_shape("ssl3_master_key_derive", &[Nested(RANDOM_DATA_INNER_FIELDS), Pointer]),
        // CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS: prfHashMechanism, pSessionHash,
        // ulSessionHashLen, pVersion.
        pointer_shape("tls12_extended_master_key_derive", &[Ulong, Pointer, Ulong, Pointer]),
        // CK_TLS12_MASTER_KEY_DERIVE_PARAMS: RandomInfo (inline), pVersion, prfHashMechanism.
        pointer_shape(
            "tls12_master_key_derive",
            &[Nested(RANDOM_DATA_INNER_FIELDS), Pointer, Ulong],
        ),
        // CK_TLS_KDF_PARAMS: prfMechanism, pLabel, ulLabelLength, RandomInfo (inline), pContextData,
        // ulContextDataLength.
        pointer_shape(
            "tls_kdf",
            &[Ulong, Pointer, Ulong, Nested(RANDOM_DATA_INNER_FIELDS), Pointer, Ulong],
        ),
        // CK_TLS_MAC_PARAMS: prfHashMechanism, ulMacLength, ulServerOrClient.
        scalar_shape("tls_mac", &[Ulong, Ulong, Ulong]),
        // CK_TLS_PRF_PARAMS: pSeed, ulSeedLen, pLabel, ulLabelLen, pOutput, pulOutputLen (output).
        nested_shape("tls_prf", &[Pointer, Ulong, Pointer, Ulong, Pointer, Pointer]),
        // CK_WTLS_KEY_MAT_PARAMS: DigestMechanism, ulMacSizeInBits, ulKeySizeInBits, ulIVSizeInBits,
        // ulSequenceNumber, bIsExport, RandomInfo (inline), pReturnedKeyMaterial (output).
        nested_shape(
            "wtls_key_mat",
            &[Ulong, Ulong, Ulong, Ulong, Ulong, U8, Nested(RANDOM_DATA_INNER_FIELDS), Pointer],
        ),
        // CK_WTLS_MASTER_KEY_DERIVE_PARAMS: DigestMechanism, RandomInfo (inline), pVersion.
        pointer_shape(
            "wtls_master_key_derive",
            &[Ulong, Nested(RANDOM_DATA_INNER_FIELDS), Pointer],
        ),
        // CK_WTLS_PRF_PARAMS: DigestMechanism, pSeed, ulSeedLen, pLabel, ulLabelLen, pOutput,
        // pulOutputLen (output).
        nested_shape("wtls_prf", &[Ulong, Pointer, Ulong, Pointer, Ulong, Pointer, Pointer]),
        // CK_X9_42_DH1_DERIVE_PARAMS: kdf, ulOtherInfoLen, pOtherInfo, ulPublicDataLen, pPublicData.
        pointer_shape("x942_dh1_derive", &[Ulong, Ulong, Pointer, Ulong, Pointer]),
        // CK_X9_42_DH2_DERIVE_PARAMS: + ulPrivateDataLen, hPrivateData, ulPublicDataLen2, pPublicData2.
        pointer_shape_with_handle(
            "x942_dh2_derive",
            &[Ulong, Ulong, Pointer, Ulong, Pointer, Ulong, Handle, Ulong, Pointer],
        ),
        // CK_X9_42_MQV_DERIVE_PARAMS: DH2 + publicKey handle.
        pointer_shape_with_handle(
            "x942_mqv_derive",
            &[Ulong, Ulong, Pointer, Ulong, Pointer, Ulong, Handle, Ulong, Pointer, Handle],
        ),
        // CK_XEDDSA_PARAMS: single hash mechanism.
        scalar_shape("xeddsa", &[Ulong]),
    ]
};

// ─── Resolver ────────────────────────────────────────────────────────────────

/// Operation context selecting a parameter layout: mechanism + operation +
/// declared length (S2 §4). A plain one-shape-per-mechanism map is
/// insufficient: WrapKey selects the GCM/CCM wrap layouts by
/// operation+length, and unions select by length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperationContext {
    /// `CK_MECHANISM_TYPE` value.
    pub mechanism: u64,
    /// Operation the mechanism is used under.
    pub operation: Operation,
    /// Declared parameter length (`ulParameterLen`).
    pub length: u64,
}

/// A resolved shape: compiled descriptor plus selected form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedShape {
    /// The compiled descriptor (registry-bound or operation-selected).
    pub descriptor: &'static ShapeDescriptor,
    /// Selected alternate form, or `None` for the primary form.
    pub alternate: Option<&'static AlternateForm>,
}

impl ResolvedShape {
    /// Resolve to the primary form of a descriptor.
    pub const fn primary(descriptor: &'static ShapeDescriptor) -> Self {
        Self { descriptor, alternate: None }
    }

    /// Outer kind of the selected form.
    pub const fn outer_kind(self) -> OuterKind {
        match self.alternate {
            Some(form) => form.outer_kind,
            None => self.descriptor.outer_kind,
        }
    }

    /// Field sequence of the selected form.
    pub const fn fields(self) -> &'static [FieldClass] {
        match self.alternate {
            Some(form) => form.fields,
            None => self.descriptor.fields,
        }
    }

    /// Form name of the selected form (empty for primary forms).
    pub const fn form_name(self) -> &'static str {
        match self.alternate {
            Some(form) => form.name,
            None => "",
        }
    }

    /// Native size of the selected form under `abi`, or `None` for bare
    /// (parameterless/byte-buffer) forms, which carry no layout.
    pub const fn native_size(self, abi: ParamAbi) -> Option<usize> {
        if self.fields().is_empty() { None } else { Some(native_size_of(self.fields(), abi)) }
    }

    /// First unsafe offset of the selected form under `abi`.
    pub const fn first_unsafe_offset(self, abi: ParamAbi) -> Option<usize> {
        first_unsafe_offset_of(self.fields(), abi)
    }

    /// Expected wire fingerprint of the selected form under `abi`: the
    /// layout fingerprint for struct forms, the ABI-exempt marker for
    /// bare forms (S2 §3).
    pub const fn fingerprint(self, abi: ParamAbi) -> u64 {
        if self.fields().is_empty() {
            ABI_EXEMPT_FINGERPRINT
        } else {
            layout_fingerprint(self.descriptor.name, self.form_name(), abi, self.fields())
        }
    }

    /// Whether the selected form embeds a virtual handle.
    pub const fn contains_virtual_handle(self) -> bool {
        match self.alternate {
            Some(form) => form.contains_virtual_handle,
            None => self.descriptor.contains_virtual_handle,
        }
    }
}

/// Resolver from registry bindings + operation context to compiled
/// descriptors (S2 §4). Both edges resolve identically from their own
/// compiled tables (S2 §2 principle 2: server-derived eligibility, no
/// client "safe" flag); the resolver never trusts caller metadata.
pub struct ShapeResolver;

impl ShapeResolver {
    /// Look up a compiled descriptor by shape name.
    pub fn descriptor(shape: &str) -> Option<&'static ShapeDescriptor> {
        SHAPE_DESCRIPTORS
            .binary_search_by(|candidate| candidate.name.cmp(shape))
            .ok()
            .map(|index| &SHAPE_DESCRIPTORS[index])
    }

    fn wrap_native_len(name: &str, abi: ParamAbi) -> Option<u64> {
        Self::descriptor(name)
            .and_then(|descriptor| ResolvedShape::primary(descriptor).native_size(abi))
            .map(|size| size as u64)
    }

    /// Resolve a registry-bound shape name plus operation context to a
    /// compiled descriptor and form.
    ///
    /// - Under [`Operation::WrapKey`], `CKM_AES_GCM`/`CKM_AES_CCM` with a
    ///   declared length exactly equal to the wrap struct's local native
    ///   size select `gcm_wrap`/`ccm_wrap` (mirroring the shim's wrap-key
    ///   reader); every other case falls back to the registry binding.
    /// - Length-selected unions (`gcm_compat`, `sign_additional_context`,
    ///   `ssl3_key_mat`) take the first alternate form whose local native
    ///   size fits the declared length, else the primary form.
    ///
    /// Returns `None` for unbound mechanisms and unknown shape names.
    /// Total over lengths: every length yields a defined form for a
    /// known shape (degenerate lengths resolve so the Flat rules can
    /// judge them; see [`decide_flat`]).
    pub fn resolve(
        bound_shape: Option<&str>,
        ctx: OperationContext,
        local_abi: ParamAbi,
    ) -> Option<ResolvedShape> {
        if ctx.operation == Operation::WrapKey {
            if ctx.mechanism == CkMechanismType::AES_GCM.0
                && Some(ctx.length) == Self::wrap_native_len("gcm_wrap", local_abi)
            {
                return Self::descriptor("gcm_wrap").map(ResolvedShape::primary);
            }
            if ctx.mechanism == CkMechanismType::AES_CCM.0
                && Some(ctx.length) == Self::wrap_native_len("ccm_wrap", local_abi)
            {
                return Self::descriptor("ccm_wrap").map(ResolvedShape::primary);
            }
        }
        let descriptor = Self::descriptor(bound_shape?)?;
        let alternate = descriptor
            .alternate_forms
            .iter()
            .find(|form| ctx.length >= native_size_of(form.fields, local_abi) as u64);
        Some(ResolvedShape { descriptor, alternate })
    }
}

// ─── Server Flat-eligibility rules (pure functions, S2 §4) ───────────────────

/// Maximum flat parameter extent in bytes (S2 §3 64 KiB outer cap).
pub const FLAT_MAX_BYTES: u64 = 64 * 1024;

/// First vendor-defined `CK_MECHANISM_TYPE` (OASIS vendor range
/// `0x8000_0000..=0xFFFF_FFFF`).
pub const VENDOR_MECHANISM_MIN: u64 = 0x8000_0000;

/// Compiled vendor Flat allowlist: `(mechanism, shape)` pairs whose Flat
/// forms the proxy has reviewed. TOML can never extend this — only a code
/// change adding a compiled entry authorizes vendor Flat (S2 §4). Empty
/// in v1: no vendor Flat rides.
pub const VENDOR_FLAT_ALLOWLIST: &[(u64, &str)] = &[];

/// Whether a mechanism ID is vendor-defined.
pub const fn is_vendor_mechanism(mechanism: u64) -> bool {
    mechanism >= VENDOR_MECHANISM_MIN
}

/// Whether the compiled vendor allowlist authorizes Flat for a vendor
/// mechanism. Matching is exact on `(mechanism, effective shape)`, where
/// the effective shape is the bound param shape when one is registered
/// (param shape wins over the parameterless listing) and the
/// `parameterless` marker for parameterless-listed IDs.
pub fn vendor_flat_allowed(
    allowlist: &[(u64, &str)],
    mechanism: u64,
    bound_shape: Option<&str>,
    parameterless_listed: bool,
) -> bool {
    let effective = match (bound_shape, parameterless_listed) {
        (Some(shape), _) => Some(shape),
        (None, true) => Some("parameterless"),
        (None, false) => None,
    };
    match effective {
        Some(shape) => allowlist.iter().any(|(id, name)| *id == mechanism && *name == shape),
        None => false,
    }
}

/// Inputs to the Flat-eligibility decision (plain data; see
/// [`decide_flat_for_registry`] for the registry-fed convenience form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlatRequest<'a> {
    /// `CK_MECHANISM_TYPE` value.
    pub mechanism: u64,
    /// Operation the mechanism is used under.
    pub operation: Operation,
    /// Declared parameter length (`ulParameterLen`).
    pub declared_len: u64,
    /// Registry-bound param shape name, if any.
    pub bound_shape: Option<&'a str>,
    /// Whether the registry lists the mechanism as parameterless.
    pub parameterless_listed: bool,
    /// Whether the operator excluded the mechanism.
    pub excluded: bool,
    /// Wire-sent layout fingerprint.
    pub peer_fingerprint: u64,
    /// Wire-sent source ABI.
    pub peer_abi: ParamAbi,
    /// Deciding edge's native ABI.
    pub local_abi: ParamAbi,
}

/// Why Flat carriage was denied (R9 maps every variant to
/// `PARAM_INVALID` per the S2 §6 RV table; see [`FlatDecision::Excluded`]
/// for the exclusion case).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlatDenyReason {
    /// Declared length exceeds the 64 KiB outer cap.
    OverCap,
    /// Vendor mechanism without a compiled allowlist entry.
    VendorWithoutAllowlist,
    /// No descriptor for the (bound or unbound) mechanism.
    UnknownShape,
    /// Nested/output shapes ride typed envelopes only, never Flat.
    NestedOrOutput,
    /// Full native images ride the typed path, never Flat.
    FullNativeImage,
    /// Struct prefix from a foreign ABI.
    AbiMismatch {
        /// Deciding edge's ABI.
        expected: ParamAbi,
        /// Wire-sent ABI.
        got: ParamAbi,
    },
    /// Layout fingerprint mismatch.
    FingerprintMismatch {
        /// Locally computed fingerprint.
        expected: u64,
        /// Wire-sent fingerprint.
        got: u64,
    },
    /// Declared length reaches past the safe prefix.
    PrefixTooLong {
        /// Declared length.
        declared_len: u64,
        /// First unsafe offset under the local ABI.
        first_unsafe_offset: u64,
    },
}

/// Granted Flat carriage: the resolution plus the expected wire
/// fingerprint (ABI-exempt marker for bare forms).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlatGrant {
    /// Resolved shape and form.
    pub resolved: ResolvedShape,
    /// Expected wire fingerprint under the local ABI.
    pub fingerprint: u64,
    /// Deciding edge's native ABI.
    pub local_abi: ParamAbi,
}

/// Flat-eligibility decision (S2 §4 server rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlatDecision {
    /// Flat carriage granted.
    Eligible(FlatGrant),
    /// Flat carriage denied (R9: `PARAM_INVALID`).
    Denied(FlatDenyReason),
    /// Operator-excluded mechanism (R9: `MECHANISM_INVALID`).
    Excluded,
}

/// Decide Flat carriage for a non-NULL parameter extent (S2 §4 server
/// rules, in order):
///
/// 1. Operator exclusion wins ([`FlatDecision::Excluded`]).
/// 2. Declared lengths above the 64 KiB outer cap are denied.
/// 3. Vendor mechanisms without a compiled allowlist entry are denied
///    (TOML binding alone never authorizes vendor Flat).
/// 4. Resolution: a registered param shape wins over a dual
///    parameterless listing (EdDSA-smuggling block); parameterless-only
///    mechanisms may carry arbitrary flat bytes to the cap,
///    ABI-independent; anything else without a descriptor is denied.
/// 5. Byte-buffer forms ride ABI-independent with the exempt marker;
///    nested/output forms are denied; struct forms deny full native
///    images, require exact ABI equality and a fingerprint match, and
///    confine the declared length at or below the first unsafe offset
///    (when the form has one).
///
/// Pure and total: no panics, no I/O, no registry access (see
/// [`decide_flat_for_registry`] for the registry-fed form).
pub fn decide_flat(req: FlatRequest) -> FlatDecision {
    if req.excluded {
        return FlatDecision::Excluded;
    }
    if req.declared_len > FLAT_MAX_BYTES {
        return FlatDecision::Denied(FlatDenyReason::OverCap);
    }
    if is_vendor_mechanism(req.mechanism)
        && !vendor_flat_allowed(
            VENDOR_FLAT_ALLOWLIST,
            req.mechanism,
            req.bound_shape,
            req.parameterless_listed,
        )
    {
        return FlatDecision::Denied(FlatDenyReason::VendorWithoutAllowlist);
    }
    let ctx = OperationContext {
        mechanism: req.mechanism,
        operation: req.operation,
        length: req.declared_len,
    };
    let Some(resolved) = ShapeResolver::resolve(req.bound_shape, ctx, req.local_abi) else {
        if req.bound_shape.is_none()
            && req.parameterless_listed
            && let Some(descriptor) = ShapeResolver::descriptor("parameterless")
        {
            return FlatDecision::Eligible(FlatGrant {
                resolved: ResolvedShape::primary(descriptor),
                fingerprint: ABI_EXEMPT_FINGERPRINT,
                local_abi: req.local_abi,
            });
        }
        return FlatDecision::Denied(FlatDenyReason::UnknownShape);
    };
    match resolved.outer_kind() {
        OuterKind::Parameterless | OuterKind::ByteBuffer => FlatDecision::Eligible(FlatGrant {
            resolved,
            fingerprint: ABI_EXEMPT_FINGERPRINT,
            local_abi: req.local_abi,
        }),
        OuterKind::NestedOrOutput => FlatDecision::Denied(FlatDenyReason::NestedOrOutput),
        OuterKind::ScalarStruct | OuterKind::PointerStruct => {
            if Some(req.declared_len) == resolved.native_size(req.local_abi).map(|size| size as u64)
            {
                return FlatDecision::Denied(FlatDenyReason::FullNativeImage);
            }
            if req.peer_abi != req.local_abi {
                return FlatDecision::Denied(FlatDenyReason::AbiMismatch {
                    expected: req.local_abi,
                    got: req.peer_abi,
                });
            }
            let expected = resolved.fingerprint(req.local_abi);
            if req.peer_fingerprint != expected {
                return FlatDecision::Denied(FlatDenyReason::FingerprintMismatch {
                    expected,
                    got: req.peer_fingerprint,
                });
            }
            match resolved.first_unsafe_offset(req.local_abi) {
                Some(first) if req.declared_len <= first as u64 => {}
                Some(first) => {
                    return FlatDecision::Denied(FlatDenyReason::PrefixTooLong {
                        declared_len: req.declared_len,
                        first_unsafe_offset: first as u64,
                    });
                }
                None => {}
            }
            FlatDecision::Eligible(FlatGrant {
                resolved,
                fingerprint: expected,
                local_abi: req.local_abi,
            })
        }
    }
}

/// Registry-fed [`decide_flat`]: binds `mechanism` through `registry`
/// (param shape, parameterless listing, operator exclusion) and decides.
/// The daemon calls this once per request against its own registry
/// snapshot (S2 §2 principle 2).
pub fn decide_flat_for_registry(
    registry: &MechanismRegistry,
    mechanism: u64,
    operation: Operation,
    declared_len: u64,
    peer_fingerprint: u64,
    peer_abi: ParamAbi,
    local_abi: ParamAbi,
) -> FlatDecision {
    decide_flat(FlatRequest {
        mechanism,
        operation,
        declared_len,
        bound_shape: registry.param_shape(mechanism),
        parameterless_listed: registry.is_parameterless(mechanism),
        excluded: registry.excluded_view().contains(&mechanism),
        peer_fingerprint,
        peer_abi,
        local_abi,
    })
}

#[cfg(test)]
mod engine_tests {
    use super::{
        FieldClass, ParamAbi, field_offset_of, first_unsafe_offset_of, layout_fingerprint,
        native_size_of,
    };

    // Canonical-encoding oracle: independent Python FNV-1a 64 over the
    // documented canonical bytes (little-endian u32 length prefixes,
    // explicit padding ranges). If the Rust encoding drifts from the
    // documented form, these fail.
    #[test]
    fn canonical_encoding_matches_python_oracle() {
        let lp64 = ParamAbi::Lp64NativeLe;
        // ("rsa_pss", "", ulong 8, order 0, native 24,
        //  leaves [(0,8),(8,8),(16,8)], pads []).
        assert_eq!(
            layout_fingerprint(
                "rsa_pss",
                "",
                lp64,
                &[FieldClass::Ulong, FieldClass::Ulong, FieldClass::Ulong]
            ),
            0x2b9a_d39b_2de9_3dd6,
        );
        // ("eddsa", "", ulong 8, order 0, native 24,
        //  leaves [(0,1),(8,8),(16,8)], pads [(1,7)]).
        assert_eq!(
            layout_fingerprint(
                "eddsa",
                "",
                lp64,
                &[FieldClass::U8, FieldClass::Ulong, FieldClass::Pointer]
            ),
            0xc5f8_2282_7a07_34b2,
        );
        // Empty shape id, no fields: hashing still well-defined.
        assert_eq!(layout_fingerprint("", "", lp64, &[]), 0x293f_a063_7b8c_485d);
    }

    #[test]
    fn layout_engine_synthetic_vectors() {
        use FieldClass::{Bytes, Handle, Nested, Pointer, U8, Ulong};
        let lp64 = ParamAbi::Lp64NativeLe;
        let ilp32 = ParamAbi::Ilp32NativeLe;
        let pack1 = ParamAbi::Llp64Packed1Le;
        // Single byte then ulong: LP64 pads [1..8).
        let f = &[U8, Ulong];
        assert_eq!(native_size_of(f, lp64), 16);
        assert_eq!(native_size_of(f, ilp32), 8);
        assert_eq!(native_size_of(f, pack1), 5);
        assert_eq!(field_offset_of(f, lp64, 0), 0);
        assert_eq!(field_offset_of(f, lp64, 1), 8);
        assert_eq!(field_offset_of(f, pack1, 1), 1);
        assert_eq!(first_unsafe_offset_of(f, lp64), None);
        // Pointer-led struct: unsafe from byte zero on every ABI.
        let g = &[Pointer, Ulong];
        assert_eq!(native_size_of(g, lp64), 16);
        assert_eq!(native_size_of(g, ilp32), 8);
        assert_eq!(native_size_of(g, pack1), 12);
        assert_eq!(first_unsafe_offset_of(g, lp64), Some(0));
        assert_eq!(first_unsafe_offset_of(g, pack1), Some(0));
        // Handle counts as unsafe (virtual-handle value in flat bytes).
        let h = &[Ulong, Handle];
        assert_eq!(first_unsafe_offset_of(h, lp64), Some(8));
        assert_eq!(first_unsafe_offset_of(h, ilp32), Some(4));
        // Fixed bytes never unsafe, never padded internally.
        let b = &[Ulong, Bytes(8)];
        assert_eq!(native_size_of(b, lp64), 16);
        assert_eq!(first_unsafe_offset_of(b, lp64), None);
        // Nested inline struct: alignment = max member align; inner
        // padding participates in the outer layout.
        static INNER: &[FieldClass] = &[Pointer, Ulong];
        let n = &[Ulong, Nested(INNER), Ulong];
        assert_eq!(native_size_of(n, lp64), 32);
        assert_eq!(field_offset_of(n, lp64, 0), 0);
        assert_eq!(field_offset_of(n, lp64, 1), 8);
        assert_eq!(field_offset_of(n, lp64, 2), 24);
        assert_eq!(first_unsafe_offset_of(n, lp64), Some(8));
        assert_eq!(native_size_of(n, ilp32), 16);
        assert_eq!(native_size_of(n, pack1), 20);
        // Empty layout: zero size, no unsafe offset.
        assert_eq!(native_size_of(&[], lp64), 0);
        assert_eq!(first_unsafe_offset_of(&[], lp64), None);
    }

    /// Test-local size rule mirror (4 lines): packed-1 has alignment 1
    /// everywhere, so the packed size must equal the bare byte sum. The
    /// *offsets* remain engine-derived (see the walker test below).
    fn packed_leaf_sum(fields: &[FieldClass], abi: ParamAbi) -> usize {
        use FieldClass::{Bytes, Handle, Nested, Pointer, U8, Ulong};
        let mut sum = 0usize;
        let mut i = 0usize;
        while i < fields.len() {
            sum += match fields[i] {
                Ulong | Handle => abi.ulong_size(),
                Pointer => abi.pointer_size(),
                U8 => 1,
                Bytes(n) => n as usize,
                Nested(inner) => packed_leaf_sum(inner, abi),
            };
            i += 1;
        }
        sum
    }

    #[test]
    fn packed_layout_has_no_padding_over_whole_table() {
        use super::SHAPE_DESCRIPTORS;
        for pack1 in [ParamAbi::Llp64Packed1Le, ParamAbi::Ilp32Packed1Le] {
            for d in SHAPE_DESCRIPTORS {
                assert_eq!(
                    native_size_of(d.fields, pack1),
                    packed_leaf_sum(d.fields, pack1),
                    "packed size must be the bare byte sum for {} on {pack1:?}",
                    d.name
                );
                for a in d.alternate_forms {
                    assert_eq!(
                        native_size_of(a.fields, pack1),
                        packed_leaf_sum(a.fields, pack1),
                        "packed size must be the bare byte sum for {}#{} on {pack1:?}",
                        d.name,
                        a.name
                    );
                }
            }
        }
    }

    #[test]
    fn nested_never_nests_over_whole_table() {
        use super::SHAPE_DESCRIPTORS;
        use FieldClass::Nested;
        for d in SHAPE_DESCRIPTORS {
            for f in d.fields.iter().chain(d.alternate_forms.iter().flat_map(|a| a.fields.iter())) {
                if let Nested(inner) = f {
                    assert!(!inner.is_empty(), "empty nested struct in {}", d.name);
                    for g in *inner {
                        assert!(
                            !matches!(g, Nested(_)),
                            "depth-2 nesting in {} (engine supports depth 1)",
                            d.name
                        );
                    }
                }
            }
        }
    }

    /// Test-local leaf walker: absolute leaf offsets in order.
    fn walk_leaf_offsets(fields: &[FieldClass], abi: ParamAbi) -> Vec<usize> {
        use FieldClass::Nested;
        let mut out = Vec::new();
        for (i, f) in fields.iter().enumerate() {
            let base = field_offset_of(fields, abi, i);
            match f {
                Nested(inner) => {
                    for (j, _) in inner.iter().enumerate() {
                        out.push(base + field_offset_of(inner, abi, j));
                    }
                }
                _ => out.push(base),
            }
        }
        out
    }

    #[test]
    fn leaf_offsets_monotone_over_whole_table() {
        use super::SHAPE_DESCRIPTORS;
        for abi in [
            ParamAbi::Lp64NativeLe,
            ParamAbi::Ilp32NativeLe,
            ParamAbi::Llp64Packed1Le,
            ParamAbi::Ilp32Packed1Le,
        ] {
            for d in SHAPE_DESCRIPTORS {
                for fields in
                    std::iter::once(d.fields).chain(d.alternate_forms.iter().map(|a| a.fields))
                {
                    let mut prev = 0usize;
                    for (k, off) in walk_leaf_offsets(fields, abi).into_iter().enumerate() {
                        assert!(
                            k == 0 || off >= prev,
                            "non-monotone leaf offsets in {} on {abi:?}",
                            d.name
                        );
                        prev = off;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod table_tests {
    use super::{
        ALL_OPERATIONS, FieldClass, Operation, OuterKind, SHAPE_DESCRIPTORS, ShapeResolver,
        WRAP_ONLY_OPERATIONS, contains_handle_in,
    };

    #[test]
    fn table_has_68_compiled_shapes() {
        // 56 registry-bound + 11 reader-only/operation-selected + the
        // synthetic parameterless marker. A new shape must land here
        // deliberately (triage-forcing pin for R8/R21).
        assert_eq!(SHAPE_DESCRIPTORS.len(), 68);
    }

    #[test]
    fn table_names_sorted_unique() {
        let mut names: Vec<&str> = SHAPE_DESCRIPTORS.iter().map(|d| d.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "table must stay sorted for binary search");
        names.dedup();
        assert_eq!(names.len(), SHAPE_DESCRIPTORS.len(), "duplicate shape name");
    }

    #[test]
    fn every_kind_has_expected_members() {
        use OuterKind::{ByteBuffer, NestedOrOutput, Parameterless, PointerStruct, ScalarStruct};
        let count = |k: OuterKind| SHAPE_DESCRIPTORS.iter().filter(|d| d.outer_kind == k).count();
        assert_eq!(count(Parameterless), 1);
        assert_eq!(count(ByteBuffer), 2);
        assert_eq!(count(ScalarStruct), 12);
        assert_eq!(count(PointerStruct), 42);
        assert_eq!(count(NestedOrOutput), 11);
        // Spot members per kind.
        let kind_of = |n: &str| ShapeResolver::descriptor(n).unwrap().outer_kind;
        assert_eq!(kind_of("parameterless"), Parameterless);
        assert_eq!(kind_of("iv"), ByteBuffer);
        assert_eq!(kind_of("gcm_compat"), ByteBuffer);
        assert_eq!(kind_of("rsa_pss"), ScalarStruct);
        assert_eq!(kind_of("object_handle"), ScalarStruct);
        assert_eq!(kind_of("tls_mac"), ScalarStruct);
        assert_eq!(kind_of("gcm"), PointerStruct);
        assert_eq!(kind_of("eddsa"), PointerStruct);
        assert_eq!(kind_of("rsa_aes_key_wrap"), PointerStruct);
        assert_eq!(kind_of("gcm_wrap"), PointerStruct);
        assert_eq!(kind_of("kip"), NestedOrOutput);
        assert_eq!(kind_of("otp"), NestedOrOutput);
        assert_eq!(kind_of("kea_derive"), NestedOrOutput);
        assert_eq!(kind_of("skipjack_relayx"), NestedOrOutput);
        assert_eq!(kind_of("ssl3_key_mat"), NestedOrOutput);
        assert_eq!(kind_of("tls_prf"), NestedOrOutput);
    }

    #[test]
    fn message_opaque_admits_only_byte_buffer_shapes() {
        // Issue #37: only byte-buffer forms may travel message-opaque
        // (exact caller bytes, no layout/ABI proof). Struct images
        // embed stale client addresses (daemon SIGSEGV); unknown
        // layouts fail closed.
        use super::message_opaque_admits_shape;
        assert!(message_opaque_admits_shape(Some("iv")));
        assert!(message_opaque_admits_shape(Some("parameterless")));
        // Pointer structs, including via length-selected alternates.
        assert!(!message_opaque_admits_shape(Some("chacha20")));
        assert!(!message_opaque_admits_shape(Some("gcm")));
        assert!(!message_opaque_admits_shape(Some("gcm_compat")));
        assert!(!message_opaque_admits_shape(Some("tls_prf")));
        // Scalar structs (no layout/ABI proof; object_handle also
        // carries a virtual handle past remapping).
        assert!(!message_opaque_admits_shape(Some("rsa_pss")));
        assert!(!message_opaque_admits_shape(Some("extract")));
        assert!(!message_opaque_admits_shape(Some("object_handle")));
        // Unknown layouts fail closed.
        assert!(!message_opaque_admits_shape(None));
        assert!(!message_opaque_admits_shape(Some("no_such_shape")));
    }

    #[test]
    fn field_presence_matches_kind() {
        use OuterKind::{ByteBuffer, Parameterless};
        for d in SHAPE_DESCRIPTORS {
            let bare = d.outer_kind == Parameterless || d.outer_kind == ByteBuffer;
            assert_eq!(d.fields.is_empty(), bare, "field presence must match kind for {}", d.name);
        }
    }

    #[test]
    fn stored_handle_flag_matches_derivation() {
        for d in SHAPE_DESCRIPTORS {
            assert_eq!(
                d.contains_virtual_handle,
                contains_handle_in(d.fields),
                "stored handle flag must match fields for {}",
                d.name
            );
            for a in d.alternate_forms {
                assert_eq!(
                    a.contains_virtual_handle,
                    contains_handle_in(a.fields),
                    "stored handle flag must match fields for {}#{}",
                    d.name,
                    a.name
                );
            }
        }
        // Spot pins: the shapes whose flat bytes could carry handles.
        assert!(ShapeResolver::descriptor("object_handle").unwrap().contains_virtual_handle);
        assert!(ShapeResolver::descriptor("hkdf").unwrap().contains_virtual_handle);
        assert!(ShapeResolver::descriptor("kip").unwrap().contains_virtual_handle);
        assert!(ShapeResolver::descriptor("kmac").unwrap().contains_virtual_handle);
        assert!(!ShapeResolver::descriptor("gcm").unwrap().contains_virtual_handle);
        assert!(!ShapeResolver::descriptor("rsa_pss").unwrap().contains_virtual_handle);
    }

    #[test]
    fn operations_valid_over_whole_table() {
        for d in SHAPE_DESCRIPTORS {
            assert!(!d.operations.is_empty(), "no operation context for {}", d.name);
        }
        assert_eq!(ShapeResolver::descriptor("gcm_wrap").unwrap().operations, WRAP_ONLY_OPERATIONS);
        assert_eq!(ShapeResolver::descriptor("ccm_wrap").unwrap().operations, WRAP_ONLY_OPERATIONS);
        // Every other shape applies to all operations (WrapKey falls back
        // to the registry binding when the wrap-size rule does not fire).
        for d in SHAPE_DESCRIPTORS {
            if d.name != "gcm_wrap" && d.name != "ccm_wrap" {
                assert_eq!(d.operations, ALL_OPERATIONS, "operations for {}", d.name);
            }
        }
        assert!(ALL_OPERATIONS.contains(&Operation::General));
        assert!(ALL_OPERATIONS.contains(&Operation::WrapKey));
    }

    #[test]
    fn companion_sets_exact() {
        use FieldClass::{Pointer, Ulong};
        // Only two shapes share one length across two governed pointers.
        let kea = ShapeResolver::descriptor("kea_derive").unwrap();
        assert_eq!(kea.shared_length_groups.len(), 1);
        assert_eq!(kea.shared_length_groups[0].length_field, 1);
        assert_eq!(kea.shared_length_groups[0].pointers, &[2, 3]);
        let sj = ShapeResolver::descriptor("skipjack_private_wrap").unwrap();
        assert_eq!(sj.shared_length_groups.len(), 1);
        assert_eq!(sj.shared_length_groups[0].length_field, 4);
        assert_eq!(sj.shared_length_groups[0].pointers, &[8, 9]);
        // Universal validity: indices in range, length is a ulong field,
        // companions are pointer fields, groups non-trivial.
        for d in SHAPE_DESCRIPTORS {
            for g in d.shared_length_groups {
                assert!(
                    (g.length_field as usize) < d.fields.len(),
                    "length index out of range in {}",
                    d.name
                );
                assert_eq!(
                    d.fields[g.length_field as usize], Ulong,
                    "length field must be ulong in {}",
                    d.name
                );
                assert!(g.pointers.len() >= 2, "trivial companion group in {}", d.name);
                for p in g.pointers {
                    assert!(
                        (*p as usize) < d.fields.len(),
                        "companion index out of range in {}",
                        d.name
                    );
                    assert_eq!(
                        d.fields[*p as usize], Pointer,
                        "companion must be a pointer field in {}",
                        d.name
                    );
                }
            }
            for a in d.alternate_forms {
                assert!(
                    a.shared_length_groups.is_empty(),
                    "v1 alternates carry no companion sets ({}#{})",
                    d.name,
                    a.name
                );
            }
        }
    }

    #[test]
    fn alternate_forms_exact() {
        use OuterKind::PointerStruct;
        // Exactly three length-selected unions exist in v1.
        let compat = ShapeResolver::descriptor("gcm_compat").unwrap();
        assert_eq!(compat.alternate_forms.len(), 1);
        assert_eq!(compat.alternate_forms[0].name, "struct");
        assert_eq!(compat.alternate_forms[0].outer_kind, PointerStruct);
        let sign = ShapeResolver::descriptor("sign_additional_context").unwrap();
        assert_eq!(sign.alternate_forms.len(), 1);
        assert_eq!(sign.alternate_forms[0].name, "hash");
        assert_eq!(sign.alternate_forms[0].outer_kind, PointerStruct);
        assert!(sign.alternate_forms[0].fields.len() > sign.fields.len());
        let mat = ShapeResolver::descriptor("ssl3_key_mat").unwrap();
        assert_eq!(mat.alternate_forms.len(), 1);
        assert_eq!(mat.alternate_forms[0].name, "tls12");
        for d in SHAPE_DESCRIPTORS {
            if d.name != "gcm_compat"
                && d.name != "sign_additional_context"
                && d.name != "ssl3_key_mat"
            {
                assert!(d.alternate_forms.is_empty(), "unexpected alternate form on {}", d.name);
            }
            assert!(
                d.alternate_forms.len() <= 1,
                "resolver takes the first length match (v1 shape: {})",
                d.name
            );
        }
    }

    #[test]
    fn gcm_compat_struct_shares_gcm_layout() {
        let gcm = ShapeResolver::descriptor("gcm").unwrap();
        let compat = ShapeResolver::descriptor("gcm_compat").unwrap();
        assert_eq!(compat.alternate_forms[0].fields, gcm.fields);
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::{
        ABI_EXEMPT_FINGERPRINT, OuterKind, ParamAbi, ResolvedShape, SHAPE_DESCRIPTORS,
        ShapeResolver, layout_fingerprint,
    };

    const ABIS: [ParamAbi; 4] = [
        ParamAbi::Lp64NativeLe,
        ParamAbi::Ilp32NativeLe,
        ParamAbi::Llp64Packed1Le,
        ParamAbi::Ilp32Packed1Le,
    ];

    fn fp_of(shape: &str, form: &str, abi: ParamAbi) -> u64 {
        let d = ShapeResolver::descriptor(shape).unwrap();
        if form.is_empty() {
            assert!(!d.fields.is_empty(), "bare form has no computed print: {shape}");
            layout_fingerprint(d.name, "", abi, d.fields)
        } else {
            let a = d.alternate_forms.iter().find(|a| a.name == form).unwrap();
            layout_fingerprint(d.name, a.name, abi, a.fields)
        }
    }

    #[test]
    fn abi_exempt_marker_value_pinned() {
        assert_eq!(ABI_EXEMPT_FINGERPRINT, 0x5450_4d58_4549_4241);
        assert_eq!(ABI_EXEMPT_FINGERPRINT, u64::from_le_bytes(*b"ABIEXMPT"));
    }

    #[test]
    fn bare_forms_use_exempt_marker_on_every_abi() {
        for abi in ABIS {
            let iv = ResolvedShape::primary(ShapeResolver::descriptor("iv").unwrap());
            assert_eq!(iv.fingerprint(abi), ABI_EXEMPT_FINGERPRINT);
            let compat = ShapeResolver::resolve(
                Some("gcm_compat"),
                super::OperationContext {
                    mechanism: 0x108E,
                    operation: super::Operation::General,
                    length: 16,
                },
                abi,
            )
            .unwrap();
            assert_eq!(compat.outer_kind(), OuterKind::ByteBuffer);
            assert_eq!(compat.fingerprint(abi), ABI_EXEMPT_FINGERPRINT);
            let pl = ResolvedShape::primary(ShapeResolver::descriptor("parameterless").unwrap());
            assert_eq!(pl.fingerprint(abi), ABI_EXEMPT_FINGERPRINT);
        }
    }

    #[test]
    fn resolved_fingerprint_delegates_to_layout_or_marker() {
        use OuterKind::{ByteBuffer, Parameterless};
        for d in SHAPE_DESCRIPTORS {
            for abi in ABIS {
                let r = ResolvedShape::primary(d);
                let bare = r.outer_kind() == ByteBuffer || r.outer_kind() == Parameterless;
                let want = if bare {
                    ABI_EXEMPT_FINGERPRINT
                } else {
                    layout_fingerprint(d.name, "", abi, d.fields)
                };
                assert_eq!(r.fingerprint(abi), want, "primary {}", d.name);
                for a in d.alternate_forms {
                    let r2 = ResolvedShape { descriptor: d, alternate: Some(a) };
                    assert_eq!(
                        r2.fingerprint(abi),
                        layout_fingerprint(d.name, a.name, abi, a.fields),
                        "alternate {}#{}",
                        d.name,
                        a.name
                    );
                }
            }
        }
    }

    /// Whether ILP32 and LLP64-pack1 layouts can differ for a field
    /// sequence: both use 4-byte ulongs, so only pointer widths (4 vs 8)
    /// and packing-sensitive padding (via u8/byte/nested fields) separate
    /// them. All-Ulong/Handle/Bytes forms are layout-identical on both.
    fn ilp32_differs_from_llp64(fields: &[super::FieldClass]) -> bool {
        use super::FieldClass::{Bytes, Handle, Nested, Pointer, U8, Ulong};
        let mut i = 0usize;
        while i < fields.len() {
            match fields[i] {
                Pointer | U8 | Nested(_) => return true,
                Ulong | Handle | Bytes(_) => {}
            }
            i += 1;
        }
        false
    }

    #[test]
    fn struct_fingerprints_differ_across_abis_where_layouts_differ() {
        // LP64 always differs (ulong_size 8 vs 4 is in the tuple). ILP32
        // vs LLP64-pack1 differ exactly for pointer/packing-sensitive
        // forms; the rest are layout-identical (pinned equal — the ABI
        // enum check, not the fingerprint, separates those edges, and it
        // fires first for struct forms in decide_flat).
        for d in SHAPE_DESCRIPTORS {
            if d.fields.is_empty() {
                continue;
            }
            let f = ABIS.map(|abi| layout_fingerprint(d.name, "", abi, d.fields));
            assert_ne!(f[0], f[1], "ABI-blind print: {}", d.name);
            assert_ne!(f[0], f[2], "ABI-blind print: {}", d.name);
            if ilp32_differs_from_llp64(d.fields) {
                assert_ne!(f[1], f[2], "ABI-blind print: {}", d.name);
            } else {
                assert_eq!(f[1], f[2], "unexpected ILP32/LLP64 split: {}", d.name);
            }
            for a in d.alternate_forms {
                let g = ABIS.map(|abi| layout_fingerprint(d.name, a.name, abi, a.fields));
                assert_ne!(g[0], g[1], "ABI-blind print: {}#{}", d.name, a.name);
                assert_ne!(g[0], g[2], "ABI-blind print: {}#{}", d.name, a.name);
                if ilp32_differs_from_llp64(a.fields) {
                    assert_ne!(g[1], g[2], "ABI-blind print: {}#{}", d.name, a.name);
                } else {
                    assert_eq!(g[1], g[2], "unexpected split: {}#{}", d.name, a.name);
                }
            }
        }
        // The identical set is exactly the pointer-free, padding-free
        // forms (all-Ulong/Handle singles/multiples + Ulong+Bytes pairs).
        let mut identical = Vec::new();
        for d in SHAPE_DESCRIPTORS {
            if !d.fields.is_empty() && !ilp32_differs_from_llp64(d.fields) {
                identical.push(d.name);
            }
        }
        assert_eq!(
            identical,
            [
                "aes_ctr",
                "camellia_ctr",
                "extract",
                "mac_general",
                "object_handle",
                "rc2_cbc",
                "rc2_mac_general",
                "rc5",
                "rc5_mac_general",
                "rsa_pss",
                "tls_mac",
                "xeddsa",
            ]
        );
    }

    #[test]
    fn shape_id_separates_identical_layouts() {
        // gcm and gcm_compat#struct share the field list but must never
        // share a fingerprint (the binding is part of the identity).
        for abi in ABIS {
            assert_ne!(fp_of("gcm", "", abi), fp_of("gcm_compat", "struct", abi));
        }
    }

    #[test]
    fn packed32_fingerprints_match_ilp32_where_layouts_identical() {
        // The S2 §3 tuple carries (shape, ulong-size, byte-order, leaves,
        // pads) but no packing flag, and packed-32 shares ulong-size and
        // byte-order with ILP32-natural: packing-insensitive forms share
        // fingerprints across the two (the ABI enum check, not the
        // fingerprint, separates those edges — same pattern as the
        // ILP32/LLP64 identical-set pin above), while forms whose packed
        // size differs (native_size is in the tuple) always split. The
        // oracle here is the size relation, the subject the fingerprint
        // encoding; the exact differs-set values live in
        // `crosscheck_tests::PACKED32_DIFFERS`.
        use super::native_size_of;
        let ilp32 = ParamAbi::Ilp32NativeLe;
        let packed32 = ParamAbi::Ilp32Packed1Le;
        let check = |shape: &str, form: &str, fields: &[super::FieldClass]| {
            let same_size = native_size_of(fields, ilp32) == native_size_of(fields, packed32);
            let (a, b) = (fp_of(shape, form, ilp32), fp_of(shape, form, packed32));
            if same_size {
                assert_eq!(a, b, "unexpected packed-32 split: {shape}#{form}");
            } else {
                assert_ne!(a, b, "ABI-blind print: {shape}#{form}");
            }
        };
        for d in SHAPE_DESCRIPTORS {
            if !d.fields.is_empty() {
                check(d.name, "", d.fields);
            }
            for a in d.alternate_forms {
                check(d.name, a.name, a.fields);
            }
        }
    }

    #[test]
    fn fingerprints_distinct_within_each_abi_and_marker_free() {
        // Within one ABI every (shape, form) fingerprint is unique and
        // never the exempt marker. (Across ABIs, the twelve
        // pointer-free/padding-free forms are ILP32/LLP64-identical by
        // construction — pinned in the test above.)
        for abi in ABIS {
            let mut seen = std::collections::HashSet::new();
            for d in SHAPE_DESCRIPTORS {
                if !d.fields.is_empty() {
                    let f = layout_fingerprint(d.name, "", abi, d.fields);
                    assert_ne!(f, ABI_EXEMPT_FINGERPRINT, "marker collision: {}", d.name);
                    assert!(seen.insert(f), "fingerprint collision: {}", d.name);
                }
                for a in d.alternate_forms {
                    let g = layout_fingerprint(d.name, a.name, abi, a.fields);
                    assert_ne!(
                        g, ABI_EXEMPT_FINGERPRINT,
                        "marker collision: {}#{}",
                        d.name, a.name
                    );
                    assert!(seen.insert(g), "collision: {}#{}", d.name, a.name);
                }
            }
            // 65 struct primaries + 3 alternates.
            assert_eq!(seen.len(), 68);
        }
    }

    // Cross-edge goldens: frozen once v1 ships; any layout change needs a
    // new transport version. Values generated by the const engine, reviewed
    // against the independent Python oracle + cryptoki ground truth.
    const LP64_GOLDENS: &[(&str, &str, u64)] = &[
        ("aes_cbc_encrypt_data", "", 0x6431_93a3_c33b_2e8b),
        ("aes_ctr", "", 0x8add_9bb4_0512_c973),
        ("aria_cbc_encrypt_data", "", 0xe8de_05e2_8b1a_d480),
        ("camellia_cbc_encrypt_data", "", 0xf110_a78a_3c94_ba67),
        ("camellia_ctr", "", 0xf5c3_43dd_54c9_a7b7),
        ("ccm", "", 0x0386_4c0c_444d_efcd),
        ("ccm_wrap", "", 0x5923_46c6_8fc0_4d0f),
        ("chacha20", "", 0xadec_b7f0_f766_a2cb),
        ("des_cbc_encrypt_data", "", 0xc8e8_9a48_e15f_4fc6),
        ("ecdh1_derive", "", 0x677a_eef2_71ef_77c3),
        ("ecdh2_derive", "", 0x315b_3d67_3322_4298),
        ("ecdh_aes_key_wrap", "", 0x186b_6941_0835_edb1),
        ("ecmqv_derive", "", 0xaa77_7a4b_ffc8_095d),
        ("eddsa", "", 0xc5f8_2282_7a07_34b2),
        ("extract", "", 0xab25_611e_ca25_b3be),
        ("gcm", "", 0x4a05_fd00_b426_2191),
        ("gcm_compat", "struct", 0xef01_8ed3_72b2_4a56),
        ("gcm_wrap", "", 0x93d3_a045_aef3_9b74),
        ("gostr3410_derive", "", 0xdffa_6298_b383_aa5f),
        ("gostr3410_key_wrap", "", 0x00bc_a906_3e3d_826a),
        ("hkdf", "", 0xc089_e287_3c7a_12a3),
        ("ike1_extended_derive", "", 0x8759_1737_75c8_759a),
        ("ike1_prf_derive", "", 0xfc11_a3b4_ca84_6768),
        ("ike2_prf_plus_derive", "", 0x2599_c3ed_1c57_60df),
        ("ike_prf_derive", "", 0xaa4d_bc38_0e91_8339),
        ("kea_derive", "", 0x726e_e132_9d3a_5f14),
        ("key_derivation_string", "", 0x5884_77b0_c587_82a5),
        ("key_wrap_set_oaep", "", 0x5b74_d271_8479_a338),
        ("kip", "", 0x2bae_b716_8398_6e12),
        ("kmac", "", 0x3d80_2c30_b2c0_f4fd),
        ("mac_general", "", 0x7515_044a_5a6d_a1cb),
        ("mu_gen", "", 0xc22f_1511_f393_9669),
        ("object_handle", "", 0x0049_fe2e_80c6_02cf),
        ("otp", "", 0xf292_59e3_31c5_ec95),
        ("pbe", "", 0x67f6_a4f3_c8f9_a1c9),
        ("pkcs5_pbkd2", "", 0x2c6a_fc5b_6857_6e53),
        ("rc2_cbc", "", 0xf9bc_2b56_37e0_7cba),
        ("rc2_mac_general", "", 0x0e07_6b30_4252_09d4),
        ("rc5", "", 0x8403_05ac_0b6f_36ba),
        ("rc5_cbc", "", 0x86e7_da50_e8d8_c841),
        ("rc5_mac_general", "", 0xef81_0b52_dc1e_ce5c),
        ("rsa_aes_key_wrap", "", 0x79f9_346f_17e0_b5a8),
        ("rsa_oaep", "", 0xf728_1bc9_7bdb_29aa),
        ("rsa_pss", "", 0x2b9a_d39b_2de9_3dd6),
        ("salsa20", "", 0x598d_0529_abcc_c0e3),
        ("salsa20_chacha20_poly1305", "", 0xff65_4714_65b9_a0bb),
        ("seed_cbc_encrypt_data", "", 0x9e8b_7cbb_ebf3_81d8),
        ("sign_additional_context", "", 0x95a7_d81b_1014_7322),
        ("sign_additional_context", "hash", 0x08db_032a_a60d_889d),
        ("skipjack_private_wrap", "", 0x15a9_03ec_9ce7_17aa),
        ("skipjack_relayx", "", 0x43a5_6aba_2dc2_cc36),
        ("sp800_108_feedback_kdf", "", 0xb4ff_fa7b_8dfe_0411),
        ("sp800_108_kdf", "", 0x11fa_f4e6_d70c_369c),
        ("ssl3_key_mat", "", 0x63bd_fc96_f3f9_eafc),
        ("ssl3_key_mat", "tls12", 0x3368_d5ec_2d41_0cd4),
        ("ssl3_master_key_derive", "", 0xed76_7dba_822c_9b5a),
        ("tls12_extended_master_key_derive", "", 0x59ca_704c_69bb_d33c),
        ("tls12_master_key_derive", "", 0xe7c1_9d62_fae0_c2c1),
        ("tls_kdf", "", 0x9066_d9f8_b4a4_32ae),
        ("tls_mac", "", 0x9c3e_b63a_b50a_32ac),
        ("tls_prf", "", 0x2b62_2fbc_6773_f7aa),
        ("wtls_key_mat", "", 0xfe41_aa8c_81b5_71d3),
        ("wtls_master_key_derive", "", 0xe076_c451_f3c9_6fd8),
        ("wtls_prf", "", 0x7fc7_464d_8dae_d887),
        ("x942_dh1_derive", "", 0x77d4_7f42_45e7_7b1e),
        ("x942_dh2_derive", "", 0x1095_0bd3_f146_af15),
        ("x942_mqv_derive", "", 0x8492_b095_93e8_2e44),
        ("xeddsa", "", 0xf90d_2fac_e6ff_9755),
    ];

    #[test]
    fn golden_fingerprints_lp64() {
        assert_eq!(LP64_GOLDENS.len(), 68);
        for (shape, form, want) in LP64_GOLDENS {
            assert_eq!(
                fp_of(shape, form, ParamAbi::Lp64NativeLe),
                *want,
                "golden drift: {shape}#{form} (layouts freeze at v1)"
            );
        }
    }

    const ILP32_GOLDENS: &[(&str, &str, u64)] = &[
        ("gcm", "", 0xf321_39c5_bb04_b5f9),
        ("hkdf", "", 0xa1e2_1c74_d464_8b07),
        ("eddsa", "", 0x59c4_8ad1_4297_c9ba),
        ("rsa_pss", "", 0xf39c_f48d_0e90_36f6),
        ("object_handle", "", 0x1595_40c1_c1d0_57c3),
        ("ssl3_key_mat", "", 0xbb98_baa1_2311_e78c),
        ("ssl3_key_mat", "tls12", 0x3e5c_78b2_df83_de90),
        ("kea_derive", "", 0x991f_bc98_c5fe_abf4),
        ("ike1_prf_derive", "", 0x2f6e_6a27_6639_8c48),
        ("gcm_compat", "struct", 0xde0e_d034_2bfc_c0fe),
        ("tls_kdf", "", 0x5a85_d5d3_0cce_4562),
        ("otp", "", 0xa7ac_b37a_9254_5aad),
        ("chacha20", "", 0x3e2f_bbc1_6b68_c2d7),
    ];

    #[test]
    fn golden_fingerprints_ilp32_subset() {
        for (shape, form, want) in ILP32_GOLDENS {
            assert_eq!(
                fp_of(shape, form, ParamAbi::Ilp32NativeLe),
                *want,
                "golden drift: {shape}#{form}"
            );
        }
    }

    const LLP64_GOLDENS: &[(&str, &str, u64)] = &[
        ("gcm", "", 0xd488_837f_a60b_7e95),
        ("hkdf", "", 0xbbe6_f613_37eb_6e82),
        ("eddsa", "", 0xcb84_2821_e31b_4dec),
        ("ssl3_key_mat", "", 0x5a7e_6dce_6d17_01e3),
        ("kea_derive", "", 0xf15d_98e8_fbef_b243),
        ("otp", "", 0xd61b_b3de_4c4f_82a9),
        ("rsa_pss", "", 0xf39c_f48d_0e90_36f6),
        ("tls_kdf", "", 0xf527_bddb_1c12_ed92),
        ("ike1_prf_derive", "", 0x51eb_c425_c345_2311),
        ("gcm_wrap", "", 0x4b14_314a_b275_dfcc),
    ];

    #[test]
    fn golden_fingerprints_llp64_subset() {
        for (shape, form, want) in LLP64_GOLDENS {
            assert_eq!(
                fp_of(shape, form, ParamAbi::Llp64Packed1Le),
                *want,
                "golden drift: {shape}#{form}"
            );
        }
    }
}

#[cfg(test)]
mod resolver_tests {
    use super::{
        Operation, OperationContext, OuterKind, ParamAbi, SHAPE_DESCRIPTORS, ShapeResolver,
        native_size_of,
    };

    const LP64: ParamAbi = ParamAbi::Lp64NativeLe;
    const ILP32: ParamAbi = ParamAbi::Ilp32NativeLe;
    const LLP64: ParamAbi = ParamAbi::Llp64Packed1Le;
    const CKM_AES_GCM: u64 = 0x1087;
    const CKM_AES_CCM: u64 = 0x1088;
    const CKM_AES_GMAC: u64 = 0x108E;

    fn ctx(mechanism: u64, operation: Operation, length: u64) -> OperationContext {
        OperationContext { mechanism, operation, length }
    }

    fn selected_name(
        bound: Option<&str>,
        c: OperationContext,
        abi: ParamAbi,
    ) -> (&'static str, &'static str) {
        let r = ShapeResolver::resolve(bound, c, abi).unwrap();
        (r.descriptor.name, r.alternate.map(|a| a.name).unwrap_or(""))
    }

    #[test]
    fn wrap_key_selects_gcm_wrap_layout() {
        // CK_GCM_WRAP_PARAMS is 56 bytes on LP64; the plain GCM struct is 48.
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 56), LP64),
            ("gcm_wrap", "")
        );
        // Any other length falls back to the registry binding.
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 48), LP64),
            ("gcm", "")
        );
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 55), LP64),
            ("gcm", "")
        );
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 57), LP64),
            ("gcm", "")
        );
        // A one-shape-per-mechanism map is insufficient: the same mechanism
        // resolves differently under a different operation (see below) and
        // the wrap layout wins even over an unbound mechanism.
        assert_eq!(
            selected_name(None, ctx(CKM_AES_GCM, Operation::WrapKey, 56), LP64),
            ("gcm_wrap", "")
        );
    }

    #[test]
    fn wrap_key_selects_ccm_wrap_layout() {
        // CK_CCM_WRAP_PARAMS is 64 bytes on LP64; the plain CCM struct is 48.
        assert_eq!(
            selected_name(Some("ccm"), ctx(CKM_AES_CCM, Operation::WrapKey, 64), LP64),
            ("ccm_wrap", "")
        );
        assert_eq!(
            selected_name(Some("ccm"), ctx(CKM_AES_CCM, Operation::WrapKey, 48), LP64),
            ("ccm", "")
        );
        assert_eq!(
            selected_name(Some("ccm"), ctx(CKM_AES_CCM, Operation::WrapKey, 63), LP64),
            ("ccm", "")
        );
        assert_eq!(
            selected_name(None, ctx(CKM_AES_CCM, Operation::WrapKey, 64), LP64),
            ("ccm_wrap", "")
        );
    }

    #[test]
    fn general_operation_ignores_wrap_layouts() {
        // Same (mechanism, length), different operation: the wrap layout
        // must NOT be selected (operation context is load-bearing).
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::General, 56), LP64),
            ("gcm", "")
        );
        assert_eq!(
            selected_name(Some("ccm"), ctx(CKM_AES_CCM, Operation::General, 64), LP64),
            ("ccm", "")
        );
        // Cross-mechanism guard: GCM never selects the CCM wrap layout.
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 64), LP64),
            ("gcm", "")
        );
    }

    #[test]
    fn wrap_selection_uses_local_abi_sizes() {
        // ILP32 CK_GCM_WRAP_PARAMS is 28 bytes (8 × 4); the LP64 exact
        // size 56 must NOT select the wrap layout there (and the local
        // 28-byte size must). Cross-ABI form disagreement fails closed
        // later via the fingerprint check.
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 28), ILP32),
            ("gcm_wrap", "")
        );
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 56), ILP32),
            ("gcm", "")
        );
        assert_eq!(
            selected_name(Some("ccm"), ctx(CKM_AES_CCM, Operation::WrapKey, 32), ILP32),
            ("ccm_wrap", "")
        );
    }

    #[test]
    fn wrap_key_selects_wrap_layouts_on_llp64() {
        // R7 review carry (reviewer probe): LLP64-pack1 CK_GCM_WRAP_PARAMS
        // is 36 bytes and CK_CCM_WRAP_PARAMS is 40 bytes (packed, so the
        // bare byte sums). Exact sizes select the wrap layouts; off-by-one
        // falls back to the registry binding.
        let gcm_wrap_len =
            native_size_of(ShapeResolver::descriptor("gcm_wrap").unwrap().fields, LLP64);
        let ccm_wrap_len =
            native_size_of(ShapeResolver::descriptor("ccm_wrap").unwrap().fields, LLP64);
        assert_eq!((gcm_wrap_len, ccm_wrap_len), (36, 40));
        assert_eq!(
            selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, 36), LLP64),
            ("gcm_wrap", "")
        );
        assert_eq!(
            selected_name(Some("ccm"), ctx(CKM_AES_CCM, Operation::WrapKey, 40), LLP64),
            ("ccm_wrap", "")
        );
        for length in [35, 37] {
            assert_eq!(
                selected_name(Some("gcm"), ctx(CKM_AES_GCM, Operation::WrapKey, length), LLP64),
                ("gcm", ""),
                "off-by-one length {length} must fall back to the binding"
            );
        }
        for length in [39, 41] {
            assert_eq!(
                selected_name(Some("ccm"), ctx(CKM_AES_CCM, Operation::WrapKey, length), LLP64),
                ("ccm", ""),
                "off-by-one length {length} must fall back to the binding"
            );
        }
    }

    #[test]
    fn gcm_compat_union_by_length() {
        // Short buffers are flat IV bytes; struct-sized buffers are
        // CK_GCM_PARAMS (48 bytes LP64 / 24 ILP32).
        for op in [Operation::General, Operation::WrapKey] {
            assert_eq!(
                selected_name(Some("gcm_compat"), ctx(CKM_AES_GMAC, op, 0), LP64),
                ("gcm_compat", "")
            );
            assert_eq!(
                selected_name(Some("gcm_compat"), ctx(CKM_AES_GMAC, op, 16), LP64),
                ("gcm_compat", "")
            );
            assert_eq!(
                selected_name(Some("gcm_compat"), ctx(CKM_AES_GMAC, op, 47), LP64),
                ("gcm_compat", "")
            );
            assert_eq!(
                selected_name(Some("gcm_compat"), ctx(CKM_AES_GMAC, op, 48), LP64),
                ("gcm_compat", "struct")
            );
            assert_eq!(
                selected_name(Some("gcm_compat"), ctx(CKM_AES_GMAC, op, 96), LP64),
                ("gcm_compat", "struct")
            );
        }
        assert_eq!(
            selected_name(Some("gcm_compat"), ctx(CKM_AES_GMAC, Operation::General, 23), ILP32),
            ("gcm_compat", "")
        );
        assert_eq!(
            selected_name(Some("gcm_compat"), ctx(CKM_AES_GMAC, Operation::General, 24), ILP32),
            ("gcm_compat", "struct")
        );
        // The short form is the byte-buffer kind; the struct form is a
        // pointer struct.
        let short = ShapeResolver::resolve(
            Some("gcm_compat"),
            ctx(CKM_AES_GMAC, Operation::General, 16),
            LP64,
        )
        .unwrap();
        assert_eq!(short.outer_kind(), OuterKind::ByteBuffer);
        let tall = ShapeResolver::resolve(
            Some("gcm_compat"),
            ctx(CKM_AES_GMAC, Operation::General, 48),
            LP64,
        )
        .unwrap();
        assert_eq!(tall.outer_kind(), OuterKind::PointerStruct);
    }

    #[test]
    fn sign_context_dual_form_by_length() {
        // Plain CK_SIGN_ADDITIONAL_CONTEXT is 24 bytes LP64; the generic
        // hash variant adds a trailing CK_ULONG (32 bytes).
        assert_eq!(
            selected_name(
                Some("sign_additional_context"),
                ctx(0x001D, Operation::General, 23),
                LP64
            ),
            ("sign_additional_context", "")
        );
        assert_eq!(
            selected_name(
                Some("sign_additional_context"),
                ctx(0x001D, Operation::General, 24),
                LP64
            ),
            ("sign_additional_context", "")
        );
        assert_eq!(
            selected_name(
                Some("sign_additional_context"),
                ctx(0x001F, Operation::General, 31),
                LP64
            ),
            ("sign_additional_context", "")
        );
        assert_eq!(
            selected_name(
                Some("sign_additional_context"),
                ctx(0x001F, Operation::General, 32),
                LP64
            ),
            ("sign_additional_context", "hash")
        );
        assert_eq!(
            selected_name(
                Some("sign_additional_context"),
                ctx(0x001F, Operation::General, 40),
                LP64
            ),
            ("sign_additional_context", "hash")
        );
    }

    #[test]
    fn ssl3_key_mat_dual_form_by_length() {
        // CK_SSL3_KEY_MAT_PARAMS is 72 bytes LP64; the TLS 1.2 superset
        // adds a trailing prfHashMechanism (80 bytes).
        assert_eq!(
            selected_name(Some("ssl3_key_mat"), ctx(0x0372, Operation::General, 71), LP64),
            ("ssl3_key_mat", "")
        );
        assert_eq!(
            selected_name(Some("ssl3_key_mat"), ctx(0x0372, Operation::General, 72), LP64),
            ("ssl3_key_mat", "")
        );
        assert_eq!(
            selected_name(Some("ssl3_key_mat"), ctx(0x03E1, Operation::General, 79), LP64),
            ("ssl3_key_mat", "")
        );
        assert_eq!(
            selected_name(Some("ssl3_key_mat"), ctx(0x03E1, Operation::General, 80), LP64),
            ("ssl3_key_mat", "tls12")
        );
    }

    #[test]
    fn unknown_shape_and_unbound_resolve_to_none() {
        assert!(
            ShapeResolver::resolve(
                Some("no_such_shape"),
                ctx(0x1087, Operation::General, 16),
                LP64
            )
            .is_none()
        );
        assert!(ShapeResolver::resolve(None, ctx(0x0250, Operation::General, 16), LP64).is_none());
        assert!(ShapeResolver::descriptor("no_such_shape").is_none());
        assert!(ShapeResolver::descriptor("").is_none());
    }

    #[test]
    fn resolver_totality_sweep() {
        // Totality over the compiled table: every bound shape × every
        // operation × boundary lengths yields a defined result and never
        // panics (comparison-only classifier; lengths partition into
        // finitely many classes, all covered here).
        const LENS: &[u64] = &[
            0,
            1,
            2,
            7,
            8,
            15,
            16,
            17,
            23,
            24,
            27,
            28,
            31,
            32,
            39,
            40,
            47,
            48,
            55,
            56,
            63,
            64,
            71,
            72,
            79,
            80,
            87,
            88,
            111,
            112,
            113,
            65535,
            65536,
            65537,
            u64::MAX,
        ];
        const ABIS: &[ParamAbi] = &[
            ParamAbi::Lp64NativeLe,
            ParamAbi::Ilp32NativeLe,
            ParamAbi::Llp64Packed1Le,
            ParamAbi::Ilp32Packed1Le,
        ];
        for d in SHAPE_DESCRIPTORS {
            for op in [Operation::General, Operation::WrapKey] {
                for len in LENS {
                    for abi in ABIS {
                        let r = ShapeResolver::resolve(Some(d.name), ctx(0xFFFF, op, *len), *abi);
                        assert!(r.is_some(), "no resolution for {}", d.name);
                        let r = r.unwrap();
                        // Wrap layouts are operation-selected only for
                        // their own mechanism (0xFFFF here never selects
                        // them); direct name binding still resolves.
                        if d.name != "gcm_wrap" && d.name != "ccm_wrap" {
                            assert!(
                                r.descriptor.name != "gcm_wrap" && r.descriptor.name != "ccm_wrap",
                                "wrap layout selected without operation context"
                            );
                        }
                        // Alternate selection obeys the length rule.
                        match r.alternate {
                            None => {}
                            Some(a) => assert!(
                                *len >= native_size_of(a.fields, *abi) as u64,
                                "alternate selected below its size for {}",
                                d.name
                            ),
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod eligibility_tests {
    use super::{
        ABI_EXEMPT_FINGERPRINT, FLAT_MAX_BYTES, FlatDecision, FlatDenyReason, FlatRequest,
        Operation, OperationContext, ParamAbi, SHAPE_DESCRIPTORS, ShapeResolver,
        VENDOR_FLAT_ALLOWLIST, decide_flat, decide_flat_for_registry, is_vendor_mechanism,
        vendor_flat_allowed,
    };
    use crate::mechanism_registry::MechanismRegistry;

    const LP64: ParamAbi = ParamAbi::Lp64NativeLe;
    const ILP32: ParamAbi = ParamAbi::Ilp32NativeLe;

    fn matching_fp(bound: &str, mech: u64, op: Operation, len: u64, abi: ParamAbi) -> u64 {
        ShapeResolver::resolve(
            Some(bound),
            OperationContext { mechanism: mech, operation: op, length: len },
            abi,
        )
        .unwrap()
        .fingerprint(abi)
    }

    fn req(
        mechanism: u64,
        declared_len: u64,
        bound_shape: Option<&'static str>,
        parameterless_listed: bool,
        peer_fingerprint: u64,
    ) -> FlatRequest<'static> {
        FlatRequest {
            mechanism,
            operation: Operation::General,
            declared_len,
            bound_shape,
            parameterless_listed,
            excluded: false,
            peer_fingerprint,
            peer_abi: LP64,
            local_abi: LP64,
        }
    }

    #[test]
    fn exclusion_wins_over_everything() {
        // Operator exclusion maps to MECHANISM_INVALID (S2 §6 RV table) no
        // matter the shape, length, vendor status, or fingerprints.
        let mut r = req(
            0x1057,
            1,
            Some("eddsa"),
            true,
            matching_fp("eddsa", 0x1057, Operation::General, 1, LP64),
        );
        r.excluded = true;
        assert_eq!(decide_flat(r), FlatDecision::Excluded);
        let mut over = req(0x0250, FLAT_MAX_BYTES + 1, None, true, ABI_EXEMPT_FINGERPRINT);
        over.excluded = true;
        assert_eq!(decide_flat(over), FlatDecision::Excluded);
        let mut vendor = req(0x8000_1087, 1, Some("gcm"), false, 0);
        vendor.excluded = true;
        assert_eq!(decide_flat(vendor), FlatDecision::Excluded);
    }

    #[test]
    fn over_cap_denied_before_resolution() {
        assert_eq!(
            decide_flat(req(0x0250, FLAT_MAX_BYTES + 1, None, true, ABI_EXEMPT_FINGERPRINT)),
            FlatDecision::Denied(FlatDenyReason::OverCap)
        );
        // Unknown shapes are still unknown shapes (cap is checked after
        // exclusion/vendor, before kind rules — deterministic order).
        assert_eq!(
            decide_flat(req(0xDEAD, FLAT_MAX_BYTES + 1, Some("nope"), false, 0)),
            FlatDecision::Denied(FlatDenyReason::OverCap)
        );
        assert_eq!(FLAT_MAX_BYTES, 64 * 1024);
    }

    #[test]
    fn vendor_binding_without_allowlist_denied_flat() {
        // TOML may bind a vendor mechanism to a compiled shape (the
        // registry accepts it) — but that binding alone never authorizes
        // Flat (S2 §4: vendor IDs need a compiled allowlist entry).
        let reg = MechanismRegistry::load_with_override_str(Some(
            "parameterless = [0x80FF0001]\n[[params]]\nshape = \"gcm\"\nmechanisms = [0x80001087]\n",
        ))
        .unwrap();
        assert_eq!(reg.param_shape(0x8000_1087), Some("gcm"));
        assert!(reg.is_parameterless(0x80FF_0001));
        assert_eq!(
            decide_flat_for_registry(&reg, 0x8000_1087, Operation::General, 1, 0, LP64, LP64),
            FlatDecision::Denied(FlatDenyReason::VendorWithoutAllowlist)
        );
        assert_eq!(
            decide_flat_for_registry(
                &reg,
                0x80FF_0001,
                Operation::General,
                16,
                ABI_EXEMPT_FINGERPRINT,
                LP64,
                LP64
            ),
            FlatDecision::Denied(FlatDenyReason::VendorWithoutAllowlist)
        );
        // Unknown vendor IDs likewise (no binding, no allowlist).
        assert_eq!(
            decide_flat_for_registry(&reg, 0x8000_9999, Operation::General, 1, 0, LP64, LP64),
            FlatDecision::Denied(FlatDenyReason::VendorWithoutAllowlist)
        );
    }

    #[test]
    fn vendor_allowlist_positive_and_negative() {
        // The compiled allowlist starts empty: no vendor Flat in v1.
        assert!(VENDOR_FLAT_ALLOWLIST.is_empty());
        assert!(!vendor_flat_allowed(VENDOR_FLAT_ALLOWLIST, 0x8000_1087, Some("gcm"), false));
        // Matching is exact on (mechanism, effective shape); the
        // parameterless marker only applies to parameterless-listed IDs.
        let list: &[(u64, &str)] = &[(0x8000_1087, "gcm"), (0x80FF_0001, "parameterless")];
        assert!(vendor_flat_allowed(list, 0x8000_1087, Some("gcm"), false));
        assert!(!vendor_flat_allowed(list, 0x8000_1087, Some("iv"), false));
        assert!(!vendor_flat_allowed(list, 0x8000_1088, Some("gcm"), false));
        assert!(vendor_flat_allowed(list, 0x80FF_0001, None, true));
        assert!(!vendor_flat_allowed(list, 0x80FF_0001, None, false));
        // A registered param shape wins over the parameterless listing
        // here too (effective shape = bound shape).
        assert!(!vendor_flat_allowed(list, 0x80FF_0001, Some("gcm"), true));
    }

    #[test]
    fn is_vendor_mechanism_boundaries() {
        assert!(!is_vendor_mechanism(0x1087));
        assert!(!is_vendor_mechanism(0x7FFF_FFFF));
        assert!(is_vendor_mechanism(0x8000_0000));
        assert!(is_vendor_mechanism(0xFFFF_FFFF));
    }

    #[test]
    fn eddsa_dual_listing_param_shape_wins() {
        // CKM_EDDSA is dual-listed in the embedded registry (parameterless
        // entry + "eddsa" param shape). The param shape wins: a full
        // pointer image must NOT ride the parameterless arbitrary-bytes
        // rule (smuggling block, S2 §4).
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        assert!(reg.is_parameterless(0x1057));
        assert_eq!(reg.param_shape(0x1057), Some("eddsa"));
        let decided = |len: u64, fp: u64| {
            decide_flat_for_registry(&reg, 0x1057, Operation::General, len, fp, LP64, LP64)
        };
        // Full native image (24 bytes LP64) is never Flat — typed owns it.
        assert_eq!(
            decided(24, matching_fp("eddsa", 0x1057, Operation::General, 24, LP64)),
            FlatDecision::Denied(FlatDenyReason::FullNativeImage)
        );
        // 1-byte degenerate form: within the safe prefix (16), matching
        // fingerprint → eligible (the S2 §1 evidence row).
        assert!(matches!(
            decided(1, matching_fp("eddsa", 0x1057, Operation::General, 1, LP64)),
            FlatDecision::Eligible(_)
        ));
        // Past the first unsafe offset (pContextData at 16) → denied.
        assert_eq!(
            decided(17, matching_fp("eddsa", 0x1057, Operation::General, 17, LP64)),
            FlatDecision::Denied(FlatDenyReason::PrefixTooLong {
                declared_len: 17,
                first_unsafe_offset: 16
            })
        );
        // Fingerprint mismatch → denied even within the prefix.
        assert!(matches!(
            decided(1, 0x1234_5678),
            FlatDecision::Denied(FlatDenyReason::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn parameterless_only_carries_arbitrary_bytes_to_cap() {
        // SHA-256 is parameterless-only: any flat bytes to 64 KiB ride
        // (S2 §1 row 1: SHA-256 + 16 bytes), ABI-independent.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        assert!(reg.is_parameterless(0x0250));
        assert_eq!(reg.param_shape(0x0250), None);
        for len in [0, 1, 16, FLAT_MAX_BYTES] {
            let d = decide_flat_for_registry(
                &reg,
                0x0250,
                Operation::General,
                len,
                ABI_EXEMPT_FINGERPRINT,
                LP64,
                LP64,
            );
            assert!(matches!(d, FlatDecision::Eligible(_)), "len {len} must ride");
            if let FlatDecision::Eligible(g) = d {
                assert_eq!(g.fingerprint, ABI_EXEMPT_FINGERPRINT);
            }
        }
        // Cross-ABI peer: still eligible (bytes are bytes).
        assert!(matches!(
            decide_flat_for_registry(
                &reg,
                0x0250,
                Operation::General,
                16,
                ABI_EXEMPT_FINGERPRINT,
                ILP32,
                LP64
            ),
            FlatDecision::Eligible(_)
        ));
        assert_eq!(
            decide_flat_for_registry(
                &reg,
                0x0250,
                Operation::General,
                FLAT_MAX_BYTES + 1,
                ABI_EXEMPT_FINGERPRINT,
                LP64,
                LP64
            ),
            FlatDecision::Denied(FlatDenyReason::OverCap)
        );
    }

    #[test]
    fn byte_buffer_is_abi_independent() {
        // AES-CBC binds "iv" (raw bytes, no struct): eligible at any
        // length to the cap, on any peer ABI.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        assert_eq!(reg.param_shape(0x1082), Some("iv"));
        for len in [0, 8, 16, 48, 100, FLAT_MAX_BYTES] {
            for peer in [LP64, ILP32] {
                let d = decide_flat_for_registry(
                    &reg,
                    0x1082,
                    Operation::General,
                    len,
                    ABI_EXEMPT_FINGERPRINT,
                    peer,
                    LP64,
                );
                assert!(matches!(d, FlatDecision::Eligible(_)), "len {len} peer {peer:?}");
            }
        }
    }

    #[test]
    fn scalar_flat_requires_fingerprint_match() {
        // RSA-PSS (3 × CK_ULONG = 24 bytes LP64): noncanonical lengths
        // ride only on fingerprint match; the native image never does.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        assert_eq!(reg.param_shape(0x000D), Some("rsa_pss"));
        let good3 = matching_fp("rsa_pss", 0x000D, Operation::General, 3, LP64);
        assert!(matches!(
            decide_flat_for_registry(&reg, 0x000D, Operation::General, 3, good3, LP64, LP64),
            FlatDecision::Eligible(_)
        ));
        let good24 = matching_fp("rsa_pss", 0x000D, Operation::General, 24, LP64);
        assert_eq!(
            decide_flat_for_registry(&reg, 0x000D, Operation::General, 24, good24, LP64, LP64),
            FlatDecision::Denied(FlatDenyReason::FullNativeImage)
        );
        // Wrong fingerprint (e.g. another shape's) → denied.
        let gcm_fp = matching_fp("gcm", 0x1087, Operation::General, 1, LP64);
        assert!(matches!(
            decide_flat_for_registry(&reg, 0x000D, Operation::General, 3, gcm_fp, LP64, LP64),
            FlatDecision::Denied(FlatDenyReason::FingerprintMismatch { .. })
        ));
        // Cross-ABI struct prefix → denied before the fingerprint check.
        assert_eq!(
            decide_flat_for_registry(&reg, 0x000D, Operation::General, 3, good3, ILP32, LP64),
            FlatDecision::Denied(FlatDenyReason::AbiMismatch { expected: LP64, got: ILP32 })
        );
    }

    #[test]
    fn pointer_prefix_rule() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        // GCM's first field is a pointer (first unsafe offset 0): only
        // the empty prefix rides.
        let g0 = matching_fp("gcm", 0x1087, Operation::General, 0, LP64);
        assert!(matches!(
            decide_flat_for_registry(&reg, 0x1087, Operation::General, 0, g0, LP64, LP64),
            FlatDecision::Eligible(_)
        ));
        let g1 = matching_fp("gcm", 0x1087, Operation::General, 1, LP64);
        assert_eq!(
            decide_flat_for_registry(&reg, 0x1087, Operation::General, 1, g1, LP64, LP64),
            FlatDecision::Denied(FlatDenyReason::PrefixTooLong {
                declared_len: 1,
                first_unsafe_offset: 0
            })
        );
        // Single-handle params (object_handle): the handle sits at offset
        // 0, so only the empty prefix rides (handles remap via typed
        // paths only, S2 §10).
        let h0 = matching_fp("object_handle", 0x0360, Operation::General, 0, LP64);
        let r = FlatRequest {
            mechanism: 0x0360,
            operation: Operation::General,
            declared_len: 0,
            bound_shape: Some("object_handle"),
            parameterless_listed: false,
            excluded: false,
            peer_fingerprint: h0,
            peer_abi: LP64,
            local_abi: LP64,
        };
        assert!(matches!(decide_flat(r), FlatDecision::Eligible(_)));
        let h4 = matching_fp("object_handle", 0x0360, Operation::General, 4, LP64);
        let r = FlatRequest { declared_len: 4, peer_fingerprint: h4, ..r };
        assert_eq!(
            decide_flat(r),
            FlatDecision::Denied(FlatDenyReason::PrefixTooLong {
                declared_len: 4,
                first_unsafe_offset: 0
            })
        );
    }

    #[test]
    fn nested_or_output_never_flat() {
        // Tail shapes ride typed envelopes only (S2 §8); even short
        // prefixes with matching fingerprints are denied Flat.
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        for (mech, shape) in [
            (0x03AC_u64, "sp800_108_kdf"),
            (0x1011, "kea_derive"),
            (0x0378, "tls_prf"),
            (0x0372, "ssl3_key_mat"),
            (0x03D4, "wtls_key_mat"),
        ] {
            assert_eq!(reg.param_shape(mech), Some(shape), "binding for {mech:#x}");
            for len in [0, 1] {
                let fp = matching_fp(shape, mech, Operation::General, len, LP64);
                assert_eq!(
                    decide_flat_for_registry(&reg, mech, Operation::General, len, fp, LP64, LP64),
                    FlatDecision::Denied(FlatDenyReason::NestedOrOutput),
                    "{shape} len {len} must not ride Flat"
                );
            }
        }
        // Unbound-but-compiled tail shapes: the daemon resolves from its
        // own compiled tables (S2 §2 principle 2), same denial.
        for shape in ["kip", "otp", "skipjack_private_wrap", "skipjack_relayx"] {
            let fp = matching_fp(shape, 0xFFFF, Operation::General, 1, LP64);
            assert_eq!(
                decide_flat(req(0xFFFF, 1, Some(shape), false, fp)),
                FlatDecision::Denied(FlatDenyReason::NestedOrOutput),
                "{shape} must not ride Flat"
            );
        }
    }

    #[test]
    fn full_native_images_never_flat_sweep() {
        // Every struct form at exactly its native size is denied Flat
        // (the typed path owns canonical lengths) — with a matching
        // fingerprint, so the denial is the image rule, not mismatch.
        for d in SHAPE_DESCRIPTORS {
            if d.fields.is_empty() {
                continue;
            }
            for abi in [LP64, ILP32] {
                let r = ShapeResolver::resolve(
                    Some(d.name),
                    OperationContext {
                        mechanism: 0xFFFF,
                        operation: Operation::General,
                        length: 0,
                    },
                    abi,
                )
                .unwrap();
                let native = r.native_size(abi).unwrap() as u64;
                let fp = r.fingerprint(abi);
                let req = FlatRequest {
                    mechanism: 0xFFFF,
                    operation: Operation::General,
                    declared_len: native,
                    bound_shape: Some(d.name),
                    parameterless_listed: false,
                    excluded: false,
                    peer_fingerprint: fp,
                    peer_abi: abi,
                    local_abi: abi,
                };
                // Nested/output denies earlier (still denied, other reason).
                match decide_flat(req) {
                    FlatDecision::Denied(FlatDenyReason::FullNativeImage) => {}
                    FlatDecision::Denied(FlatDenyReason::NestedOrOutput) => {}
                    other => panic!("native image rode Flat for {}: {other:?}", d.name),
                }
            }
        }
    }

    #[test]
    fn unknown_shape_denied() {
        assert_eq!(
            decide_flat(req(0xFFFF, 1, Some("no_such_shape"), false, 0)),
            FlatDecision::Denied(FlatDenyReason::UnknownShape)
        );
        assert_eq!(
            decide_flat(req(0xFFFF, 1, None, false, 0)),
            FlatDecision::Denied(FlatDenyReason::UnknownShape)
        );
    }

    #[test]
    fn registry_convenience_matches_core() {
        let reg = MechanismRegistry::load_with_override_str(None).unwrap();
        // Parameterless-only via both APIs.
        let via_reg = decide_flat_for_registry(
            &reg,
            0x0250,
            Operation::General,
            16,
            ABI_EXEMPT_FINGERPRINT,
            LP64,
            LP64,
        );
        let via_core = decide_flat(req(0x0250, 16, None, true, ABI_EXEMPT_FINGERPRINT));
        assert_eq!(via_reg, via_core);
        // Bound shape via both APIs.
        let fp = matching_fp("rsa_pss", 0x000D, Operation::General, 3, LP64);
        let via_reg = decide_flat_for_registry(&reg, 0x000D, Operation::General, 3, fp, LP64, LP64);
        let via_core = decide_flat(req(0x000D, 3, Some("rsa_pss"), false, fp));
        assert_eq!(via_reg, via_core);
    }
}

#[cfg(test)]
mod crosscheck_tests {
    //! Ground the table against `cryptoki-sys` (host ABI) and published
    //! binding sizes (ILP32) plus hand-derived packed vectors (LLP64 and
    //! ILP32-pack1).
    use super::{ParamAbi, SHAPE_DESCRIPTORS, ShapeResolver, native_size_of};

    fn lp64_size(shape: &str) -> usize {
        let d = ShapeResolver::descriptor(shape).unwrap();
        native_size_of(d.fields, ParamAbi::Lp64NativeLe)
    }

    // Host-ABI cross-checks: the table's LP64 derivation must equal the
    // linked cryptoki structs byte-for-byte (unix 64-bit only: on Windows
    // the linked cryptoki-sys 0.5.0 bindings are `#[repr(C, packed)]`
    // LLP64-pack1 — 97 of 99 CK_* structs, the 2 plain ones being the
    // all-u8 CK_DATE/CK_VERSION — so LP64 byte-equality cannot hold there.
    // Bindgen `size_of` assertions in `x86_64-pc-windows-msvc.rs`, all
    // align 1: CK_GCM_WRAP_PARAMS 36 (56 LP64), CK_CCM_WRAP_PARAMS 40
    // (64 LP64), CK_GCM_PARAMS 32 (48 LP64), CK_RSA_PKCS_PSS_PARAMS 12
    // (24 LP64), CK_MECHANISM 16 (24 LP64). The packed layout, modeled
    // here as `Llp64Packed1Le`, is covered by the hand-derived vectors
    // below, which agree with those assertions).
    #[cfg(all(unix, target_pointer_width = "64"))]
    #[test]
    fn lp64_native_sizes_match_cryptoki() {
        use cryptoki_sys::*;
        assert_eq!(lp64_size("rsa_pss"), size_of::<CK_RSA_PKCS_PSS_PARAMS>());
        assert_eq!(lp64_size("rsa_oaep"), size_of::<CK_RSA_PKCS_OAEP_PARAMS>());
        assert_eq!(lp64_size("gcm"), size_of::<CK_GCM_PARAMS>());
        assert_eq!(lp64_size("ccm"), size_of::<CK_CCM_PARAMS>());
        assert_eq!(lp64_size("ecdh1_derive"), size_of::<CK_ECDH1_DERIVE_PARAMS>());
        assert_eq!(lp64_size("ecdh2_derive"), size_of::<CK_ECDH2_DERIVE_PARAMS>());
        assert_eq!(lp64_size("aes_ctr"), size_of::<CK_AES_CTR_PARAMS>());
        assert_eq!(lp64_size("camellia_ctr"), size_of::<CK_CAMELLIA_CTR_PARAMS>());
        assert_eq!(lp64_size("hkdf"), size_of::<CK_HKDF_PARAMS>());
        assert_eq!(lp64_size("eddsa"), size_of::<CK_EDDSA_PARAMS>());
        assert_eq!(lp64_size("chacha20"), size_of::<CK_CHACHA20_PARAMS>());
        assert_eq!(lp64_size("salsa20"), size_of::<CK_SALSA20_PARAMS>());
        assert_eq!(
            lp64_size("salsa20_chacha20_poly1305"),
            size_of::<CK_SALSA20_CHACHA20_POLY1305_PARAMS>()
        );
        assert_eq!(lp64_size("aes_cbc_encrypt_data"), size_of::<CK_AES_CBC_ENCRYPT_DATA_PARAMS>());
        assert_eq!(lp64_size("des_cbc_encrypt_data"), size_of::<CK_DES_CBC_ENCRYPT_DATA_PARAMS>());
        assert_eq!(
            lp64_size("camellia_cbc_encrypt_data"),
            size_of::<CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS>()
        );
        assert_eq!(
            lp64_size("aria_cbc_encrypt_data"),
            size_of::<CK_ARIA_CBC_ENCRYPT_DATA_PARAMS>()
        );
        assert_eq!(
            lp64_size("seed_cbc_encrypt_data"),
            size_of::<CK_SEED_CBC_ENCRYPT_DATA_PARAMS>()
        );
        assert_eq!(lp64_size("mac_general"), size_of::<CK_MAC_GENERAL_PARAMS>());
        assert_eq!(lp64_size("object_handle"), size_of::<CK_OBJECT_HANDLE>());
        assert_eq!(lp64_size("extract"), size_of::<CK_EXTRACT_PARAMS>());
        assert_eq!(lp64_size("key_derivation_string"), size_of::<CK_KEY_DERIVATION_STRING_DATA>());
        assert_eq!(lp64_size("gcm_wrap"), size_of::<CK_GCM_WRAP_PARAMS>());
        assert_eq!(lp64_size("ccm_wrap"), size_of::<CK_CCM_WRAP_PARAMS>());
        assert_eq!(lp64_size("rc5"), size_of::<CK_RC5_PARAMS>());
        assert_eq!(lp64_size("rc5_mac_general"), size_of::<CK_RC5_MAC_GENERAL_PARAMS>());
        assert_eq!(lp64_size("rc5_cbc"), size_of::<CK_RC5_CBC_PARAMS>());
        assert_eq!(lp64_size("rc2_cbc"), size_of::<CK_RC2_CBC_PARAMS>());
        assert_eq!(lp64_size("rc2_mac_general"), size_of::<CK_RC2_MAC_GENERAL_PARAMS>());
        assert_eq!(lp64_size("xeddsa"), size_of::<CK_XEDDSA_PARAMS>());
        assert_eq!(lp64_size("tls_mac"), size_of::<CK_TLS_MAC_PARAMS>());
        assert_eq!(lp64_size("rsa_aes_key_wrap"), size_of::<CK_RSA_AES_KEY_WRAP_PARAMS>());
        assert_eq!(lp64_size("sign_additional_context"), size_of::<CK_SIGN_ADDITIONAL_CONTEXT>());
        assert_eq!(lp64_size("pkcs5_pbkd2"), size_of::<CK_PKCS5_PBKD2_PARAMS2>());
        assert_eq!(
            lp64_size("wtls_master_key_derive"),
            size_of::<CK_WTLS_MASTER_KEY_DERIVE_PARAMS>()
        );
        assert_eq!(lp64_size("wtls_prf"), size_of::<CK_WTLS_PRF_PARAMS>());
        assert_eq!(lp64_size("wtls_key_mat"), size_of::<CK_WTLS_KEY_MAT_PARAMS>());
        assert_eq!(
            lp64_size("tls12_master_key_derive"),
            size_of::<CK_TLS12_MASTER_KEY_DERIVE_PARAMS>()
        );
        assert_eq!(lp64_size("tls_prf"), size_of::<CK_TLS_PRF_PARAMS>());
        assert_eq!(lp64_size("tls_kdf"), size_of::<CK_TLS_KDF_PARAMS>());
        assert_eq!(
            lp64_size("ssl3_master_key_derive"),
            size_of::<CK_SSL3_MASTER_KEY_DERIVE_PARAMS>()
        );
        assert_eq!(
            lp64_size("tls12_extended_master_key_derive"),
            size_of::<CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS>()
        );
        assert_eq!(lp64_size("ssl3_key_mat"), size_of::<CK_SSL3_KEY_MAT_PARAMS>());
        assert_eq!(lp64_size("pbe"), size_of::<CK_PBE_PARAMS>());
        assert_eq!(lp64_size("ecdh_aes_key_wrap"), size_of::<CK_ECDH_AES_KEY_WRAP_PARAMS>());
        assert_eq!(lp64_size("ecmqv_derive"), size_of::<CK_ECMQV_DERIVE_PARAMS>());
        assert_eq!(lp64_size("x942_dh1_derive"), size_of::<CK_X9_42_DH1_DERIVE_PARAMS>());
        assert_eq!(lp64_size("x942_dh2_derive"), size_of::<CK_X9_42_DH2_DERIVE_PARAMS>());
        assert_eq!(lp64_size("x942_mqv_derive"), size_of::<CK_X9_42_MQV_DERIVE_PARAMS>());
        assert_eq!(lp64_size("gostr3410_derive"), size_of::<CK_GOSTR3410_DERIVE_PARAMS>());
        assert_eq!(lp64_size("gostr3410_key_wrap"), size_of::<CK_GOSTR3410_KEY_WRAP_PARAMS>());
        assert_eq!(lp64_size("key_wrap_set_oaep"), size_of::<CK_KEY_WRAP_SET_OAEP_PARAMS>());
        assert_eq!(lp64_size("kea_derive"), size_of::<CK_KEA_DERIVE_PARAMS>());
        assert_eq!(lp64_size("ike_prf_derive"), size_of::<CK_IKE_PRF_DERIVE_PARAMS>());
        assert_eq!(lp64_size("ike1_prf_derive"), size_of::<CK_IKE1_PRF_DERIVE_PARAMS>());
        assert_eq!(lp64_size("ike1_extended_derive"), size_of::<CK_IKE1_EXTENDED_DERIVE_PARAMS>());
        assert_eq!(lp64_size("ike2_prf_plus_derive"), size_of::<CK_IKE2_PRF_PLUS_DERIVE_PARAMS>());
        assert_eq!(lp64_size("kip"), size_of::<CK_KIP_PARAMS>());
        assert_eq!(lp64_size("otp"), size_of::<CK_OTP_PARAMS>());
        assert_eq!(
            lp64_size("skipjack_private_wrap"),
            size_of::<CK_SKIPJACK_PRIVATE_WRAP_PARAMS>()
        );
        assert_eq!(lp64_size("skipjack_relayx"), size_of::<CK_SKIPJACK_RELAYX_PARAMS>());
        assert_eq!(lp64_size("sp800_108_kdf"), size_of::<CK_SP800_108_KDF_PARAMS>());
        assert_eq!(
            lp64_size("sp800_108_feedback_kdf"),
            size_of::<CK_SP800_108_FEEDBACK_KDF_PARAMS>()
        );
        // Alternate forms share the table's alternate field lists.
        let d = ShapeResolver::descriptor("sign_additional_context").unwrap();
        assert_eq!(
            native_size_of(d.alternate_forms[0].fields, ParamAbi::Lp64NativeLe),
            size_of::<CK_HASH_SIGN_ADDITIONAL_CONTEXT>()
        );
        let d = ShapeResolver::descriptor("ssl3_key_mat").unwrap();
        assert_eq!(
            native_size_of(d.alternate_forms[0].fields, ParamAbi::Lp64NativeLe),
            size_of::<CK_TLS12_KEY_MAT_PARAMS>()
        );
        let d = ShapeResolver::descriptor("gcm_compat").unwrap();
        assert_eq!(
            native_size_of(d.alternate_forms[0].fields, ParamAbi::Lp64NativeLe),
            size_of::<CK_GCM_PARAMS>()
        );
        // Local shim mirrors (no cryptoki struct): sizes from the mirror
        // definitions (h_key/ulong/ptr/ulong and h_key/ptr/ulong/ptr/ulong).
        assert_eq!(lp64_size("kmac"), 32);
        assert_eq!(lp64_size("mu_gen"), 40);
    }

    #[cfg(all(unix, target_pointer_width = "64"))]
    #[test]
    fn lp64_field_offsets_match_cryptoki() {
        use std::mem::offset_of;

        use super::field_offset_of;
        use cryptoki_sys::*;
        let lp64 = ParamAbi::Lp64NativeLe;
        let offs = |shape: &str| {
            let d = ShapeResolver::descriptor(shape).unwrap();
            (0..d.fields.len()).map(|i| field_offset_of(d.fields, lp64, i)).collect::<Vec<_>>()
        };
        // Padding-risky shapes only (u8/byte-array/nested fields); all
        // ulong/pointer shapes have trivial i*8 offsets covered by sizes.
        assert_eq!(offs("hkdf"), vec![0, 1, 8, 16, 24, 32, 40, 48, 56]);
        assert_eq!(offset_of!(CK_HKDF_PARAMS, bExtract), 0);
        assert_eq!(offset_of!(CK_HKDF_PARAMS, bExpand), 1);
        assert_eq!(offset_of!(CK_HKDF_PARAMS, prfHashMechanism), 8);
        assert_eq!(offset_of!(CK_HKDF_PARAMS, hSaltKey), 40);
        assert_eq!(offs("eddsa"), vec![0, 8, 16]);
        assert_eq!(offset_of!(CK_EDDSA_PARAMS, phFlag), 0);
        assert_eq!(offset_of!(CK_EDDSA_PARAMS, ulContextDataLen), 8);
        assert_eq!(offset_of!(CK_EDDSA_PARAMS, pContextData), 16);
        assert_eq!(offs("kea_derive"), vec![0, 8, 16, 24, 32, 40]);
        assert_eq!(offset_of!(CK_KEA_DERIVE_PARAMS, isSender), 0);
        assert_eq!(offset_of!(CK_KEA_DERIVE_PARAMS, ulRandomLen), 8);
        assert_eq!(offset_of!(CK_KEA_DERIVE_PARAMS, RandomA), 16);
        assert_eq!(offs("key_wrap_set_oaep"), vec![0, 8, 16]);
        assert_eq!(offset_of!(CK_KEY_WRAP_SET_OAEP_PARAMS, bBC), 0);
        assert_eq!(offset_of!(CK_KEY_WRAP_SET_OAEP_PARAMS, pX), 8);
        assert_eq!(offs("ike_prf_derive"), vec![0, 8, 9, 16, 24, 32, 40, 48]);
        assert_eq!(offset_of!(CK_IKE_PRF_DERIVE_PARAMS, bDataAsKey), 8);
        assert_eq!(offset_of!(CK_IKE_PRF_DERIVE_PARAMS, bRekey), 9);
        assert_eq!(offset_of!(CK_IKE_PRF_DERIVE_PARAMS, pNi), 16);
        assert_eq!(offset_of!(CK_IKE_PRF_DERIVE_PARAMS, hNewKey), 48);
        assert_eq!(offs("ike1_prf_derive"), vec![0, 8, 16, 24, 32, 40, 48, 56, 64]);
        assert_eq!(offset_of!(CK_IKE1_PRF_DERIVE_PARAMS, bHasPrevKey), 8);
        assert_eq!(offset_of!(CK_IKE1_PRF_DERIVE_PARAMS, hKeygxy), 16);
        assert_eq!(offset_of!(CK_IKE1_PRF_DERIVE_PARAMS, keyNumber), 64);
        assert_eq!(offs("ike1_extended_derive"), vec![0, 8, 16, 24, 32]);
        assert_eq!(offset_of!(CK_IKE1_EXTENDED_DERIVE_PARAMS, hKeygxy), 16);
        assert_eq!(offs("ike2_prf_plus_derive"), vec![0, 8, 16, 24, 32]);
        assert_eq!(offset_of!(CK_IKE2_PRF_PLUS_DERIVE_PARAMS, hSeedKey), 16);
        assert_eq!(offs("rc2_cbc"), vec![0, 8]);
        assert_eq!(offset_of!(CK_RC2_CBC_PARAMS, iv), 8);
        assert_eq!(offs("aes_ctr"), vec![0, 8]);
        assert_eq!(offset_of!(CK_AES_CTR_PARAMS, cb), 8);
        assert_eq!(offs("camellia_ctr"), vec![0, 8]);
        assert_eq!(offs("aes_cbc_encrypt_data"), vec![0, 16, 24]);
        assert_eq!(offset_of!(CK_AES_CBC_ENCRYPT_DATA_PARAMS, pData), 16);
        assert_eq!(offs("des_cbc_encrypt_data"), vec![0, 8, 16]);
        assert_eq!(offset_of!(CK_DES_CBC_ENCRYPT_DATA_PARAMS, pData), 8);
        assert_eq!(offs("camellia_cbc_encrypt_data"), vec![0, 16, 24]);
        assert_eq!(offs("aria_cbc_encrypt_data"), vec![0, 16, 24]);
        assert_eq!(offs("seed_cbc_encrypt_data"), vec![0, 16, 24]);
        // Nested-inline shapes: top-level offsets + composed inner offsets.
        assert_eq!(offs("tls_kdf"), vec![0, 8, 16, 24, 56, 64]);
        assert_eq!(offset_of!(CK_TLS_KDF_PARAMS, RandomInfo), 24);
        assert_eq!(offset_of!(CK_SSL3_RANDOM_DATA, pClientRandom), 0);
        assert_eq!(offset_of!(CK_SSL3_RANDOM_DATA, ulServerRandomLen), 24);
        assert_eq!(offs("ssl3_key_mat"), vec![0, 8, 16, 24, 32, 64]);
        assert_eq!(offset_of!(CK_SSL3_KEY_MAT_PARAMS, bIsExport), 24);
        assert_eq!(offset_of!(CK_SSL3_KEY_MAT_PARAMS, RandomInfo), 32);
        assert_eq!(offset_of!(CK_SSL3_KEY_MAT_PARAMS, pReturnedKeyMaterial), 64);
        assert_eq!(offs("ssl3_master_key_derive"), vec![0, 32]);
        assert_eq!(offset_of!(CK_SSL3_MASTER_KEY_DERIVE_PARAMS, pVersion), 32);
        assert_eq!(offs("tls12_master_key_derive"), vec![0, 32, 40]);
        assert_eq!(offset_of!(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, pVersion), 32);
        assert_eq!(offset_of!(CK_TLS12_MASTER_KEY_DERIVE_PARAMS, prfHashMechanism), 40);
        assert_eq!(offs("wtls_master_key_derive"), vec![0, 8, 40]);
        assert_eq!(offset_of!(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, RandomInfo), 8);
        assert_eq!(offset_of!(CK_WTLS_MASTER_KEY_DERIVE_PARAMS, pVersion), 40);
        assert_eq!(offs("wtls_key_mat"), vec![0, 8, 16, 24, 32, 40, 48, 80]);
        assert_eq!(offset_of!(CK_WTLS_KEY_MAT_PARAMS, RandomInfo), 48);
        assert_eq!(offset_of!(CK_WTLS_KEY_MAT_PARAMS, pReturnedKeyMaterial), 80);
    }

    // 32-bit unix CI (if run): same host check against the ILP32 cryptoki
    // structs (sizes only; offsets follow the same engine).
    #[cfg(all(unix, target_pointer_width = "32"))]
    #[test]
    fn ilp32_host_sizes_match_cryptoki() {
        use cryptoki_sys::*;
        let ilp32 = ParamAbi::Ilp32NativeLe;
        let size = |shape: &str| {
            let d = ShapeResolver::descriptor(shape).unwrap();
            native_size_of(d.fields, ilp32)
        };
        assert_eq!(size("gcm"), size_of::<CK_GCM_PARAMS>());
        assert_eq!(size("ccm"), size_of::<CK_CCM_PARAMS>());
        assert_eq!(size("hkdf"), size_of::<CK_HKDF_PARAMS>());
        assert_eq!(size("eddsa"), size_of::<CK_EDDSA_PARAMS>());
        assert_eq!(size("rsa_pss"), size_of::<CK_RSA_PKCS_PSS_PARAMS>());
        assert_eq!(size("ssl3_key_mat"), size_of::<CK_SSL3_KEY_MAT_PARAMS>());
        assert_eq!(size("kea_derive"), size_of::<CK_KEA_DERIVE_PARAMS>());
        assert_eq!(size("ike1_prf_derive"), size_of::<CK_IKE1_PRF_DERIVE_PARAMS>());
        assert_eq!(size("tls_kdf"), size_of::<CK_TLS_KDF_PARAMS>());
        assert_eq!(size("pkcs5_pbkd2"), size_of::<CK_PKCS5_PBKD2_PARAMS2>());
    }

    // Published i686 binding sizes (cryptoki-sys size asserts) plus
    // hand-derived ILP32 sizes for structs without asserts (same C rules:
    // ulong/pointer 4 bytes, align 4). Host-independent: runs everywhere.
    const ILP32_SIZES: &[(&str, usize)] = &[
        ("rsa_pss", 12),
        ("rsa_oaep", 20),
        ("gcm", 24),
        ("ccm", 24),
        ("ecdh1_derive", 20),
        ("ecdh2_derive", 36),
        ("aes_ctr", 20),
        ("camellia_ctr", 20),
        ("hkdf", 32),
        ("eddsa", 12),
        ("chacha20", 16),
        ("salsa20", 12),
        ("gcm_wrap", 28),
        ("ccm_wrap", 32),
        ("rc5", 8),
        ("rc5_cbc", 16),
        ("rc2_cbc", 12),
        ("xeddsa", 4),
        ("tls_mac", 12),
        ("pkcs5_pbkd2", 36),
        ("wtls_prf", 28),
        ("wtls_key_mat", 44),
        ("tls_prf", 24),
        ("tls_kdf", 36),
        ("ssl3_key_mat", 36),
        ("pbe", 24),
        ("ecmqv_derive", 40),
        ("kea_derive", 24),
        ("kip", 16),
        ("otp", 8),
        ("sp800_108_kdf", 20),
        // Hand-derived (no i686 size assert published):
        ("salsa20_chacha20_poly1305", 16),
        ("aes_cbc_encrypt_data", 24),
        ("des_cbc_encrypt_data", 16),
        ("camellia_cbc_encrypt_data", 24),
        ("aria_cbc_encrypt_data", 24),
        ("seed_cbc_encrypt_data", 24),
        ("mac_general", 4),
        ("object_handle", 4),
        ("extract", 4),
        ("key_derivation_string", 8),
        ("rc5_mac_general", 12),
        ("rc2_mac_general", 8),
        ("rsa_aes_key_wrap", 8),
        ("sign_additional_context", 12),
        ("wtls_master_key_derive", 24),
        ("tls12_master_key_derive", 24),
        ("ssl3_master_key_derive", 20),
        ("tls12_extended_master_key_derive", 16),
        ("ecdh_aes_key_wrap", 16),
        ("x942_dh1_derive", 20),
        ("x942_dh2_derive", 36),
        ("x942_mqv_derive", 40),
        ("gostr3410_derive", 20),
        ("gostr3410_key_wrap", 20),
        ("key_wrap_set_oaep", 12),
        ("ike_prf_derive", 28),
        ("ike1_prf_derive", 36),
        ("ike1_extended_derive", 20),
        ("ike2_prf_plus_derive", 20),
        ("skipjack_private_wrap", 44),
        ("skipjack_relayx", 56),
        ("sp800_108_feedback_kdf", 28),
        ("kmac", 16),
        ("mu_gen", 20),
    ];

    #[test]
    fn ilp32_native_sizes_match_published_vectors() {
        assert_eq!(ILP32_SIZES.len(), 65);
        for (shape, want) in ILP32_SIZES {
            let d = ShapeResolver::descriptor(shape).unwrap();
            assert_eq!(
                native_size_of(d.fields, ParamAbi::Ilp32NativeLe),
                *want,
                "ILP32 size for {shape}"
            );
        }
        // Alternate forms (ILP32): hash +12→16? No: plain 12, hash 16.
        let d = ShapeResolver::descriptor("sign_additional_context").unwrap();
        assert_eq!(native_size_of(d.alternate_forms[0].fields, ParamAbi::Ilp32NativeLe), 16);
        let d = ShapeResolver::descriptor("ssl3_key_mat").unwrap();
        assert_eq!(native_size_of(d.alternate_forms[0].fields, ParamAbi::Ilp32NativeLe), 40);
        let d = ShapeResolver::descriptor("gcm_compat").unwrap();
        assert_eq!(native_size_of(d.alternate_forms[0].fields, ParamAbi::Ilp32NativeLe), 24);
    }

    // Hand-derived LLP64-pack1 sizes (ulong 4, pointer 8, align 1 — the
    // Windows `#pragma pack(1)` PKCS#11 layout). Full-table no-padding
    // property lives in engine_tests; these pin representative values.
    const LLP64_SIZES: &[(&str, usize)] = &[
        ("gcm", 32),
        ("hkdf", 38),
        ("eddsa", 13),
        ("ssl3_key_mat", 45),
        ("kea_derive", 33),
        ("otp", 12),
        ("rsa_pss", 12),
        ("tls_kdf", 52),
        ("ike1_prf_derive", 38),
        ("gcm_wrap", 36),
    ];

    #[test]
    fn llp64_packed_sizes_match_hand_vectors() {
        for (shape, want) in LLP64_SIZES {
            let d = ShapeResolver::descriptor(shape).unwrap();
            assert_eq!(
                native_size_of(d.fields, ParamAbi::Llp64Packed1Le),
                *want,
                "LLP64-pack1 size for {shape}"
            );
        }
    }

    // The exact ILP32-pack1 differs-set: (shape, form, ILP32-natural size,
    // packed-32 size) for every form whose natural layout carries padding
    // (10 shapes, 11 forms — the win32 WOW64 failures were exactly the
    // packing-sensitive readers of these forms). True native win32 sizes:
    // cryptoki-sys 0.5.0 has no x86-windows bindings, so win32 uses the
    // generic `repr(packed)` structs. Host-independent: runs everywhere;
    // the win32 WOW64 leg is the authentic gate that executes these
    // layouts against real packed `CK_*` structs.
    const PACKED32_DIFFERS: &[(&str, &str, usize, usize)] = &[
        ("eddsa", "", 12, 9),
        ("hkdf", "", 32, 30),
        ("ike1_extended_derive", "", 20, 17),
        ("ike1_prf_derive", "", 36, 30),
        ("ike2_prf_plus_derive", "", 20, 17),
        ("ike_prf_derive", "", 28, 26),
        ("kea_derive", "", 24, 21),
        ("key_wrap_set_oaep", "", 12, 9),
        ("ssl3_key_mat", "", 36, 33),
        ("ssl3_key_mat", "tls12", 40, 37),
        ("wtls_key_mat", "", 44, 41),
    ];

    #[test]
    fn packed32_sizes_match_hand_vectors_with_exact_differs_set() {
        assert_eq!(PACKED32_DIFFERS.len(), 11);
        let ilp32 = ParamAbi::Ilp32NativeLe;
        let packed32 = ParamAbi::Ilp32Packed1Le;
        // Listed forms carry exactly the pinned sizes on both ABIs.
        for (shape, form, want_ilp32, want_packed) in PACKED32_DIFFERS {
            let d = ShapeResolver::descriptor(shape).unwrap();
            let fields = if form.is_empty() {
                d.fields
            } else {
                d.alternate_forms.iter().find(|a| &a.name == form).unwrap().fields
            };
            assert_eq!(native_size_of(fields, ilp32), *want_ilp32, "ILP32 size for {shape}#{form}");
            assert_eq!(
                native_size_of(fields, packed32),
                *want_packed,
                "packed-32 size for {shape}#{form}"
            );
        }
        // Every other non-bare form is packing-insensitive: packed-32
        // equals ILP32-natural exactly (the differs-set above is complete).
        let listed = |shape: &str, form: &str| {
            PACKED32_DIFFERS.iter().any(|(s, f, _, _)| *s == shape && *f == form)
        };
        for d in SHAPE_DESCRIPTORS {
            if !d.fields.is_empty() && !listed(d.name, "") {
                assert_eq!(
                    native_size_of(d.fields, packed32),
                    native_size_of(d.fields, ilp32),
                    "unlisted packed-32 split: {}",
                    d.name
                );
            }
            for a in d.alternate_forms {
                if !listed(d.name, a.name) {
                    assert_eq!(
                        native_size_of(a.fields, packed32),
                        native_size_of(a.fields, ilp32),
                        "unlisted packed-32 split: {}#{}",
                        d.name,
                        a.name
                    );
                }
            }
        }
    }

    // `native()` pins, one per little-endian target family: exactly one
    // arm compiles per target (big-endian targets compile none —
    // `native()` is `None` there). The win32 arm executes only on the
    // win32 WOW64 CI leg (`cross-platform.yml` `win32` job): that leg is
    // the authentic gate for 32-bit Windows, and a width-blind
    // `cfg!(windows)` here mis-sized every pointer-bearing win32 struct.
    #[cfg(all(unix, target_pointer_width = "64", target_endian = "little"))]
    #[test]
    fn native_abi_is_lp64_on_unix64() {
        assert_eq!(ParamAbi::native(), Some(ParamAbi::Lp64NativeLe));
    }

    #[cfg(all(unix, target_pointer_width = "32", target_endian = "little"))]
    #[test]
    fn native_abi_is_ilp32_on_unix32() {
        assert_eq!(ParamAbi::native(), Some(ParamAbi::Ilp32NativeLe));
    }

    #[cfg(all(windows, target_pointer_width = "64", target_endian = "little"))]
    #[test]
    fn native_abi_is_llp64_on_win64() {
        assert_eq!(ParamAbi::native(), Some(ParamAbi::Llp64Packed1Le));
    }

    #[cfg(all(windows, target_pointer_width = "32", target_endian = "little"))]
    #[test]
    fn native_abi_is_packed32_on_win32() {
        // True native win32 layout is packed-32 (cryptoki-sys generic.rs
        // `repr(packed)` fallback), not ILP32-natural: the ILP32 pin
        // mis-sized every packing-sensitive win32 struct (cid-fix-3).
        assert_eq!(ParamAbi::native(), Some(ParamAbi::Ilp32Packed1Le));
    }
}
