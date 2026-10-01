//! Kani proofs for the pure `types` laws: width translation, attribute
//! classification, mechanism/object/session/slot/secret/output laws, plus
//! CkRv, CkInBuf, and the official-mechanism table (round 3).
//!
//! Compiled only under `cargo kani` (`--cfg kani`, declared via the
//! crate build script's `cargo::rustc-check-cfg` so stable/MSRV builds
//! stay warning-free); normal stable/MSRV builds never see this module,
//! so no manifest dependency or lockfile change is needed — `cargo kani`
//! injects the `kani` library itself. Run:
//! `cargo kani -p pkcs11-proxy-ng-types` (nightly lane, like Miri/fuzz).
//!
//! Kani checks memory safety, panics, and arithmetic overflow on every
//! path for free; the explicit asserts pin the "never silently
//! truncate" laws. Coverage shape varies per harness (see each proof's
//! doc comment): fully symbolic scalars/ids where tractable, bounded
//! models — fixed 8/12/6-byte inputs, 0..=8-byte secrets, a concrete
//! invalid-width set, a concrete flag table, one symbolic table index —
//! where CBMC needs a bound. The unit + randomized law tests in
//! `width.rs` cover examples; these proofs cover each modeled space
//! exhaustively, not the unbounded input space.

use crate::CkRv;
use crate::attribute::{CkAttributeType, is_value_bearing_secret};
use crate::input::CkInBuf;
use crate::mechanism::{CkMechanismFlags, CkMechanismType};
use crate::mechanism_official::pkcs11_3_2_official_mechanisms;
use crate::object::{CkKeyType, CkObjectClass};
use crate::output::attribute_outputs_defined;
use crate::secret::SecretBytes;
use crate::session::{CkSessionFlags, CkUserType};
use crate::slot::{CkSlotFlags, CkTokenFlags};
use crate::width::*;

fn sym_width() -> usize {
    if kani::any() { 4 } else { 8 }
}

fn sym_order() -> ByteOrder {
    if kani::any() { ByteOrder::Little } else { ByteOrder::Big }
}

/// reencode over all 8-byte inputs and all valid width/order combos:
/// no panic, no overflow, and Ok outputs have exactly elements*dst bytes.
#[kani::proof]
#[kani::unwind(3)]
fn reencode_8byte_no_panic_exact_len() {
    let src: [u8; 8] = kani::any();
    let sw = sym_width();
    let dw = sym_width();
    let order = sym_order();
    match reencode_ulong(&src, sw, dw, order) {
        Ok(out) => kani::assert(out.len() == (8 / sw) * dw, "exact output length"),
        Err(e) => kani::assert(e == WidthError::Overflow, "only narrowing can fail"),
    }
}

/// Misaligned inputs are rejected, never partially converted.
#[kani::proof]
fn reencode_misaligned_rejected() {
    let src: [u8; 12] = kani::any();
    // 12 is a multiple of 4 but not of 8.
    kani::assert(
        reencode_ulong(&src, 8, 4, sym_order()) == Err(WidthError::Misaligned),
        "12 bytes at width 8 is misaligned",
    );
    let odd: [u8; 6] = kani::any();
    kani::assert(
        reencode_ulong(&odd, 4, 8, sym_order()) == Err(WidthError::Misaligned),
        "6 bytes at width 4 is misaligned",
    );
}

/// Invalid widths (including 0 and huge) are rejected before any indexing.
///
/// NOTE: widths are a concrete invalid set, not fully symbolic `usize`.
/// A fully symbolic width makes `chunks_exact(sw)` unwind symbolically and
/// CBMC does not finish (>26 min single-threaded); the guard under test is
/// the `w == 4 || w == 8` check, which these boundary values pin exactly.
#[kani::proof]
fn reencode_bad_width_rejected_no_panic() {
    let src: [u8; 8] = kani::any();
    let order = sym_order();
    for bad in [0usize, 1, 2, 3, 5, 7, 9, 16, usize::MAX] {
        kani::assert(
            reencode_ulong(&src, bad, 8, order) == Err(WidthError::UnsupportedWidth),
            "bad src width rejected",
        );
        kani::assert(
            reencode_ulong(&src, 4, bad, order) == Err(WidthError::UnsupportedWidth),
            "bad dst width rejected",
        );
    }
}

/// Widen 4->8 then narrow 8->4: every value round-trips (widening never
/// overflows, and the narrowed value equals the original).
///
/// Unwind 6 covers the one-element reencode loop plus the 4-byte `memcmp`
/// in the final comparison (bound 3 fails on `memcmp.unwind.0`).
#[kani::proof]
#[kani::unwind(6)]
fn widen_narrow_roundtrip() {
    let elem: [u8; 4] = kani::any();
    let order = sym_order();
    let wide = reencode_ulong(&elem, 4, 8, order);
    kani::assert(wide.is_ok(), "widening never overflows");
    let back = reencode_ulong(&wide.unwrap(), 8, 4, order).unwrap();
    kani::assert(back == elem.to_vec(), "value round-trips");
}

/// translate_ulong_len over ALL u64 lengths and ALL usize widths:
/// no panic (no div-by-zero, no shift overflow), sentinel maps by
/// destination width, non-sentinel results rescale exactly.
#[kani::proof]
fn translate_len_no_panic_exact() {
    let len: u64 = kani::any();
    let sw: usize = kani::any();
    let dw: usize = kani::any();
    let r = translate_ulong_len(len, sw, dw);
    let valid = (sw == 4 || sw == 8) && (dw == 4 || dw == 8);
    if !valid {
        kani::assert(r == Err(WidthError::UnsupportedWidth), "bad widths rejected first");
    } else if len == CANONICAL_UNAVAILABLE {
        kani::assert(r == Ok(all_ones(dw)), "sentinel maps to dst all-ones");
    } else {
        let elements = len / sw as u64;
        match elements.checked_mul(dw as u64) {
            Some(want) => kani::assert(r == Ok(want), "exact rescale"),
            None => kani::assert(r == Err(WidthError::LengthOverflow), "length overflow reported"),
        }
    }
}

/// decanonicalize never truncates: Ok(v) always fits the destination width.
#[kani::proof]
fn decanonicalize_never_truncates() {
    let wire: u64 = kani::any();
    let dw = sym_width();
    match decanonicalize_ulong(wire, dw) {
        Ok(v) => kani::assert(v <= all_ones(dw), "result fits dst width"),
        Err(e) => kani::assert(e == WidthError::Overflow, "only overflow fails"),
    }
}

/// narrow_info_field never errors and never exceeds dst all-ones.
#[kani::proof]
fn narrow_info_field_bounded() {
    let wire: u64 = kani::any();
    let dw = sym_width();
    let v = narrow_info_field(wire, dw);
    kani::assert(v <= all_ones(dw), "bounded by dst all-ones");
    if wire != CANONICAL_UNAVAILABLE && wire <= all_ones(dw) {
        kani::assert(v == wire, "representable values pass through");
    }
}

/// checked_narrow: Some(v) iff v fits; wide-nonzero never becomes 0/OK.
#[kani::proof]
fn checked_narrow_sound_and_complete() {
    let wire: u64 = kani::any();
    let dw = sym_width();
    match checked_narrow_to_width(wire, dw) {
        Some(v) => kani::assert(v == wire && wire <= all_ones(dw), "Some means fits"),
        None => kani::assert(wire > all_ones(dw), "None means unrepresentable"),
    }
}

/// u32->u8 matches the primitive exactly on all inputs.
#[kani::proof]
fn narrow_u32_matches_primitive() {
    let v: u32 = kani::any();
    kani::assert(narrow_u32_to_u8(v).ok() == u8::try_from(v).ok(), "matches primitive");
}

// ── Attribute-classifier laws (K1) ──────────────────────────────────────
// The width bridge (ADR-0011 D10) routes attribute values by these
// predicates; a misclassification is invisible at same width but corrupts
// values across an ABI boundary. The fuzz harness asserts these over
// examples; these proofs cover all 2^64 type ids.

/// Scalar shapes are disjoint: no id is two of bool/ulong/ulong-array.
#[kani::proof]
fn attr_scalar_kinds_disjoint() {
    let t = CkAttributeType(kani::any());
    let n = [t.is_bool(), t.is_ulong(), t.is_ulong_array()].iter().filter(|b| **b).count();
    kani::assert(n <= 1, "scalar kinds disjoint");
}

/// Nested-template ids always carry the CKF_ARRAY_ATTRIBUTE flag.
#[kani::proof]
fn attr_template_implies_array_flag() {
    let t = CkAttributeType(kani::any());
    if t.is_attribute_template() {
        kani::assert(t.is_array_attribute(), "template implies array flag");
    }
}

/// Allocation-size ids are width-bridged scalars: the absurd-allocation
/// guard (W1-C9-11) only ever applies to `is_ulong` values.
#[kani::proof]
fn attr_allocation_size_subset_of_ulong() {
    let t = CkAttributeType(kani::any());
    if t.is_allocation_size() {
        kani::assert(t.is_ulong(), "allocation-size implies ulong scalar");
    }
}

/// Secret classification matches the independently specified PKCS#11 id
/// set over all 2^64 ids: `CKA_VALUE` (0x11) plus the six RSA private-key
/// component attributes `CKA_PRIVATE_EXPONENT..=CKA_COEFFICIENT`
/// (0x123..=0x128). The expected set is written as literal spec ids, not
/// derived from the implementation's `VALUE_BEARING_SECRET` list, so a
/// missing or extra entry fails here. Totality (no panic) is free.
#[kani::proof]
fn attr_secret_classification_matches_spec() {
    let raw: u64 = kani::any();
    let t = CkAttributeType(raw);
    let expected = raw == 0x11 || (0x123..=0x128).contains(&raw);
    kani::assert(is_value_bearing_secret(t) == expected, "classification matches spec ids");
}

// ── Mechanism-type/flag laws (K1b) ─────────────────────────────────────
// Vendor construction and flag combination are total bit operations;
// a typo'd constant or a dropped bit would silently corrupt mechanism
// filtering or vendor dispatch.

/// `from_vendor` always sets the vendor bit and preserves the offset.
#[kani::proof]
fn mech_vendor_constructs_vendor_ids() {
    let off: u32 = kani::any();
    let t = CkMechanismType::from_vendor(off);
    kani::assert(t.is_vendor_defined(), "from_vendor sets vendor bit");
    kani::assert(t.0 == (0x8000_0000u64 | off as u64), "from_vendor preserves offset bits");
}

/// Vendor detection is exactly the high-bit test over all ids.
#[kani::proof]
fn mech_vendor_detects_high_bit() {
    let id: u64 = kani::any();
    kani::assert(
        CkMechanismType(id).is_vendor_defined() == (id & 0x8000_0000 == 0x8000_0000),
        "detection matches high-bit test",
    );
}

/// Flag OR is exact (no dropped bits) with zero identity.
#[kani::proof]
fn mech_flags_bitor_exact() {
    let a = CkMechanismFlags(kani::any());
    let b = CkMechanismFlags(kani::any());
    kani::assert((a | b).0 == a.0 | b.0, "bitor exact");
    kani::assert((a | CkMechanismFlags(0)).0 == a.0, "zero identity");
    let mut acc = a;
    acc |= b;
    kani::assert(acc.0 == a.0 | b.0, "bitor-assign exact");
}

/// Every named flag constant is a single bit (a doubled bit would
/// silently merge two capabilities), and distinct names sit on distinct
/// bits; aliases equal their primaries.
#[kani::proof]
fn mech_flag_consts_single_bit() {
    use CkMechanismFlags as F;
    let flags = [
        F::HW.0,
        F::MESSAGE_ENCRYPT.0,
        F::MESSAGE_DECRYPT.0,
        F::MESSAGE_SIGN.0,
        F::MESSAGE_VERIFY.0,
        F::MULTI_MESSAGE.0,
        F::FIND_OBJECTS.0,
        F::ENCRYPT.0,
        F::DECRYPT.0,
        F::DIGEST.0,
        F::SIGN.0,
        F::SIGN_RECOVER.0,
        F::VERIFY.0,
        F::VERIFY_RECOVER.0,
        F::GENERATE.0,
        F::GENERATE_KEY_PAIR.0,
        F::WRAP.0,
        F::UNWRAP.0,
        F::DERIVE.0,
        F::EC_F_P.0,
        F::EC_F_2M.0,
        F::EC_ECPARAMETERS.0,
        F::EC_OID.0,
        F::EC_UNCOMPRESS.0,
        F::EC_COMPRESS.0,
        F::EC_CURVENAME.0,
        F::ENCAPSULATE.0,
        F::DECAPSULATE.0,
        F::EXTENSION.0,
    ];
    for f in flags {
        kani::assert(f.is_power_of_two(), "flag const is a single bit");
    }
    // Pairwise distinct: two capabilities sharing one bit would be
    // indistinguishable to every flag filter. The intentional aliases
    // (`EC_NAMEDCURVE`/`EC_OID`, `MULTI_MESSGE`/`MULTI_MESSAGE`) are
    // pinned equal below and listed once here, so they cannot trip this.
    for (i, a) in flags.iter().enumerate() {
        for b in flags.iter().skip(i + 1) {
            kani::assert(a != b, "flag consts are pairwise distinct");
        }
    }
    kani::assert(F::MULTI_MESSGE.0 == F::MULTI_MESSAGE.0, "alias equal");
    kani::assert(F::EC_NAMEDCURVE.0 == F::EC_OID.0, "alias equal");
}

// ── SecretBytes laws (K2) ─────────────────────────────────────────────
// The wiping owner is the linchpin of ADR-0013: length/content must be
// exact (no silent truncation or extension) and access must stay scoped.

/// `copy_from_slice` preserves length, emptiness, and every byte.
#[kani::proof]
fn secret_copy_preserves_bytes() {
    let src: [u8; 8] = kani::any();
    let s = SecretBytes::copy_from_slice(&src);
    kani::assert(s.len() == 8, "length preserved");
    kani::assert(s.is_empty() == src.is_empty(), "emptiness matches");
    kani::assert(s.expose(|b| b == src), "bytes preserved");
}

/// `new` adopts the allocation with exact length; `default` is empty.
#[kani::proof]
fn secret_new_adopts_len() {
    let src: [u8; 8] = kani::any();
    let s = SecretBytes::new(src.to_vec());
    kani::assert(s.len() == 8, "adopted length exact");
    kani::assert(!s.is_empty(), "nonempty adopted");
    let d = SecretBytes::default();
    kani::assert(d.len() == 0, "default length zero");
    kani::assert(d.is_empty(), "default empty");
}

/// `copy_from_slice` over empty and bounded variable-length inputs
/// (every length 0..=8): exact length, exact emptiness, exact bytes.
/// The fixed four/eight-byte models above are retained as concrete
/// width pins; this proof adds the empty input and every length in
/// between. Lengths past 8 are covered by shape, not symbolically —
/// CBMC needs the bound — plus the native round-trip tests.
#[kani::proof]
#[kani::unwind(10)]
fn secret_copy_variable_len_exact() {
    let buf: [u8; 8] = kani::any();
    let len: usize = kani::any();
    kani::assume(len <= 8);
    let s = SecretBytes::copy_from_slice(&buf[..len]);
    kani::assert(s.len() == len, "length exact");
    kani::assert(s.is_empty() == (len == 0), "emptiness exact");
    kani::assert(s.expose(|b| b == &buf[..len]), "bytes exact");
}

/// `expose_mut` writes are visible through later `expose` reads.
#[kani::proof]
fn secret_expose_mut_writes_visible() {
    let src: [u8; 4] = kani::any();
    let mut s = SecretBytes::copy_from_slice(&src);
    s.expose_mut(|b| b[0] = b[0].wrapping_add(1));
    let expect = src[0].wrapping_add(1);
    kani::assert(s.expose(|b| b[0] == expect), "write visible");
    kani::assert(s.expose(|b| b[1..] == src[1..]), "rest untouched");
}

// ── Output/session/slot/object laws (K3) ────────────────────────────────
// Login/session/slot gating predicates decide authentication and token
// presence; an off-by-one here fails open or closed for every caller.

/// Output-defined RVs are exactly the documented four.
#[kani::proof]
fn output_defined_rvs_exact() {
    let rv = CkRv(kani::any());
    let v = rv.0;
    kani::assert(
        attribute_outputs_defined(rv)
            == (v == 0x0000_0000 || v == 0x0000_0011 || v == 0x0000_0012 || v == 0x0000_0150),
        "defined set is exactly OK/SENSITIVE/TYPE_INVALID/BUFFER_TOO_SMALL",
    );
}

/// `CkUserType::from_raw` accepts exactly 0/1/2 with round-trip.
#[kani::proof]
fn session_user_type_total() {
    let v: u64 = kani::any();
    match CkUserType::from_raw(v) {
        Some(t) => kani::assert(v <= 2 && t as u64 == v, "accepted values round-trip"),
        None => kani::assert(v > 2, "only 0/1/2 accepted"),
    }
}

/// Session/slot/token flag predicates match their bit tests; OR is exact.
#[kani::proof]
fn flags_predicates_match_bits() {
    let s = CkSessionFlags(kani::any());
    kani::assert(s.is_rw() == (s.0 & 0x00000002 != 0), "is_rw matches bit");
    let f = CkSlotFlags(kani::any());
    kani::assert(f.token_present() == (f.0 & 0x01 != 0), "token_present matches bit");
    let t = CkTokenFlags(kani::any());
    kani::assert(t.login_required() == (t.0 & 0x0000_0004 != 0), "login_required matches bit");
    kani::assert(
        t.token_initialized() == (t.0 & 0x0000_0400 != 0),
        "token_initialized matches bit",
    );
    let a = CkSessionFlags(kani::any());
    let b = CkSessionFlags(kani::any());
    kani::assert((a | b).0 == a.0 | b.0, "session bitor exact");
    let c = CkSlotFlags(kani::any());
    let d = CkSlotFlags(kani::any());
    kani::assert((c | d).0 == c.0 | d.0, "slot bitor exact");
    let e = CkTokenFlags(kani::any());
    let g = CkTokenFlags(kani::any());
    kani::assert((e | g).0 == e.0 | g.0, "token bitor exact");
}

/// Object-class/key-type vendor construction mirrors the mechanism law.
#[kani::proof]
fn object_vendor_laws() {
    let off: u32 = kani::any();
    let c = CkObjectClass::from_vendor(off);
    kani::assert(c.is_vendor_defined(), "class from_vendor sets bit");
    kani::assert(c.0 == (0x8000_0000u64 | off as u64), "class preserves offset");
    let k = CkKeyType::from_vendor(off);
    kani::assert(k.is_vendor_defined(), "keytype from_vendor sets bit");
    kani::assert(k.0 == (0x8000_0000u64 | off as u64), "keytype preserves offset");
}

// NOTE (K4 verdict, 2026-09-30): registry-query proofs over synthetic
// registries were attempted and REMOVED. CBMC ground for 19+ minutes to
// 6.3 GB RSS on a 2-entry concrete map: Kani models `RandomState` keys
// as nondeterministic, so every `HashMap` op runs symbolic SipHash —
// intractable regardless of proof formulation. The exclusion/security
// laws stay covered by `fuzz_registry` + the 48 native registry tests.
// Do not re-add map-touching harnesses without a deterministic-hasher
// story (e.g. `#[cfg(kani)]` hasher override — itself a correspondence
// risk, hence not done here).
//
// NOTE (K5 verdict, 2026-09-30): a proto-crate spike (attribute scalar
// roundtrip over prost types) was attempted and REMOVED: even a minimal
// scalar-only 4-byte proof blew past 5.9 GB/5 min and the harness failed
// to verify. The edge stays covered by `fuzz_attribute` + Miri
// classifier tests + the types-side laws above.

// ── Round 3 (2026-09-30): CkRv, CkInBuf, official-mechanism table ──

/// `is_ok`/`is_err` are exact complements over the whole u64 space.
#[kani::proof]
fn rv_ok_err_complementary() {
    let v: u64 = kani::any();
    let rv = CkRv(v);
    kani::assert(rv.is_ok() != rv.is_err(), "exactly one holds");
    kani::assert(rv.is_ok() == (v == 0), "ok pins zero");
}

/// `from_vendor`/`is_vendor_defined` pin the PKCS#11 vendor range exactly.
#[kani::proof]
fn rv_vendor_range_exact() {
    let off: u32 = kani::any();
    let v = CkRv::from_vendor(off);
    kani::assert(v.is_vendor_defined(), "from_vendor sets vendor bit");
    kani::assert(v.0 == (0x8000_0000u64 | off as u64), "offset preserved");
    let w: u64 = kani::any();
    kani::assert(
        CkRv(w).is_vendor_defined() == (w & 0x8000_0000 == 0x8000_0000),
        "vendor test is the high-bit mask",
    );
}

/// Every standard CKR_* constant sits below the vendor range; OK is zero
/// and VENDOR_DEFINED is exactly the range base. Pins the spec table
/// against value typos (e.g. a stray 0x8000_00B0).
#[kani::proof]
fn rv_standard_table_below_vendor_range() {
    kani::assert(CkRv::OK.0 == 0, "OK is zero");
    kani::assert(CkRv::VENDOR_DEFINED.0 == 0x8000_0000, "vendor base exact");
    kani::assert(CkRv::CANCEL.0 < 0x8000_0000, "CANCEL below vendor range");
    kani::assert(CkRv::HOST_MEMORY.0 < 0x8000_0000, "HOST_MEMORY below vendor range");
    kani::assert(CkRv::SLOT_ID_INVALID.0 < 0x8000_0000, "SLOT_ID_INVALID below vendor range");
    kani::assert(CkRv::GENERAL_ERROR.0 < 0x8000_0000, "GENERAL_ERROR below vendor range");
    kani::assert(CkRv::FUNCTION_FAILED.0 < 0x8000_0000, "FUNCTION_FAILED below vendor range");
    kani::assert(CkRv::ARGUMENTS_BAD.0 < 0x8000_0000, "ARGUMENTS_BAD below vendor range");
    kani::assert(CkRv::NO_EVENT.0 < 0x8000_0000, "NO_EVENT below vendor range");
    kani::assert(
        CkRv::NEED_TO_CREATE_THREADS.0 < 0x8000_0000,
        "NEED_TO_CREATE_THREADS below vendor range",
    );
    kani::assert(CkRv::CANT_LOCK.0 < 0x8000_0000, "CANT_LOCK below vendor range");
    kani::assert(
        CkRv::ATTRIBUTE_READ_ONLY.0 < 0x8000_0000,
        "ATTRIBUTE_READ_ONLY below vendor range",
    );
    kani::assert(
        CkRv::ATTRIBUTE_SENSITIVE.0 < 0x8000_0000,
        "ATTRIBUTE_SENSITIVE below vendor range",
    );
    kani::assert(
        CkRv::ATTRIBUTE_TYPE_INVALID.0 < 0x8000_0000,
        "ATTRIBUTE_TYPE_INVALID below vendor range",
    );
    kani::assert(
        CkRv::ATTRIBUTE_VALUE_INVALID.0 < 0x8000_0000,
        "ATTRIBUTE_VALUE_INVALID below vendor range",
    );
    kani::assert(CkRv::ACTION_PROHIBITED.0 < 0x8000_0000, "ACTION_PROHIBITED below vendor range");
    kani::assert(CkRv::DATA_INVALID.0 < 0x8000_0000, "DATA_INVALID below vendor range");
    kani::assert(CkRv::DATA_LEN_RANGE.0 < 0x8000_0000, "DATA_LEN_RANGE below vendor range");
    kani::assert(CkRv::DEVICE_ERROR.0 < 0x8000_0000, "DEVICE_ERROR below vendor range");
    kani::assert(CkRv::DEVICE_MEMORY.0 < 0x8000_0000, "DEVICE_MEMORY below vendor range");
    kani::assert(CkRv::DEVICE_REMOVED.0 < 0x8000_0000, "DEVICE_REMOVED below vendor range");
    kani::assert(
        CkRv::ENCRYPTED_DATA_INVALID.0 < 0x8000_0000,
        "ENCRYPTED_DATA_INVALID below vendor range",
    );
    kani::assert(
        CkRv::ENCRYPTED_DATA_LEN_RANGE.0 < 0x8000_0000,
        "ENCRYPTED_DATA_LEN_RANGE below vendor range",
    );
    kani::assert(
        CkRv::AEAD_DECRYPT_FAILED.0 < 0x8000_0000,
        "AEAD_DECRYPT_FAILED below vendor range",
    );
    kani::assert(CkRv::FUNCTION_CANCELED.0 < 0x8000_0000, "FUNCTION_CANCELED below vendor range");
    kani::assert(
        CkRv::FUNCTION_NOT_PARALLEL.0 < 0x8000_0000,
        "FUNCTION_NOT_PARALLEL below vendor range",
    );
    kani::assert(
        CkRv::FUNCTION_NOT_SUPPORTED.0 < 0x8000_0000,
        "FUNCTION_NOT_SUPPORTED below vendor range",
    );
    kani::assert(CkRv::KEY_HANDLE_INVALID.0 < 0x8000_0000, "KEY_HANDLE_INVALID below vendor range");
    kani::assert(CkRv::KEY_SIZE_RANGE.0 < 0x8000_0000, "KEY_SIZE_RANGE below vendor range");
    kani::assert(
        CkRv::KEY_TYPE_INCONSISTENT.0 < 0x8000_0000,
        "KEY_TYPE_INCONSISTENT below vendor range",
    );
    kani::assert(CkRv::KEY_NOT_NEEDED.0 < 0x8000_0000, "KEY_NOT_NEEDED below vendor range");
    kani::assert(CkRv::KEY_CHANGED.0 < 0x8000_0000, "KEY_CHANGED below vendor range");
    kani::assert(CkRv::KEY_NEEDED.0 < 0x8000_0000, "KEY_NEEDED below vendor range");
    kani::assert(CkRv::KEY_INDIGESTIBLE.0 < 0x8000_0000, "KEY_INDIGESTIBLE below vendor range");
    kani::assert(
        CkRv::KEY_FUNCTION_NOT_PERMITTED.0 < 0x8000_0000,
        "KEY_FUNCTION_NOT_PERMITTED below vendor range",
    );
    kani::assert(CkRv::KEY_NOT_WRAPPABLE.0 < 0x8000_0000, "KEY_NOT_WRAPPABLE below vendor range");
    kani::assert(CkRv::KEY_UNEXTRACTABLE.0 < 0x8000_0000, "KEY_UNEXTRACTABLE below vendor range");
    kani::assert(CkRv::MECHANISM_INVALID.0 < 0x8000_0000, "MECHANISM_INVALID below vendor range");
    kani::assert(
        CkRv::MECHANISM_PARAM_INVALID.0 < 0x8000_0000,
        "MECHANISM_PARAM_INVALID below vendor range",
    );
    kani::assert(
        CkRv::OBJECT_HANDLE_INVALID.0 < 0x8000_0000,
        "OBJECT_HANDLE_INVALID below vendor range",
    );
    kani::assert(CkRv::OPERATION_ACTIVE.0 < 0x8000_0000, "OPERATION_ACTIVE below vendor range");
    kani::assert(
        CkRv::OPERATION_NOT_INITIALIZED.0 < 0x8000_0000,
        "OPERATION_NOT_INITIALIZED below vendor range",
    );
    kani::assert(CkRv::PIN_INCORRECT.0 < 0x8000_0000, "PIN_INCORRECT below vendor range");
    kani::assert(CkRv::PIN_INVALID.0 < 0x8000_0000, "PIN_INVALID below vendor range");
    kani::assert(CkRv::PIN_LEN_RANGE.0 < 0x8000_0000, "PIN_LEN_RANGE below vendor range");
    kani::assert(CkRv::PIN_EXPIRED.0 < 0x8000_0000, "PIN_EXPIRED below vendor range");
    kani::assert(CkRv::PIN_LOCKED.0 < 0x8000_0000, "PIN_LOCKED below vendor range");
    kani::assert(CkRv::SESSION_CLOSED.0 < 0x8000_0000, "SESSION_CLOSED below vendor range");
    kani::assert(CkRv::SESSION_COUNT.0 < 0x8000_0000, "SESSION_COUNT below vendor range");
    kani::assert(
        CkRv::SESSION_HANDLE_INVALID.0 < 0x8000_0000,
        "SESSION_HANDLE_INVALID below vendor range",
    );
    kani::assert(
        CkRv::SESSION_PARALLEL_NOT_SUPPORTED.0 < 0x8000_0000,
        "SESSION_PARALLEL_NOT_SUPPORTED below vendor range",
    );
    kani::assert(CkRv::SESSION_READ_ONLY.0 < 0x8000_0000, "SESSION_READ_ONLY below vendor range");
    kani::assert(CkRv::SESSION_EXISTS.0 < 0x8000_0000, "SESSION_EXISTS below vendor range");
    kani::assert(
        CkRv::SESSION_READ_ONLY_EXISTS.0 < 0x8000_0000,
        "SESSION_READ_ONLY_EXISTS below vendor range",
    );
    kani::assert(
        CkRv::SESSION_READ_WRITE_SO_EXISTS.0 < 0x8000_0000,
        "SESSION_READ_WRITE_SO_EXISTS below vendor range",
    );
    kani::assert(CkRv::SIGNATURE_INVALID.0 < 0x8000_0000, "SIGNATURE_INVALID below vendor range");
    kani::assert(
        CkRv::SIGNATURE_LEN_RANGE.0 < 0x8000_0000,
        "SIGNATURE_LEN_RANGE below vendor range",
    );
    kani::assert(
        CkRv::TEMPLATE_INCOMPLETE.0 < 0x8000_0000,
        "TEMPLATE_INCOMPLETE below vendor range",
    );
    kani::assert(
        CkRv::TEMPLATE_INCONSISTENT.0 < 0x8000_0000,
        "TEMPLATE_INCONSISTENT below vendor range",
    );
    kani::assert(CkRv::TOKEN_NOT_PRESENT.0 < 0x8000_0000, "TOKEN_NOT_PRESENT below vendor range");
    kani::assert(
        CkRv::TOKEN_NOT_RECOGNIZED.0 < 0x8000_0000,
        "TOKEN_NOT_RECOGNIZED below vendor range",
    );
    kani::assert(
        CkRv::TOKEN_WRITE_PROTECTED.0 < 0x8000_0000,
        "TOKEN_WRITE_PROTECTED below vendor range",
    );
    kani::assert(
        CkRv::UNWRAPPING_KEY_HANDLE_INVALID.0 < 0x8000_0000,
        "UNWRAPPING_KEY_HANDLE_INVALID below vendor range",
    );
    kani::assert(
        CkRv::UNWRAPPING_KEY_SIZE_RANGE.0 < 0x8000_0000,
        "UNWRAPPING_KEY_SIZE_RANGE below vendor range",
    );
    kani::assert(
        CkRv::UNWRAPPING_KEY_TYPE_INCONSISTENT.0 < 0x8000_0000,
        "UNWRAPPING_KEY_TYPE_INCONSISTENT below vendor range",
    );
    kani::assert(
        CkRv::USER_ALREADY_LOGGED_IN.0 < 0x8000_0000,
        "USER_ALREADY_LOGGED_IN below vendor range",
    );
    kani::assert(CkRv::USER_NOT_LOGGED_IN.0 < 0x8000_0000, "USER_NOT_LOGGED_IN below vendor range");
    kani::assert(
        CkRv::USER_PIN_NOT_INITIALIZED.0 < 0x8000_0000,
        "USER_PIN_NOT_INITIALIZED below vendor range",
    );
    kani::assert(CkRv::USER_TYPE_INVALID.0 < 0x8000_0000, "USER_TYPE_INVALID below vendor range");
    kani::assert(
        CkRv::USER_ANOTHER_ALREADY_LOGGED_IN.0 < 0x8000_0000,
        "USER_ANOTHER_ALREADY_LOGGED_IN below vendor range",
    );
    kani::assert(
        CkRv::USER_TOO_MANY_TYPES.0 < 0x8000_0000,
        "USER_TOO_MANY_TYPES below vendor range",
    );
    kani::assert(
        CkRv::WRAPPED_KEY_INVALID.0 < 0x8000_0000,
        "WRAPPED_KEY_INVALID below vendor range",
    );
    kani::assert(
        CkRv::WRAPPED_KEY_LEN_RANGE.0 < 0x8000_0000,
        "WRAPPED_KEY_LEN_RANGE below vendor range",
    );
    kani::assert(
        CkRv::WRAPPING_KEY_HANDLE_INVALID.0 < 0x8000_0000,
        "WRAPPING_KEY_HANDLE_INVALID below vendor range",
    );
    kani::assert(
        CkRv::WRAPPING_KEY_SIZE_RANGE.0 < 0x8000_0000,
        "WRAPPING_KEY_SIZE_RANGE below vendor range",
    );
    kani::assert(
        CkRv::WRAPPING_KEY_TYPE_INCONSISTENT.0 < 0x8000_0000,
        "WRAPPING_KEY_TYPE_INCONSISTENT below vendor range",
    );
    kani::assert(
        CkRv::RANDOM_SEED_NOT_SUPPORTED.0 < 0x8000_0000,
        "RANDOM_SEED_NOT_SUPPORTED below vendor range",
    );
    kani::assert(CkRv::RANDOM_NO_RNG.0 < 0x8000_0000, "RANDOM_NO_RNG below vendor range");
    kani::assert(
        CkRv::DOMAIN_PARAMS_INVALID.0 < 0x8000_0000,
        "DOMAIN_PARAMS_INVALID below vendor range",
    );
    kani::assert(
        CkRv::CURVE_NOT_SUPPORTED.0 < 0x8000_0000,
        "CURVE_NOT_SUPPORTED below vendor range",
    );
    kani::assert(CkRv::BUFFER_TOO_SMALL.0 < 0x8000_0000, "BUFFER_TOO_SMALL below vendor range");
    kani::assert(
        CkRv::SAVED_STATE_INVALID.0 < 0x8000_0000,
        "SAVED_STATE_INVALID below vendor range",
    );
    kani::assert(
        CkRv::INFORMATION_SENSITIVE.0 < 0x8000_0000,
        "INFORMATION_SENSITIVE below vendor range",
    );
    kani::assert(CkRv::STATE_UNSAVEABLE.0 < 0x8000_0000, "STATE_UNSAVEABLE below vendor range");
    kani::assert(
        CkRv::CRYPTOKI_NOT_INITIALIZED.0 < 0x8000_0000,
        "CRYPTOKI_NOT_INITIALIZED below vendor range",
    );
    kani::assert(
        CkRv::CRYPTOKI_ALREADY_INITIALIZED.0 < 0x8000_0000,
        "CRYPTOKI_ALREADY_INITIALIZED below vendor range",
    );
    kani::assert(CkRv::MUTEX_BAD.0 < 0x8000_0000, "MUTEX_BAD below vendor range");
    kani::assert(CkRv::MUTEX_NOT_LOCKED.0 < 0x8000_0000, "MUTEX_NOT_LOCKED below vendor range");
    kani::assert(CkRv::NEW_PIN_MODE.0 < 0x8000_0000, "NEW_PIN_MODE below vendor range");
    kani::assert(CkRv::NEXT_OTP.0 < 0x8000_0000, "NEXT_OTP below vendor range");
    kani::assert(
        CkRv::EXCEEDED_MAX_ITERATIONS.0 < 0x8000_0000,
        "EXCEEDED_MAX_ITERATIONS below vendor range",
    );
    kani::assert(
        CkRv::FIPS_SELF_TEST_FAILED.0 < 0x8000_0000,
        "FIPS_SELF_TEST_FAILED below vendor range",
    );
    kani::assert(
        CkRv::LIBRARY_LOAD_FAILED.0 < 0x8000_0000,
        "LIBRARY_LOAD_FAILED below vendor range",
    );
    kani::assert(CkRv::PIN_TOO_WEAK.0 < 0x8000_0000, "PIN_TOO_WEAK below vendor range");
    kani::assert(CkRv::PUBLIC_KEY_INVALID.0 < 0x8000_0000, "PUBLIC_KEY_INVALID below vendor range");
    kani::assert(CkRv::FUNCTION_REJECTED.0 < 0x8000_0000, "FUNCTION_REJECTED below vendor range");
    kani::assert(
        CkRv::TOKEN_RESOURCE_EXCEEDED.0 < 0x8000_0000,
        "TOKEN_RESOURCE_EXCEEDED below vendor range",
    );
    kani::assert(
        CkRv::OPERATION_CANCEL_FAILED.0 < 0x8000_0000,
        "OPERATION_CANCEL_FAILED below vendor range",
    );
    kani::assert(CkRv::KEY_EXHAUSTED.0 < 0x8000_0000, "KEY_EXHAUSTED below vendor range");
    kani::assert(CkRv::PENDING.0 < 0x8000_0000, "PENDING below vendor range");
    kani::assert(
        CkRv::SESSION_ASYNC_NOT_SUPPORTED.0 < 0x8000_0000,
        "SESSION_ASYNC_NOT_SUPPORTED below vendor range",
    );
    kani::assert(
        CkRv::SEED_RANDOM_REQUIRED.0 < 0x8000_0000,
        "SEED_RANDOM_REQUIRED below vendor range",
    );
    kani::assert(
        CkRv::OPERATION_NOT_VALIDATED.0 < 0x8000_0000,
        "OPERATION_NOT_VALIDATED below vendor range",
    );
    kani::assert(
        CkRv::TOKEN_NOT_INITIALIZED.0 < 0x8000_0000,
        "TOKEN_NOT_INITIALIZED below vendor range",
    );
    kani::assert(
        CkRv::PARAMETER_SET_NOT_SUPPORTED.0 < 0x8000_0000,
        "PARAMETER_SET_NOT_SUPPORTED below vendor range",
    );
}

/// NULL inputs reconstruct (NULL, claimed_len) verbatim (ADR-0010).
#[kani::proof]
fn inbuf_null_law() {
    let len: u64 = kani::any();
    let (p, l) = CkInBuf::Null { len }.as_ptr_len();
    kani::assert(p.is_null(), "null stays null");
    kani::assert(l == len, "claimed len verbatim");
}

/// Byte inputs give a non-null pointer with exact length, including empty.
#[kani::proof]
fn inbuf_bytes_len_exact() {
    let data: [u8; 8] = kani::any();
    let (p, l) = CkInBuf::Bytes(&data).as_ptr_len();
    kani::assert(!p.is_null(), "bytes ptr non-null");
    kani::assert(l == 8, "len exact");
    let (pe, le) = CkInBuf::Bytes(&[]).as_ptr_len();
    kani::assert(!pe.is_null(), "empty ptr non-null dangling");
    kani::assert(le == 0, "empty len zero");
}

/// Every official PKCS#11 3.2 mechanism sits below the vendor range.
/// A symbolic index covers the whole table, not examples — after an
/// explicit nonempty assert so an empty table cannot make the proof
/// vacuous (`any_where` over an empty range constrains nothing).
#[kani::proof]
fn official_mechanisms_below_vendor_range() {
    let list = pkcs11_3_2_official_mechanisms();
    kani::assert(!list.is_empty(), "table nonempty: symbolic index is non-vacuous");
    let i = kani::any_where(|idx: &usize| *idx < list.len());
    kani::assert(list[i].0 < 0x8000_0000, "official entry non-vendor");
}
