//! Kani proofs for the width-translation laws (Step 7).
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
//! truncate" laws over all inputs (the unit + randomized law tests in
//! `width.rs` cover examples; these cover the whole input space).

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
