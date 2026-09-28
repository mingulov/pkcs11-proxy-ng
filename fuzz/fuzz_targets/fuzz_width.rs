#![no_main]

//! Fuzz the pure CK_ULONG width-translation seam (ADR-0011).
//!
//! Widths arrive from cross-ABI peers, so every `Result`-returning entry must
//! be total over all 256 width values (never panic, typed `WidthError` only).
//! `encode_native_ulong` is deliberately excluded: it asserts 4/8 by contract
//! (fixture-only helper, panics by design on other widths).

use libfuzzer_sys::fuzz_target;
use pkcs11_proxy_ng_types::width::{
    all_ones, canonicalize_ulong, checked_narrow_to_width, decanonicalize_ulong,
    narrow_info_field, narrow_u32_to_u8, reencode_ulong, translate_ulong_len, ByteOrder,
    CANONICAL_UNAVAILABLE,
};

fn order(byte: u8) -> ByteOrder {
    if byte & 1 == 0 { ByteOrder::Little } else { ByteOrder::Big }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let value = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let src_w = data[8] as usize;
    let dst_w = data[9] as usize;
    let mode = data[10];
    let ord = order(data[11]);
    let payload = &data[12..];

    // reencode_ulong: total over all widths; widening never overflows.
    match reencode_ulong(payload, src_w, dst_w, ord) {
        Ok(out) => {
            assert!(src_w == 4 || src_w == 8, "ok implies valid widths");
            assert!(dst_w == 4 || dst_w == 8, "ok implies valid widths");
            assert_eq!(out.len(), payload.len() / src_w * dst_w);
            if dst_w >= src_w {
                // Widening accepted: every element fit by construction.
                let _ = out;
            }
        }
        Err(_) => {
            // Only typed errors; any panic above is a bug.
        }
    }

    // canonicalize -> decanonicalize round trip on valid widths.
    if src_w == 4 || src_w == 8 {
        let canon = canonicalize_ulong(value, src_w);
        if dst_w == 4 || dst_w == 8 {
            let back = decanonicalize_ulong(canon, dst_w);
            // `u64::MAX` is the canonical sentinel itself: it passes
            // `canonicalize` through unchanged (for src_w=4 it is not the
            // source sentinel) and `decanonicalize` always maps it to the
            // destination ones. Real edges only feed in-src-range values,
            // so this aliasing is unreachable past the FFI edge.
            if value == all_ones(src_w) || value == CANONICAL_UNAVAILABLE {
                assert_eq!(back, Ok(all_ones(dst_w)), "sentinel must survive");
            } else if value <= all_ones(dst_w) {
                assert_eq!(back, Ok(value), "fitting value must round-trip");
            } else {
                assert!(back.is_err(), "non-fitting value must be refused");
            }
        }
        // Sentinel canonicalises regardless of source width validity edge.
        if value == all_ones(src_w) {
            assert_eq!(canon, CANONICAL_UNAVAILABLE);
        }
    }

    // narrow_info_field: infallible, bounded by destination ones.
    let narrowed = narrow_info_field(value, dst_w);
    assert!(narrowed <= all_ones(dst_w));
    // checked_narrow: Some exactly when the value fits.
    assert_eq!(
        checked_narrow_to_width(value, dst_w).is_some(),
        value <= all_ones(dst_w)
    );
    // u32->u8: total, errors only on overflow.
    let narrow8 = narrow_u32_to_u8(value as u32);
    assert_eq!(narrow8.is_ok(), value as u32 <= u8::MAX as u32);

    // translate_ulong_len: total; sentinel maps to destination ones.
    if let Ok(len) = translate_ulong_len(value, src_w, dst_w) {
        assert!(src_w == 4 || src_w == 8);
        assert!(dst_w == 4 || dst_w == 8);
        if value == CANONICAL_UNAVAILABLE {
            assert_eq!(len, all_ones(dst_w));
        }
    }

    // Mode bit: also exercise the big-endian order for symmetry.
    if mode & 0x80 != 0 {
        let flipped = if ord == ByteOrder::Little { ByteOrder::Big } else { ByteOrder::Little };
        let _ = reencode_ulong(payload, src_w, dst_w, flipped);
    }
});
