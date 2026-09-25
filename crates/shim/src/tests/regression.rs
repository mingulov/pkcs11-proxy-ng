//! Named regression tier: each test pins a specific past defect and cites
//! the commit that fixed it. Thin, direct pins — the full-stack coverage
//! for the same defects lives in its natural module and still runs in
//! every tier.
//!
//! Defects pinned end-to-end elsewhere (found by name filter in
//! `scripts/run-test-tiers.sh`):
//! - i686 bits-derived wild reads (cfd5d06): `*_not_wild_read` tests in
//!   `dispatch::general::helpers`.
//! - D4 wire/alias truncation (aacd3a1, b892820): `*_wider_than_native_*`
//!   tests in the backend's `ffi_conversion`.
//! - Cross-layout nested templates + D6 refusal (this series):
//!   `tests::cross_abi`.

use super::*;

/// d88f74a: parallel tests raced on the process-global endpoint and every
/// victim slept ~21 s of connect backoff — the whole suite degraded to
/// ~620 s per run and was misdiagnosed as an i686 hang. The env knob must
/// lower the retry cap but never raise it past the resilience contract.
#[test]
fn regression_connect_retry_cap_is_tunable_downward_only() {
    assert_eq!(crate::state::connect_attempts_from_value(None), 10);
    assert_eq!(crate::state::connect_attempts_from_value(Some("1")), 1);
    assert_eq!(crate::state::connect_attempts_from_value(Some("0")), 1);
    assert_eq!(crate::state::connect_attempts_from_value(Some("50")), 10);
    assert_eq!(crate::state::connect_attempts_from_value(Some("junk")), 10);
}

/// This series: the D6 resolver always refused a foreign-order backend, but
/// nothing ACTED on the refusal at C_Initialize (reprobe warned and
/// carried on). The resolver contract stays pinned here; the end-to-end
/// enforcement is `cross_abi::foreign_byte_order_backend_is_refused_at_initialize`.
#[test]
fn regression_byte_order_mismatch_is_resolver_refused() {
    // The foreign order for this host (BE on LE, LE on BE) is refused at
    // both widths; the native order passes through.
    let foreign = Some(if cfg!(target_endian = "little") { 2 } else { 1 });
    let native = Some(if cfg!(target_endian = "little") { 1 } else { 2 });
    assert!(crate::interface_probe::resolve_backend_ulong_size(Some(8), foreign).is_err());
    assert!(crate::interface_probe::resolve_backend_ulong_size(Some(4), foreign).is_err());
    assert_eq!(crate::interface_probe::resolve_backend_ulong_size(Some(4), native), Ok((4, false)));
}

/// This series: nested CKA_*_TEMPLATE byte lengths crossed the wire in
/// the wrong layout — the outer request length was client-layout and the
/// pure size query leaked the backend's byte length verbatim. Lengths
/// count whole CK_ATTRIBUTE structs and must rescale by stride
/// (24 LP64 / 12 ILP32 / 16 LLP64-packed — NOT always 3 x width).
#[test]
fn regression_nested_template_lengths_rescale_by_stride() {
    use dispatch::general::width_bridge::{
        bridge_template_output_len, bridge_template_request_len,
    };
    // A wide client's 2-entry template must not look "too small" narrow.
    assert_eq!(bridge_template_request_len(48, 24, 12), 24);
    // An LLP64 backend's 2-entry size query must not surface as 32 bytes
    // on an LP64 client.
    assert_eq!(bridge_template_output_len(32, 16, 24), 48);
    // The LLP64 stride is not derivable from the ulong width.
    assert_ne!(16, 3 * 4_usize);
}

/// cfd5d06: the salsa20/chacha/gcm bits-derived length guards were dead on
/// 32-bit hosts because ceil(u32::MAX / 8) lands EXACTLY on the 512 MiB
/// serialization cap — a `>` comparison never fired and the shim read a
/// dangling pointer. Pin the boundary identity that made them dead: any
/// future cap change that re-aligns with a width boundary must be caught.
#[test]
fn regression_bits_guard_boundary_identity() {
    let max_narrow_bits_bytes = (u32::MAX as u64).div_ceil(8);
    assert_eq!(
        max_narrow_bits_bytes,
        dispatch::general::helpers::MAX_SERIALIZABLE_BYTES as u64,
        "ceil(u32::MAX/8) == MAX_SERIALIZABLE_BYTES: bits-derived guards \
         MUST use >= (reject at the boundary), see the *_not_wild_read tests"
    );
}

/// 329cdeb: MockBackend encoded ulong attribute values as 8 bytes
/// unconditionally, violating the wire contract (backend-native width) on
/// narrow hosts and masking bridge bugs. The emulated profile must drive
/// the encoding.
#[test]
fn regression_mock_ulong_encoding_follows_emulated_width() {
    use pkcs11_proxy_ng_backend::mock::MockAbi;
    assert_eq!(MockAbi::Ilp32.encode_ulong(3).len(), 4);
    assert_eq!(MockAbi::Lp64.encode_ulong(3).len(), 8);
    assert_eq!(
        MockAbi::host().encode_ulong(3).len(),
        std::mem::size_of::<CK_ULONG>(),
        "the default mock profile matches the host"
    );
}

/// This series: input-direction CKA_*_TEMPLATE attributes were serialized
/// as raw client CK_ATTRIBUTE struct bytes — client-address-space POINTERS
/// crossed the wire and a real backend would have dereferenced them in the
/// daemon's address space. Templates must parse structurally at the C ABI
/// edge; the full loop is pinned in
/// `cross_abi::nested_template_input_round_trips_across_abis`.
#[test]
fn regression_input_nested_template_is_structural_not_pointer_bytes() {
    let mut sub_class: CK_ULONG = 4;
    let mut subs = [CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: &mut sub_class as *mut CK_ULONG as CK_VOID_PTR,
        ulValueLen: std::mem::size_of::<CK_ULONG>() as CK_ULONG,
    }];
    let outer = [CK_ATTRIBUTE {
        type_: cryptoki_sys::CKA_WRAP_TEMPLATE,
        pValue: subs.as_mut_ptr() as CK_VOID_PTR,
        ulValueLen: std::mem::size_of_val(&subs) as CK_ULONG,
    }];
    let parsed = unsafe { dispatch::general::helpers::ck_attrs_to_rust_checked(outer.as_ptr(), 1) }
        .expect("parses");
    assert!(
        matches!(parsed[0].value, Some(pkcs11_proxy_ng_types::CkAttributeValue::NestedTemplate(_))),
        "template input must never serialize as raw (pointer-carrying) bytes: {:?}",
        parsed[0].value
    );
}
