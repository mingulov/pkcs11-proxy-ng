//! Check ownership before dereferencing any native X3DH pointee. This makes
//! the regression tests safe even against the original dangling-pointer bug.

use super::*;
use cryptoki_sys::{CK_MECHANISM, CK_RV, CK_ULONG, CK_X3DH_RESPOND_PARAMS};

const VALUES: [u64; 6] = [0x11, 0x2233, 0x445566, 0x778899aa, 0x33445566, 0x11223344];

fn input(values: [u64; 6]) -> CkMechanism {
    CkMechanism {
        mechanism_type: CkMechanismType::X3DH_RESPOND,
        params: Some(CkMechanismParams::X3dhRespond(X3dhRespondParams {
            kdf: values[0],
            identity_handle: CkObjectHandle(values[1]),
            prekey_handle: CkObjectHandle(values[2]),
            onetime_key_handle: CkObjectHandle(values[3]),
            initiator_identity_handle: CkObjectHandle(values[4]),
            initiator_ephemeral_handle: CkObjectHandle(values[5]),
        })),
    }
}

/// The only representation-dependent observer: enumerate storage actually
/// retained by the owner, not storage inferred from native raw pointers.
/// The native record is returned as an owned snapshot plus the live root
/// address: no live reference into retained storage may cross the owner
/// moves this suite performs.
fn retained_regions(
    ffi: &FfiMechanism,
) -> (CK_X3DH_RESPOND_PARAMS, *mut CK_X3DH_RESPOND_PARAMS, Vec<&[u8]>) {
    match &ffi._backing {
        FfiParamBacking::X3dhRespond(native, identity, prekey, onetime, ephemeral) => (
            // SAFETY: backing is borrowed alive; the copy carries no provenance.
            unsafe { native.snapshot() },
            native.root(),
            vec![identity.as_slice(), prekey.as_slice(), onetime.as_slice(), ephemeral.as_slice()],
        ),
        _ => panic!("expected X3DH response backing"),
    }
}

/// No pointee reads are permitted until this ownership proof succeeds. The
/// baseline may supply dangling raw pointer values; comparing their addresses
/// is safe, whereas reading from them (even in a test) would not be.
fn assert_live_backing(ffi: &FfiMechanism) {
    let (native, root, regions) = retained_regions(ffi);
    let parameter_pointer = ffi.ck_mechanism().pParameter;
    assert_eq!(parameter_pointer, root.cast(), "stored pointer names the live root");
    let parameter_len = ffi.ck_mechanism().ulParameterLen;
    assert_eq!(parameter_len as usize, std::mem::size_of::<CK_X3DH_RESPOND_PARAMS>());

    let pointers = [
        ("pIdentity_id", native.pIdentity_id),
        ("pPrekey_id", native.pPrekey_id),
        ("pOnetime_id", native.pOnetime_id),
        ("pInitiator_ephemeral", native.pInitiator_ephemeral),
    ];
    let width = std::mem::size_of::<CK_ULONG>();
    for (name, pointer) in pointers {
        let pointer_start = pointer.addr();
        let pointer_end = pointer_start.checked_add(width).expect("pointee address range");
        assert!(
            regions.iter().any(|region| {
                let start = region.as_ptr().addr();
                let end = start.checked_add(region.len()).expect("owned address range");
                pointer_start >= start && pointer_end <= end
            }),
            "{name} must point to a full native-width value in still-owned backing"
        );
    }
    assert_eq!(regions.len(), 4, "each pointer has its own final-size backing buffer");
    for (region, (_, pointer)) in regions.iter().zip(pointers) {
        assert_eq!(region.len(), width, "one native-width value per buffer");
        assert_eq!(region.as_ptr(), pointer.cast_const(), "pointer names its own buffer");
    }
}

#[derive(Default)]
#[repr(C)]
struct Observation {
    calls: u32,
    mechanism: CK_ULONG,
    parameter_len: CK_ULONG,
    values: [CK_ULONG; 6],
}

/// A local native ABI oracle, not a provider or a second conversion routine.
///
/// # Safety
/// `mechanism` and all four pointees must remain live for the call, as checked
/// by `assert_live_backing`; `observation` must be exclusively writable.
unsafe extern "C" fn native_oracle(
    mechanism: *const CK_MECHANISM,
    observation: *mut Observation,
) -> CK_RV {
    // SAFETY: the caller proves ownership immediately before the call and
    // retains the owner throughout. Byte buffers need not be CK_ULONG-aligned,
    // so use unaligned native-width reads, never typed references into them.
    unsafe {
        let mechanism = mechanism.read_unaligned();
        let native = mechanism.pParameter.cast::<CK_X3DH_RESPOND_PARAMS>().read_unaligned();
        (*observation).calls = (*observation).calls.saturating_add(1);
        (*observation).mechanism = mechanism.mechanism;
        (*observation).parameter_len = mechanism.ulParameterLen;
        (*observation).values = [
            native.kdf,
            native.pIdentity_id.cast::<CK_ULONG>().read_unaligned(),
            native.pPrekey_id.cast::<CK_ULONG>().read_unaligned(),
            native.pOnetime_id.cast::<CK_ULONG>().read_unaligned(),
            native.pInitiator_identity,
            native.pInitiator_ephemeral.cast::<CK_ULONG>().read_unaligned(),
        ];
    }
    cryptoki_sys::CKR_DEVICE_ERROR
}

fn assert_native_readback(ffi: &FfiMechanism, expected: [u64; 6]) {
    assert_live_backing(ffi);
    let mut observation = Observation::default();
    // SAFETY: assert_live_backing validated all pointer ranges in this owner;
    // the shared borrow keeps that owner alive and unchanged across the call.
    let rv = unsafe { native_oracle(&ffi.ck_mechanism(), &mut observation) };
    assert_eq!(rv, cryptoki_sys::CKR_DEVICE_ERROR, "native return value is preserved");
    assert_eq!(observation.calls, 1, "exactly one native oracle call");
    assert_eq!(observation.mechanism, cryptoki_sys::CKM_X3DH_RESPOND);
    assert_eq!(observation.parameter_len as usize, std::mem::size_of::<CK_X3DH_RESPOND_PARAMS>());
    assert_eq!(observation.values.map(|value| value as u64), expected);
    assert_live_backing(ffi);
}

#[test]
fn x3dh_respond_native_pointers_belong_to_live_backing() {
    let ffi = mechanism_to_ffi(&input(VALUES)).expect("X3DH response converts");
    assert_live_backing(&ffi);
}

#[test]
fn x3dh_respond_four_pointees_keep_native_width_after_owner_move() {
    let values = if std::mem::size_of::<CK_ULONG>() == 8 {
        [
            0x12345678_00000011,
            0x22334455_00002233,
            0x33445566_00445566,
            0x44556677_778899aa,
            0x55667788_33445566,
            0x66778899_11223344,
        ]
    } else {
        VALUES
    };
    let ffi = mechanism_to_ffi(&input(values)).expect("native-width values convert");
    assert_live_backing(&ffi);
    let parameter_pointer = ffi.ck_mechanism().pParameter;
    let boxed_owner = Box::new(ffi);
    let mut owners = Vec::with_capacity(1);
    owners.push(*boxed_owner);
    owners.reserve(8);
    let moved_owner = owners.pop().expect("moved owner remains present");
    // E0793: CK_MECHANISM is packed on Windows; assert on a by-value copy.
    let moved_p_parameter = moved_owner.ck_mechanism().pParameter;
    assert_eq!(moved_p_parameter, parameter_pointer);
    assert_native_readback(&moved_owner, values);
}

#[test]
fn x3dh_respond_oracle_reads_all_four_owned_pointees_once() {
    let ffi = mechanism_to_ffi(&input(VALUES)).expect("X3DH response converts");
    assert_native_readback(&ffi, VALUES);
}

#[test]
fn x3dh_respond_narrow_handles_and_kdf_reject_before_native_call() {
    let names = ["kdf", "identity", "prekey", "onetime", "initiator_identity", "ephemeral"];
    for (index, name) in names.into_iter().enumerate() {
        for wide in [0x1_23456789, u64::MAX] {
            let mut values = VALUES;
            values[index] = wide;
            let result = mechanism_to_ffi(&input(values));
            if std::mem::size_of::<CK_ULONG>() == 4 {
                assert_eq!(result.err(), Some(CkRv::FUNCTION_FAILED), "{name}: {wide:#x}");
            } else {
                let ffi = result.expect("LP64 retains wide values without truncation");
                assert_native_readback(&ffi, values);
            }
        }
    }
}
