//! Benign native output oracle. Sideband observations are test truth only.
#![allow(non_snake_case, clippy::missing_safety_doc, clippy::unnecessary_cast)]
use cryptoki_sys::*;
use std::sync::Mutex;
#[cfg(not(test))]
mod provider;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExactOracleScenario {
    pub rv: u64,
    pub length_action: u32,
    pub returned_length: u64,
    pub parameter_action: u32,
    pub output_action: u32,
    pub handle_action: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExactOracleObservation {
    pub calls: u64,
    pub output_present: u32,
    pub length_present: u32,
    pub capacity_read: u32,
    pub incoming_capacity: u64,
    pub length_stores: u64,
    pub parameter_stores: u64,
    pub output_stores: u64,
    pub handle_stores: u64,
    pub begin_parameter_present: u32,
    pub begin_parameter_length: u64,
    /// Zero-length writes performed (`output_action == 2`): distinguished
    /// from "no write attempted" (`output_action == 0`).
    pub zero_writes: u64,
    /// Oversized write attempts (`output_action == 3`): the oracle tried
    /// `capacity + 8` bytes but wrote only within capacity.
    pub overrun_attempts: u64,
}
static STATE: Mutex<(ExactOracleScenario, ExactOracleObservation)> = Mutex::new((
    ExactOracleScenario {
        rv: 0,
        length_action: 0,
        returned_length: 0,
        parameter_action: 0,
        output_action: 0,
        handle_action: 0,
    },
    ExactOracleObservation {
        calls: 0,
        output_present: 0,
        length_present: 0,
        capacity_read: 0,
        incoming_capacity: 0,
        length_stores: 0,
        parameter_stores: 0,
        output_stores: 0,
        handle_stores: 0,
        begin_parameter_present: 0,
        begin_parameter_length: 0,
        zero_writes: 0,
        overrun_attempts: 0,
    },
));

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ExactOracle_SetScenario(scenario: *const ExactOracleScenario) -> u32 {
    if scenario.is_null() {
        return 1;
    }
    STATE.lock().unwrap().0 = unsafe { *scenario };
    0
}
#[unsafe(no_mangle)]
pub extern "C" fn ExactOracle_ResetObservation() -> u32 {
    STATE.lock().unwrap().1 = ExactOracleObservation::default();
    0
}
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ExactOracle_GetObservation(
    observation: *mut ExactOracleObservation,
) -> u32 {
    if observation.is_null() {
        return 1;
    }
    unsafe { observation.write(STATE.lock().unwrap().1) };
    0
}

/// Never reads the incoming output-only query cell or writes past a capacity.
///
/// Byte-leaf action semantics (W1-L10-18):
/// * `length_action`: 0 = no store; 1 = store `returned_length`; 2 = hostile:
///   store `CK_UNAVAILABLE_INFORMATION`, ignoring `returned_length`.
/// * `output_action`: 0 = none; 1 = 4-byte canary when capacity >= 4;
///   2 = zero-length write (nothing stored, `zero_writes` recorded);
///   3 = oversized attempt (`capacity + 8` tried): bounded `0x5A` write of
///   `capacity` bytes plus `overrun_attempts` recorded; 4 = hostile
///   full-capacity `0xA5` fill.
///
/// A true out-of-bounds write cannot be modeled (it would be UB in a real
/// provider too); hostile/oversized ATTEMPTS are bounded writes plus recorded
/// observations. `parameter_action`/`handle_action` are honored by the
/// message/attribute/encapsulate entries in `provider.rs`, not this leaf.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ExactOracle_ByteOutput(
    output: CK_BYTE_PTR,
    length: CK_ULONG_PTR,
) -> CK_RV {
    let mut state = STATE.lock().unwrap();
    let scenario = state.0;
    let observation = &mut state.1;
    observation.calls += 1;
    observation.output_present = u32::from(!output.is_null());
    observation.length_present = u32::from(!length.is_null());
    let capacity = if !output.is_null() && !length.is_null() {
        observation.capacity_read += 1;
        let capacity = unsafe { length.read() };
        observation.incoming_capacity = capacity as u64;
        capacity
    } else {
        0
    };
    if !length.is_null() {
        match scenario.length_action {
            1 => {
                unsafe { length.write(scenario.returned_length as CK_ULONG) };
                observation.length_stores += 1;
            }
            2 => {
                unsafe { length.write(CK_UNAVAILABLE_INFORMATION) };
                observation.length_stores += 1;
            }
            _ => {}
        }
    }
    if !output.is_null() {
        match scenario.output_action {
            1 if capacity >= 4 => {
                unsafe {
                    std::ptr::copy_nonoverlapping([0x10, 0x20, 0x30, 0x40].as_ptr(), output, 4)
                };
                observation.output_stores += 1;
            }
            2 => {
                observation.zero_writes += 1;
            }
            3 => {
                observation.overrun_attempts += 1;
                if !length.is_null() && capacity > 0 {
                    unsafe { std::ptr::write_bytes(output, 0x5A, capacity as usize) };
                    observation.output_stores += 1;
                }
            }
            4 if !length.is_null() && capacity > 0 => {
                unsafe { std::ptr::write_bytes(output, 0xA5, capacity as usize) };
                observation.output_stores += 1;
            }
            _ => {}
        }
    }
    scenario.rv as CK_RV
}
