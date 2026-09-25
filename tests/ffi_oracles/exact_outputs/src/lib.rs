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
    if !length.is_null() && scenario.length_action == 1 {
        unsafe { length.write(scenario.returned_length as CK_ULONG) };
        observation.length_stores += 1;
    }
    if !output.is_null() && capacity >= 4 && scenario.output_action == 1 {
        unsafe { std::ptr::copy_nonoverlapping([0x10, 0x20, 0x30, 0x40].as_ptr(), output, 4) };
        observation.output_stores += 1;
    }
    scenario.rv as CK_RV
}
