use super::*;
use std::sync::{Mutex, MutexGuard};

static SHIM_STATE_TEST_GUARD: Mutex<()> = Mutex::new(());

fn shim_state_test_guard() -> MutexGuard<'static, ()> {
    SHIM_STATE_TEST_GUARD.lock().unwrap_or_else(|e| e.into_inner())
}

mod abi_audit;
mod init_args;
mod interface;
mod null_pointers;
mod output_semantics;
mod resource_limits;

fn empty_interface() -> CK_INTERFACE {
    CK_INTERFACE {
        pInterfaceName: std::ptr::null_mut(),
        pFunctionList: std::ptr::null_mut(),
        flags: 0,
    }
}
