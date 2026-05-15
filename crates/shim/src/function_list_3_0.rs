use std::sync::OnceLock;

use cryptoki_sys::*;

use crate::function_registry::build_function_list_3_x;

static FUNC_LIST_3_0: OnceLock<CK_FUNCTION_LIST_3_0> = OnceLock::new();

pub fn get_function_list_3_0() -> *mut CK_FUNCTION_LIST_3_0 {
    let fl = FUNC_LIST_3_0.get_or_init(build_function_list_3_0);
    fl as *const CK_FUNCTION_LIST_3_0 as *mut CK_FUNCTION_LIST_3_0
}

fn build_function_list_3_0() -> CK_FUNCTION_LIST_3_0 {
    // All 2.40 functions are wired to the same implementations as the 2.40
    // function list. New 3.0 functions are non-null stubs unless explicitly
    // implemented.
    build_function_list_3_x!(CK_FUNCTION_LIST_3_0, CK_VERSION { major: 3, minor: 0 })
}
