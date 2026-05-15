use std::sync::OnceLock;

use cryptoki_sys::*;

use crate::function_registry::build_function_list;

static FUNC_LIST: OnceLock<CK_FUNCTION_LIST> = OnceLock::new();

pub fn get_function_list() -> *mut CK_FUNCTION_LIST {
    let fl = FUNC_LIST.get_or_init(build_function_list);
    fl as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST
}

fn build_function_list() -> CK_FUNCTION_LIST {
    build_function_list!(CK_FUNCTION_LIST, CK_VERSION { major: 2, minor: 40 })
}
