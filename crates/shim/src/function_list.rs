use std::sync::LazyLock;

use cryptoki_sys::*;

use crate::function_registry::build_function_list;

static FUNC_LIST: LazyLock<CK_FUNCTION_LIST> = LazyLock::new(build_function_list);

pub fn get_function_list() -> *mut CK_FUNCTION_LIST {
    &*FUNC_LIST as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST
}

fn build_function_list() -> CK_FUNCTION_LIST {
    build_function_list!(CK_FUNCTION_LIST, CK_VERSION { major: 2, minor: 40 })
}
