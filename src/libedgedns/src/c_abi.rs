
use hooks::SessionState;
use libc::{c_char, c_int, c_void, size_t};
use std::cell::RefCell;
use std::ffi::{CStr, CString};

const ABI_VERSION: u64 = 0x1;

#[repr(C)]
pub struct CErr {
    description_cs: CString,
}

thread_local!(
    static CERR: RefCell<CErr> = RefCell::new(CErr {
        description_cs: CString::new("".as_bytes()).unwrap()
    })
);

unsafe extern "C" fn error_description(c_err: *const CErr) -> *const c_char {
    (*c_err).description_cs.as_bytes() as *const _ as *const c_char
}

unsafe extern "C" fn env_insert_str(
    c_err: *const CErr,
    session_state: &mut SessionState,
    key: *const c_char,
    val: *const c_char,
) -> c_int {
    let key = CStr::from_ptr(key).to_bytes().to_owned();
    let val = CStr::from_ptr(val).to_bytes().to_owned();
    let env_str = &mut session_state.inner.write().env_str;
    env_str.insert(key, val);
    0
}

unsafe extern "C" fn env_insert_i64(
    c_err: *const CErr,
    session_state: &mut SessionState,
    key: *const c_char,
    val: i64,
) -> c_int {
    let key = CStr::from_ptr(key).to_bytes().to_owned();
    let env_i64 = &mut session_state.inner.write().env_i64;
    env_i64.insert(key, val);
    0
}

unsafe extern "C" fn env_get_str(
    c_err: *const CErr,
    session_state: &SessionState,
    key: *const c_char,
    val: *mut c_char,
    val_len: *mut size_t,
    val_max_len: size_t,
) -> c_int {
    let key = CStr::from_ptr(key).to_bytes();
    -1
}

unsafe extern "C" fn env_get_i64(
    c_err: *const CErr,
    session_state: &SessionState,
    key: *const c_char,
    val_p: *mut i64,
) -> c_int {
    let key = CStr::from_ptr(key).to_bytes();
    let env_i64 = &session_state.inner.read().env_i64;
    let val = match env_i64.get(key) {
        None => return -1,
        Some(val) => *val,
    };
    *val_p = val;
    0
}
