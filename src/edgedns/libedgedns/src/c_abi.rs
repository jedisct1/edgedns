use hooks::SessionState;
use libc::{c_char, c_int, c_void, size_t};
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::slice;

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

unsafe extern "C" fn set_service_id(
    session_state: &mut SessionState,
    c_err: *const CErr,
    service_id: *const c_char,
    service_id_len: size_t,
) -> c_int {
    let service_id = slice::from_raw_parts(service_id as *const u8, service_id_len).to_owned();
    let service_id_p = &mut session_state.inner.write().service_id;
    if service_id_p.is_some() {
        return -1;
    }
    *service_id_p = Some(service_id);
    0
}

unsafe extern "C" fn env_insert_str(
    session_state: &mut SessionState,
    c_err: *const CErr,
    key: *const c_char,
    key_len: size_t,
    val: *const c_char,
    val_len: size_t,
) -> c_int {
    let key = slice::from_raw_parts(key as *const u8, key_len).to_owned();
    let val = slice::from_raw_parts(val as *const u8, val_len).to_owned();
    let env_str = &mut session_state.inner.write().env_str;
    env_str.insert(key, val);
    0
}

unsafe extern "C" fn env_insert_i64(
    session_state: &mut SessionState,
    c_err: *const CErr,
    key: *const c_char,
    key_len: size_t,
    val: i64,
) -> c_int {
    let key = slice::from_raw_parts(key as *const u8, key_len).to_owned();
    let env_i64 = &mut session_state.inner.write().env_i64;
    env_i64.insert(key, val);
    0
}

unsafe extern "C" fn env_get_str(
    session_state: &SessionState,
    c_err: *const CErr,
    key: *const c_char,
    key_len: size_t,
    val_: *mut c_char,
    val_len_p: *mut size_t,
    val_max_len: size_t,
) -> c_int {
    let key = slice::from_raw_parts(key as *const u8, key_len);
    let env_str = &session_state.inner.read().env_str;
    let val = match env_str.get(key) {
        None => return -1,
        Some(val) => val,
    };
    let val_len = val.len();
    if val.len() >= val_max_len {
        *val_len_p = 0;
        return -1;
    }
    let val_ = slice::from_raw_parts_mut(val_ as *mut u8, val_len);
    val_[..val_len].copy_from_slice(&val[..]);
    val_[val_len] = 0;
    *val_len_p = val_len;
    -1
}

unsafe extern "C" fn env_get_i64(
    session_state: &SessionState,
    c_err: *const CErr,
    key: *const c_char,
    key_len: size_t,
    val_p: *mut i64,
) -> c_int {
    let key = slice::from_raw_parts(key as *const u8, key_len);
    let env_i64 = &session_state.inner.read().env_i64;
    let val = match env_i64.get(key) {
        None => return -1,
        Some(val) => *val,
    };
    *val_p = val;
    0
}

/// C wrappers to the internal API
#[repr(C)]
pub struct FnTable {
    pub error_description: unsafe extern "C" fn(c_err: *const CErr) -> *const c_char,
    pub set_service_id: unsafe extern "C" fn(
        session_state: &mut SessionState,
        c_err: *const CErr,
        service_id: *const c_char,
        service_id_len: size_t,
    ) -> c_int,
    pub env_insert_str: unsafe extern "C" fn(
        session_state: &mut SessionState,
        c_err: *const CErr,
        key: *const c_char,
        key_len: size_t,
        val: *const c_char,
        val_len: size_t,
    ) -> c_int,
    pub env_insert_i64: unsafe extern "C" fn(
        session_state: &mut SessionState,
        c_err: *const CErr,
        key: *const c_char,
        key_len: size_t,
        val: i64,
    ) -> c_int,
    pub env_get_str: unsafe extern "C" fn(
        session_state: &SessionState,
        c_err: *const CErr,
        key: *const c_char,
        key_len: size_t,
        val_: *mut c_char,
        val_len_p: *mut size_t,
        val_max_len: size_t,
    ) -> c_int,
    pub env_get_i64: unsafe extern "C" fn(
        session_state: &SessionState,
        c_err: *const CErr,
        key: *const c_char,
        key_len: size_t,
        val_p: *mut i64,
    ) -> c_int,
    abi_version: u64,
}

pub fn fn_table() -> FnTable {
    FnTable {
        error_description,
        set_service_id,
        env_insert_str,
        env_insert_i64,
        env_get_str,
        env_get_i64,
        abi_version: ABI_VERSION,
    }
}
