use std::slice;
use serde_json::Value;

#[no_mangle]
pub extern "C" fn alloc(size: usize) -> *mut u8 {
    let mut v = vec![0u8; size];
    let ptr = v.as_mut_ptr();
    std::mem::forget(v);
    ptr
}

#[no_mangle]
pub extern "C" fn dealloc(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 { return; }
    unsafe { let _ = Vec::from_raw_parts(ptr, size, size); }
}

#[no_mangle]
pub extern "C" fn eval_policy(input_ptr: *const u8, input_len: usize) -> i32 {
    let input_slice = unsafe { slice::from_raw_parts(input_ptr, input_len) };
    let input_val: Value = match serde_json::from_slice(input_slice) {
        Ok(v) => v,
        Err(_) => return 0, // invalid JSON -> deny
    };

    // === Example policy: allow if total_amount < 50 ===
    match input_val.get("total_amount") {
        Some(x) => if x.as_f64().unwrap_or(0.0) < 50.0 { 1 } else { 0 },
        None => 0
    }
}
