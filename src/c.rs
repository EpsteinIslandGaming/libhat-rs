use std::alloc::{alloc, dealloc, Layout};
use std::ffi::CStr;
use std::ptr;

use crate::signature::{self, SignatureElement};
use crate::scanner::{self, ScanAlignment, ScanHint};

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum LibhatStatus {
    Success = 0,
    ErrUnknown = 1,
    SigInvalid = 2,
    SigEmpty = 3,
    SigNoByte = 4,
}

#[repr(C)]
pub enum ScanAlignmentC {
    X1 = 0,
    X16 = 1,
}

#[repr(C)]
pub struct Signature {
    pub data: *mut SignatureElement,
    pub count: usize,
}

fn to_cpp_align(align: ScanAlignmentC) -> ScanAlignment {
    match align {
        ScanAlignmentC::X1 => ScanAlignment::X1,
        ScanAlignmentC::X16 => ScanAlignment::X16,
    }
}

fn to_cpp_signature_error(err: signature::SignatureError) -> LibhatStatus {
    match err {
        signature::SignatureError::MissingMaskedByte => LibhatStatus::SigNoByte,
        signature::SignatureError::EmptySignature => LibhatStatus::SigEmpty,
        _ => LibhatStatus::SigInvalid,
    }
}

unsafe fn allocate_signature(sig: &[SignatureElement]) -> *mut Signature {
    let layout = Layout::new::<Signature>();
    let mem = alloc(layout);
    if mem.is_null() {
        return ptr::null_mut();
    }
    let sig_ptr = mem as *mut Signature;
    (*sig_ptr).count = sig.len();
    if sig.is_empty() {
        (*sig_ptr).data = ptr::null_mut();
        return sig_ptr;
    }
    let data_layout = Layout::array::<SignatureElement>(sig.len()).unwrap();
    let data_ptr = alloc(data_layout) as *mut SignatureElement;
    if data_ptr.is_null() {
        dealloc(mem, layout);
        return ptr::null_mut();
    }
    (*sig_ptr).data = data_ptr;
    ptr::copy_nonoverlapping(sig.as_ptr(), data_ptr, sig.len());
    sig_ptr
}

#[no_mangle]
pub unsafe extern "C" fn libhat_parse_signature(
    signature_str: *const std::ffi::c_char,
    signature_out: *mut *mut Signature,
) -> LibhatStatus {
    if signature_str.is_null() || signature_out.is_null() {
        return LibhatStatus::ErrUnknown;
    }

    let c_str = match CStr::from_ptr(signature_str).to_str() {
        Ok(s) => s,
        Err(_) => return LibhatStatus::ErrUnknown,
    };

    match signature::parse_signature(c_str) {
        Ok(sig) => {
            let allocated = allocate_signature(&sig);
            if allocated.is_null() {
                return LibhatStatus::ErrUnknown;
            }
            *signature_out = allocated;
            LibhatStatus::Success
        }
        Err(e) => {
            *signature_out = ptr::null_mut();
            to_cpp_signature_error(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_create_signature(
    bytes: *const std::ffi::c_char,
    mask: *const std::ffi::c_char,
    size: usize,
    signature_out: *mut *mut Signature,
) -> LibhatStatus {
    if bytes.is_null() || mask.is_null() || signature_out.is_null() {
        return LibhatStatus::ErrUnknown;
    }

    let bytes_slice = std::slice::from_raw_parts(bytes.cast::<u8>(), size);
    let mask_slice = std::slice::from_raw_parts(mask.cast::<u8>(), size);

    let mut sig = Vec::with_capacity(size);
    for i in 0..size {
        if mask_slice[i] != 0 {
            sig.push(SignatureElement::from_value(bytes_slice[i]));
        } else {
            sig.push(SignatureElement::wildcard());
        }
    }

    let allocated = allocate_signature(&sig);
    if allocated.is_null() {
        return LibhatStatus::ErrUnknown;
    }
    *signature_out = allocated;
    LibhatStatus::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_find_pattern(
    signature: *const Signature,
    buffer: *const std::ffi::c_void,
    size: usize,
    align: ScanAlignmentC,
) -> *const std::ffi::c_void {
    if signature.is_null() || buffer.is_null() {
        return ptr::null();
    }

    let sig = std::slice::from_raw_parts((*signature).data, (*signature).count);
    let begin = buffer as *const u8;
    let end = begin.add(size);

    let result = scanner::find_pattern(begin, end, sig, to_cpp_align(align), ScanHint::NONE);
    if result.has_result() {
        result.get() as *const std::ffi::c_void
    } else {
        ptr::null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_find_pattern_parallel(
    signature: *const Signature,
    buffer: *const std::ffi::c_void,
    size: usize,
    align: ScanAlignmentC,
) -> *const std::ffi::c_void {
    if signature.is_null() || buffer.is_null() {
        return ptr::null();
    }

    let sig = std::slice::from_raw_parts((*signature).data, (*signature).count);
    let begin = buffer as *const u8;
    let end = begin.add(size);

    let result = scanner::find_pattern_parallel(begin, end, sig, to_cpp_align(align), ScanHint::NONE);
    if result.has_result() {
        result.get() as *const std::ffi::c_void
    } else {
        ptr::null()
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_find_pattern_mod(
    signature: *const Signature,
    module_ptr: *const std::ffi::c_void,
    section: *const std::ffi::c_char,
    align: ScanAlignmentC,
) -> *const std::ffi::c_void {
    if signature.is_null() || module_ptr.is_null() || section.is_null() {
        return ptr::null();
    }

    let sig = std::slice::from_raw_parts((*signature).data, (*signature).count);
    let section_str = match CStr::from_ptr(section).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null(),
    };

    let mod_at = crate::process::module_at(module_ptr as *const u8, None);
    match mod_at {
        Some(module) => {
            let data = module.get_section_data(section_str);
            match data {
                Some(section_data) => {
                    let result = scanner::find_pattern(
                        section_data.as_ptr(),
                        section_data.as_ptr().wrapping_add(section_data.len()),
                        sig,
                        to_cpp_align(align),
                        ScanHint::NONE,
                    );
                    if result.has_result() {
        result.get() as *const std::ffi::c_void
                    } else {
                        ptr::null()
                    }
                }
                None => ptr::null(),
            }
        }
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_at(address: *const std::ffi::c_void) -> *const std::ffi::c_void {
    if address.is_null() {
        return ptr::null();
    }
    let mod_at = crate::process::module_at(address as *const u8, None);
    mod_at.map(|m| m.address() as *const std::ffi::c_void).unwrap_or(ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn libhat_get_module(name: *const std::ffi::c_char) -> *const std::ffi::c_void {
    if name.is_null() {
        let mod_at = crate::process::get_process_module();
        return mod_at.map(|m| m.address() as *const std::ffi::c_void).unwrap_or(ptr::null());
    }

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null(),
    };

    let mod_at = crate::process::get_module(name_str);
    mod_at.map(|m| m.address() as *const std::ffi::c_void).unwrap_or(ptr::null())
}

#[no_mangle]
pub unsafe extern "C" fn libhat_free(mem: *mut std::ffi::c_void) {
    if mem.is_null() {
        return;
    }
    let sig_ptr = mem as *mut Signature;
    if !(*sig_ptr).data.is_null() {
        let data_layout = Layout::array::<SignatureElement>((*sig_ptr).count).unwrap();
        dealloc((*sig_ptr).data as *mut u8, data_layout);
    }
    dealloc(mem as *mut u8, Layout::new::<Signature>());
}
