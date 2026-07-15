use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::OnceLock;

use crate::process::Module;
use crate::protection::Protection;
use crate::scanner::{self, ScanAlignment, ScanHint};
use crate::signature::{self, SignatureElement};

const fn parse_u32(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut result = 0u32;
    let mut i = 0;
    while i < bytes.len() {
        result = result * 10 + (bytes[i] - b'0') as u32;
        i += 1;
    }
    result
}

const VERSION: &str = env!("CARGO_PKG_VERSION");
// TODO: figure out a way to not hardcode these
const VERSION_MAJOR: u32 = parse_u32(env!("CARGO_PKG_VERSION_MAJOR"));
const VERSION_MINOR: u32 = parse_u32(env!("CARGO_PKG_VERSION_MINOR"));
const VERSION_PATCH: u32 = parse_u32(env!("CARGO_PKG_VERSION_PATCH"));

#[repr(C)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum libhat_status {
    Success = 0,
    ErrUnknown = 1,
    SigMissingMaskedByte = 2,
    SigElementParseError = 3,
    SigEmptySignature = 4,
    SigExpectedWildcard = 5,
    SigInvalidTokenLength = 6,
    InvalidArgumentValue = 7,
    InvalidArgumentType = 8,
}

#[repr(C)]
pub enum libhat_alignment {
    X1 = 0,
    X4 = 1,
    X16 = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct libhat_hint(pub u32);

impl libhat_hint {
    pub const NONE: libhat_hint = libhat_hint(0);
    pub const SSE42: libhat_hint = libhat_hint(1 << 0);
    pub const AVX2: libhat_hint = libhat_hint(1 << 1);
    pub const AVX512: libhat_hint = libhat_hint(1 << 2);
    pub const NEON: libhat_hint = libhat_hint(1 << 3);
    pub const AARCH64: libhat_hint = libhat_hint(1 << 4);
}

#[repr(C)]
pub struct libhat_span {
    pub data: *const u8,
    pub size: usize,
}

#[repr(C)]
pub struct libhat_protection(pub u32);

impl libhat_protection {
    pub const NONE: libhat_protection = libhat_protection(0);
    pub const READ: libhat_protection = libhat_protection(1);
    pub const WRITE: libhat_protection = libhat_protection(2);
    pub const EXECUTE: libhat_protection = libhat_protection(4);

    fn from_rust(prot: Protection) -> Self {
        let mut p = 0u32;
        if prot.contains(Protection::READ) {
            p |= Self::READ.0;
        }
        if prot.contains(Protection::WRITE) {
            p |= Self::WRITE.0;
        }
        if prot.contains(Protection::EXECUTE) {
            p |= Self::EXECUTE.0;
        }
        libhat_protection(p)
    }
}

pub type libhat_for_each_section_cb = extern "C" fn(
    name: *const std::ffi::c_char,
    data: libhat_span,
    protection: libhat_protection,
    user_data: *mut std::ffi::c_void,
) -> bool;

pub type libhat_for_each_segment_cb = extern "C" fn(
    data: libhat_span,
    protection: libhat_protection,
    user_data: *mut std::ffi::c_void,
) -> bool;

const OBJECT_MAGIC: u32 = 0x2C360B8A;
const SIGNATURE_TYPE_ID: u32 = 0xFD19C2B3;
const MODULE_TYPE_ID: u32 = 0xBAA5FEEC;

#[repr(C)]
struct OpaqueHeader {
    magic: u32,
    type_id: u32,
    destroy: extern "C" fn(*const OpaqueHeader),
}

#[repr(C)]
pub struct libhat_signature {
    header: OpaqueHeader,
    inner: signature::Signature,
}

#[repr(C)]
pub struct libhat_module {
    header: OpaqueHeader,
    inner: Option<Module>,
}

extern "C" fn destroy_signature(header: *const OpaqueHeader) {
    unsafe {
        drop(Box::from_raw(header as *mut libhat_signature));
    }
}

extern "C" fn destroy_module(header: *const OpaqueHeader) {
    unsafe {
        let _ = Box::from_raw(header as *mut libhat_module);
    }
}

unsafe fn check_signature_type(sig: *const libhat_signature) -> bool {
    !sig.is_null()
        && (*sig).header.magic == OBJECT_MAGIC
        && (*sig).header.type_id == SIGNATURE_TYPE_ID
}

unsafe fn check_module_type(module: *const libhat_module) -> bool {
    !module.is_null()
        && (*module).header.magic == OBJECT_MAGIC
        && (*module).header.type_id == MODULE_TYPE_ID
}

fn to_cpp_align(align: libhat_alignment) -> Option<ScanAlignment> {
    match align {
        libhat_alignment::X1 => Some(ScanAlignment::X1),
        libhat_alignment::X4 => Some(ScanAlignment::X4),
        libhat_alignment::X16 => Some(ScanAlignment::X16),
    }
}

fn to_cpp_hints(hints: libhat_hint) -> ScanHint {
    ScanHint(hints.0 as u64)
}

fn to_cpp_signature_error(err: signature::SignatureError) -> libhat_status {
    match err {
        signature::SignatureError::MissingMaskedByte => libhat_status::SigMissingMaskedByte,
        signature::SignatureError::EmptySignature => libhat_status::SigEmptySignature,
        signature::SignatureError::ElementParseError => libhat_status::SigElementParseError,
        signature::SignatureError::ExpectedWildcard => libhat_status::SigExpectedWildcard,
        signature::SignatureError::InvalidTokenLength => libhat_status::SigInvalidTokenLength,
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_get_version() -> *const std::ffi::c_char {
    static VERSION_CSTRING: OnceLock<CString> = OnceLock::new();
    VERSION_CSTRING
        .get_or_init(|| CString::new(VERSION).unwrap())
        .as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn libhat_get_version_num() -> std::ffi::c_int {
    ((VERSION_MAJOR << 16) | (VERSION_MINOR << 8) | VERSION_PATCH) as std::ffi::c_int
}

#[no_mangle]
pub unsafe extern "C" fn libhat_status_to_string(status: libhat_status) -> *const std::ffi::c_char {
    match status {
        libhat_status::Success => c"libhat_success".as_ptr(),
        libhat_status::ErrUnknown => c"libhat_err_unknown".as_ptr(),
        libhat_status::SigMissingMaskedByte => c"libhat_err_sig_missing_masked_byte".as_ptr(),
        libhat_status::SigElementParseError => c"libhat_err_sig_element_parse_error".as_ptr(),
        libhat_status::SigEmptySignature => c"libhat_err_sig_empty_signature".as_ptr(),
        libhat_status::SigExpectedWildcard => c"libhat_err_sig_expected_wildcard".as_ptr(),
        libhat_status::SigInvalidTokenLength => c"libhat_err_sig_invalid_token_length".as_ptr(),
        libhat_status::InvalidArgumentValue => c"libhat_err_invalid_argument_value".as_ptr(),
        libhat_status::InvalidArgumentType => c"libhat_err_invalid_argument_type".as_ptr(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_parse_signature(
    signature_str: *const std::ffi::c_char,
    signature_out: *mut *const libhat_signature,
) -> libhat_status {
    if signature_str.is_null() || signature_out.is_null() {
        return libhat_status::ErrUnknown;
    }

    let c_str = match CStr::from_ptr(signature_str).to_str() {
        Ok(s) => s,
        Err(_) => return libhat_status::ErrUnknown,
    };

    match signature::parse_signature(c_str) {
        Ok(sig) => {
            let boxed = Box::new(libhat_signature {
                header: OpaqueHeader {
                    magic: OBJECT_MAGIC,
                    type_id: SIGNATURE_TYPE_ID,
                    destroy: destroy_signature,
                },
                inner: sig,
            });
            *signature_out = Box::into_raw(boxed);
            libhat_status::Success
        }
        Err(e) => {
            *signature_out = ptr::null();
            to_cpp_signature_error(e)
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_create_signature(
    bytes: *const std::ffi::c_char,
    mask: *const std::ffi::c_char,
    size: usize,
    signature_out: *mut *const libhat_signature,
) -> libhat_status {
    if signature_out.is_null() {
        return libhat_status::InvalidArgumentValue;
    }
    if size != 0 && (bytes.is_null() || mask.is_null()) {
        return libhat_status::InvalidArgumentValue;
    }
    if size == 0 {
        *signature_out = ptr::null();
        return libhat_status::SigEmptySignature;
    }

    let bytes_slice = std::slice::from_raw_parts(bytes.cast::<u8>(), size);
    let mask_slice = std::slice::from_raw_parts(mask.cast::<u8>(), size);

    let mut sig = signature::Signature::with_capacity(size);
    let mut contains_byte = false;
    for i in 0..size {
        let elem = SignatureElement::from_value_mask(bytes_slice[i], mask_slice[i]);
        contains_byte |= elem.is_all();
        sig.push(elem);
    }
    if !contains_byte {
        *signature_out = ptr::null();
        return libhat_status::SigMissingMaskedByte;
    }

    let boxed = Box::new(libhat_signature {
        header: OpaqueHeader {
            magic: OBJECT_MAGIC,
            type_id: SIGNATURE_TYPE_ID,
            destroy: destroy_signature,
        },
        inner: sig,
    });
    *signature_out = Box::into_raw(boxed);
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_find_pattern(
    signature: *const libhat_signature,
    buffer: *const std::ffi::c_void,
    size: usize,
    result_out: *mut *const std::ffi::c_void,
    align: libhat_alignment,
    hints: libhat_hint,
) -> libhat_status {
    if signature.is_null() || (buffer.is_null() && size != 0) || result_out.is_null() {
        return libhat_status::InvalidArgumentValue;
    }

    if !check_signature_type(signature) {
        return libhat_status::InvalidArgumentType;
    }

    let cpp_align = match to_cpp_align(align) {
        Some(a) => a,
        None => return libhat_status::InvalidArgumentValue,
    };

    let sig = &(*signature).inner;
    let begin = buffer as *const u8;
    let end = begin.add(size);

    let result = scanner::find_pattern(begin, end, sig, cpp_align, to_cpp_hints(hints));
    *result_out = if result.has_result() {
        result.get() as *const std::ffi::c_void
    } else {
        ptr::null()
    };
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_find_pattern_mod(
    signature: *const libhat_signature,
    module: *const libhat_module,
    section: *const std::ffi::c_char,
    result_out: *mut *const std::ffi::c_void,
    align: libhat_alignment,
    hints: libhat_hint,
) -> libhat_status {
    if signature.is_null() || module.is_null() || section.is_null() || result_out.is_null() {
        return libhat_status::InvalidArgumentValue;
    }

    if !check_signature_type(signature) || !check_module_type(module) {
        return libhat_status::InvalidArgumentType;
    }

    let cpp_align = match to_cpp_align(align) {
        Some(a) => a,
        None => return libhat_status::InvalidArgumentValue,
    };

    let sig = &(*signature).inner;
    let section_str = match CStr::from_ptr(section).to_str() {
        Ok(s) => s,
        Err(_) => {
            *result_out = ptr::null();
            return libhat_status::InvalidArgumentValue;
        }
    };

    let mod_ref = match (*module).inner {
        Some(m) => m,
        None => {
            *result_out = ptr::null();
            return libhat_status::Success;
        }
    };

    let data = mod_ref.get_section_data(section_str);
    *result_out = match data {
        Some(section_data) => {
            let result = scanner::find_pattern(
                section_data.as_ptr(),
                section_data.as_ptr().wrapping_add(section_data.len()),
                sig,
                cpp_align,
                to_cpp_hints(hints),
            );
            if result.has_result() {
                result.get() as *const std::ffi::c_void
            } else {
                ptr::null()
            }
        }
        None => ptr::null(),
    };
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_address(
    module: *const libhat_module,
    out: *mut usize,
) -> libhat_status {
    if module.is_null() || out.is_null() {
        return libhat_status::InvalidArgumentValue;
    }
    if !check_module_type(module) {
        return libhat_status::InvalidArgumentType;
    }
    *out = match (*module).inner {
        Some(m) => m.address(),
        None => 0,
    };
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_get_data(
    module: *const libhat_module,
    out: *mut libhat_span,
) -> libhat_status {
    if module.is_null() || out.is_null() {
        return libhat_status::InvalidArgumentValue;
    }
    if !check_module_type(module) {
        return libhat_status::InvalidArgumentType;
    }
    *out = match (*module).inner {
        Some(m) => {
            let data = m.get_module_data();
            libhat_span {
                data: data.as_ptr(),
                size: data.len(),
            }
        }
        None => libhat_span {
            data: ptr::null(),
            size: 0,
        },
    };
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_get_executable_data(
    module: *const libhat_module,
    out: *mut libhat_span,
) -> libhat_status {
    if module.is_null() || out.is_null() {
        return libhat_status::InvalidArgumentValue;
    }
    if !check_module_type(module) {
        return libhat_status::InvalidArgumentType;
    }
    *out = match (*module).inner {
        Some(m) => {
            let data = m.get_executable_data();
            libhat_span {
                data: data.as_ptr(),
                size: data.len(),
            }
        }
        None => libhat_span {
            data: ptr::null(),
            size: 0,
        },
    };
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_get_section_data(
    module: *const libhat_module,
    name: *const std::ffi::c_char,
    out: *mut libhat_span,
) -> libhat_status {
    if module.is_null() || name.is_null() || out.is_null() {
        return libhat_status::InvalidArgumentValue;
    }
    if !check_module_type(module) {
        return libhat_status::InvalidArgumentType;
    }
    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => {
            *out = libhat_span {
                data: ptr::null(),
                size: 0,
            };
            return libhat_status::InvalidArgumentValue;
        }
    };
    *out = match (*module).inner {
        Some(m) => match m.get_section_data(name_str) {
            Some(data) => libhat_span {
                data: data.as_ptr(),
                size: data.len(),
            },
            None => libhat_span {
                data: ptr::null(),
                size: 0,
            },
        },
        None => libhat_span {
            data: ptr::null(),
            size: 0,
        },
    };
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_for_each_section(
    module: *const libhat_module,
    callback: libhat_for_each_section_cb,
    user_data: *mut std::ffi::c_void,
) -> libhat_status {
    if module.is_null() || callback as usize == 0 {
        return libhat_status::InvalidArgumentValue;
    }
    if !check_module_type(module) {
        return libhat_status::InvalidArgumentType;
    }
    let mod_ref = match (*module).inner {
        Some(m) => m,
        None => return libhat_status::Success,
    };

    mod_ref.for_each_section(&mut |name, data, prot| {
        let c_name = match CString::new(name) {
            Ok(n) => n,
            Err(_) => return true,
        };
        let span = libhat_span {
            data: data.as_ptr(),
            size: data.len(),
        };
        let libhat_prot = libhat_protection::from_rust(prot);
        callback(c_name.as_ptr(), span, libhat_prot, user_data)
    });
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_for_each_segment(
    module: *const libhat_module,
    callback: libhat_for_each_segment_cb,
    user_data: *mut std::ffi::c_void,
) -> libhat_status {
    if module.is_null() || callback as usize == 0 {
        return libhat_status::InvalidArgumentValue;
    }
    if !check_module_type(module) {
        return libhat_status::InvalidArgumentType;
    }
    let mod_ref = match (*module).inner {
        Some(m) => m,
        None => return libhat_status::Success,
    };

    mod_ref.for_each_segment(&mut |data, prot| {
        let span = libhat_span {
            data: data.as_ptr(),
            size: data.len(),
        };
        let libhat_prot = libhat_protection::from_rust(prot);
        callback(span, libhat_prot, user_data)
    });
    libhat_status::Success
}

#[no_mangle]
pub unsafe extern "C" fn libhat_is_readable(data: *const std::ffi::c_void, size: usize) -> bool {
    if data.is_null() || size == 0 {
        return false;
    }
    let region = std::slice::from_raw_parts(data as *const u8, size);
    crate::process::is_readable(region)
}

#[no_mangle]
pub unsafe extern "C" fn libhat_is_writable(data: *const std::ffi::c_void, size: usize) -> bool {
    if data.is_null() || size == 0 {
        return false;
    }
    let region = std::slice::from_raw_parts(data as *const u8, size);
    crate::process::is_writable(region)
}

#[no_mangle]
pub unsafe extern "C" fn libhat_is_executable(data: *const std::ffi::c_void, size: usize) -> bool {
    if data.is_null() || size == 0 {
        return false;
    }
    let region = std::slice::from_raw_parts(data as *const u8, size);
    crate::process::is_executable(region)
}

#[no_mangle]
pub unsafe extern "C" fn libhat_get_process_module() -> *const libhat_module {
    let module = crate::process::get_process_module();
    match module {
        Some(m) => {
            let boxed = Box::new(libhat_module {
                header: OpaqueHeader {
                    magic: OBJECT_MAGIC,
                    type_id: MODULE_TYPE_ID,
                    destroy: destroy_module,
                },
                inner: Some(m),
            });
            Box::into_raw(boxed)
        }
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_get_module(name: *const std::ffi::c_char) -> *const libhat_module {
    if name.is_null() {
        return libhat_get_process_module();
    }

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null(),
    };

    let module = crate::process::get_module(name_str);
    match module {
        Some(m) => {
            let boxed = Box::new(libhat_module {
                header: OpaqueHeader {
                    magic: OBJECT_MAGIC,
                    type_id: MODULE_TYPE_ID,
                    destroy: destroy_module,
                },
                inner: Some(m),
            });
            Box::into_raw(boxed)
        }
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_module_at(
    address: *const std::ffi::c_void,
) -> *const libhat_module {
    if address.is_null() {
        return ptr::null();
    }
    let module = crate::process::module_at(address as *const u8);
    match module {
        Some(m) => {
            let boxed = Box::new(libhat_module {
                header: OpaqueHeader {
                    magic: OBJECT_MAGIC,
                    type_id: MODULE_TYPE_ID,
                    destroy: destroy_module,
                },
                inner: Some(m),
            });
            Box::into_raw(boxed)
        }
        None => ptr::null(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn libhat_free(object: *const std::ffi::c_void) {
    if object.is_null() {
        return;
    }
    let header = &*(object as *const OpaqueHeader);
    if header.magic != OBJECT_MAGIC {
        return;
    }
    (header.destroy)(header);
}
