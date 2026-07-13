use std::ffi::CString;
use hat::c;

#[test]
fn test_c_api_parse_and_scan() {
    let sig_str = CString::new("48 8D 05 ? ? ? ? E8").unwrap();
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_parse_signature(sig_str.as_ptr(), &mut sig_out)
    };
    assert_eq!(status, c::libhat_status::Success);
    assert!(!sig_out.is_null());

    let data = [0x00u8, 0x48, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01, 0xE8, 0x00];

    let mut result: *const std::ffi::c_void = std::ptr::null();
    let status = unsafe {
        c::libhat_find_pattern(
            sig_out,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            &mut result,
            c::libhat_alignment::X1,
            c::libhat_hint::NONE,
        )
    };
    assert_eq!(status, c::libhat_status::Success);
    assert!(!result.is_null());
    assert_eq!(result as usize, unsafe { data.as_ptr().add(1) as usize });

    unsafe { c::libhat_free(sig_out as *const std::ffi::c_void) };
}

#[test]
fn test_c_api_not_found() {
    let sig_str = CString::new("FF FF FF").unwrap();
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_parse_signature(sig_str.as_ptr(), &mut sig_out)
    };
    assert_eq!(status, c::libhat_status::Success);

    let data = [0x00u8; 100];
    let mut result: *const std::ffi::c_void = std::ptr::null();
    let status = unsafe {
        c::libhat_find_pattern(
            sig_out,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            &mut result,
            c::libhat_alignment::X1,
            c::libhat_hint::NONE,
        )
    };
    assert_eq!(status, c::libhat_status::Success);
    assert!(result.is_null());

    unsafe { c::libhat_free(sig_out as *const std::ffi::c_void) };
}

#[test]
fn test_c_api_invalid_signature() {
    let sig_str = CString::new("?? ?? ??").unwrap();
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_parse_signature(sig_str.as_ptr(), &mut sig_out)
    };

    assert_eq!(status, c::libhat_status::SigMissingMaskedByte);
    assert!(sig_out.is_null());
}

#[test]
fn test_c_api_empty_signature() {
    let sig_str = CString::new("").unwrap();
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_parse_signature(sig_str.as_ptr(), &mut sig_out)
    };
    assert_eq!(status, c::libhat_status::SigEmptySignature);
    assert!(sig_out.is_null());
}

#[test]
fn test_c_api_all_wildcard() {
    let sig_str = CString::new("? ?").unwrap();
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_parse_signature(sig_str.as_ptr(), &mut sig_out)
    };
    assert_eq!(status, c::libhat_status::SigMissingMaskedByte);
    assert!(sig_out.is_null());
}

#[test]
fn test_c_api_null_handling() {
    let status = unsafe {
        c::libhat_parse_signature(std::ptr::null(), std::ptr::null_mut())
    };
    assert_eq!(status, c::libhat_status::ErrUnknown);
}

#[test]
fn test_c_api_invalid_nibble_only() {
    let sig_str = CString::new("?3").unwrap();
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_parse_signature(sig_str.as_ptr(), &mut sig_out)
    };
    assert_eq!(status, c::libhat_status::SigMissingMaskedByte);
    assert!(sig_out.is_null());
}

#[test]
fn test_c_api_invalid_non_hex() {
    let sig_str = CString::new("ZZ").unwrap();
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_parse_signature(sig_str.as_ptr(), &mut sig_out)
    };
    assert_eq!(status, c::libhat_status::SigElementParseError);
    assert!(sig_out.is_null());
}

#[test]
fn test_c_api_module_at_self() {
    let self_module = unsafe {
        c::libhat_get_process_module()
    };
    if self_module.is_null() {
        return;
    }

    let mut addr: usize = 0;
    let status = unsafe { c::libhat_module_address(self_module, &mut addr) };
    assert_eq!(status, c::libhat_status::Success);

    let mod_at = unsafe {
        c::libhat_module_at(addr as *const std::ffi::c_void)
    };
    assert!(!mod_at.is_null());

    unsafe { c::libhat_free(self_module as *const std::ffi::c_void) };
    unsafe { c::libhat_free(mod_at as *const std::ffi::c_void) };
}

#[test]
fn test_c_api_module_at_null() {
    let mod_at = unsafe {
        c::libhat_module_at(std::ptr::null())
    };
    assert!(mod_at.is_null());
}

#[test]
fn test_c_api_create_signature() {
    let bytes = [0x48u8, 0x8D, 0x00, 0x05];
    let mask = [0xFFu8, 0xFF, 0x00, 0xFF];
    let mut sig_out: *const c::libhat_signature = std::ptr::null();

    let status = unsafe {
        c::libhat_create_signature(
            bytes.as_ptr() as *const std::ffi::c_char,
            mask.as_ptr() as *const std::ffi::c_char,
            bytes.len(),
            &mut sig_out,
        )
    };
    assert_eq!(status, c::libhat_status::Success);
    assert!(!sig_out.is_null());

    let data = [0x48u8, 0x8D, 0xFF, 0x05];
    let mut result: *const std::ffi::c_void = std::ptr::null();
    let status = unsafe {
        c::libhat_find_pattern(
            sig_out,
            data.as_ptr() as *const std::ffi::c_void,
            data.len(),
            &mut result,
            c::libhat_alignment::X1,
            c::libhat_hint::NONE,
        )
    };
    assert_eq!(status, c::libhat_status::Success);
    assert!(!result.is_null());

    unsafe { c::libhat_free(sig_out as *const std::ffi::c_void) };
}

#[test]
fn test_c_api_find_pattern_null_args() {
    let mut result: *const std::ffi::c_void = std::ptr::null();
    let status = unsafe {
        c::libhat_find_pattern(
            std::ptr::null(),
            std::ptr::null(),
            0,
            &mut result,
            c::libhat_alignment::X1,
            c::libhat_hint::NONE,
        )
    };
    assert_eq!(status, c::libhat_status::InvalidArgumentValue);
}

#[test]
fn test_c_api_module_address_null() {
    let mut addr: usize = 0;
    let status = unsafe {
        c::libhat_module_address(std::ptr::null(), &mut addr)
    };
    assert_eq!(status, c::libhat_status::InvalidArgumentValue);
}
