use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::slice;

use libc::{c_void, size_t, dl_iterate_phdr, dl_phdr_info, dlopen, dlclose};
use libc::{RTLD_LAZY, RTLD_NOLOAD, PT_LOAD, PF_R, PF_W, PF_X};

use crate::process::Module;
use crate::protection::Protection;

fn fast_align_up(addr: usize, alignment: usize) -> usize {
    let align = if alignment == 0 { 1 } else { alignment };
    (addr + align - 1) & !(align - 1)
}

pub fn get_process_module() -> Option<Module> {
    get_module("")
}

pub fn get_module(name: &str) -> Option<Module> {
    unsafe {
        let handle = if name.is_empty() {
            dlopen(std::ptr::null(), RTLD_LAZY | RTLD_NOLOAD)
        } else {
            let c = CString::new(name).ok()?;
            dlopen(c.as_ptr(), RTLD_LAZY | RTLD_NOLOAD)
        };

        if handle.is_null() {
            return None;
        }

        let mut module: Option<Module> = None;
        let mod_ptr = &mut module as *mut Option<Module>;

        let mut cb = HandleMatchData { handle, mod_ptr, found: false };
        let cb_ptr = &mut cb as *mut _ as *mut c_void;

        dl_iterate_phdr(Some(handle_match_cb), cb_ptr);
        dlclose(handle);
        module
    }
}

struct HandleMatchData {
    handle: *mut c_void,
    mod_ptr: *mut Option<Module>,
    found: bool,
}

unsafe extern "C" fn handle_match_cb(
    info: *mut dl_phdr_info,
    _size: size_t,
    data: *mut c_void,
) -> i32 {
    let cb = &mut *(data as *mut HandleMatchData);
    let h = dlopen((*info).dlpi_name, RTLD_LAZY | RTLD_NOLOAD);
    if h == cb.handle && !h.is_null() {
        *cb.mod_ptr = Some(Module::new((*info).dlpi_addr as usize));
        dlclose(h);
        cb.found = true;
        return 1;
    }
    if !h.is_null() {
        dlclose(h);
    }
    0
}

pub fn get_module_data(module: &Module) -> &[u8] {
    let addr = module.address();
    let mut max_size: usize = 0;
    let max_ptr = &mut max_size as *mut usize;
    let addr_raw = addr;

    let mut cb = MaxSizeData { addr: addr_raw, max_ptr };
    unsafe {
        dl_iterate_phdr(Some(max_size_cb), &mut cb as *mut _ as *mut c_void);
    }

    if max_size == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(addr as *const u8, max_size) }
}

struct MaxSizeData {
    addr: usize,
    max_ptr: *mut usize,
}

unsafe extern "C" fn max_size_cb(
    info: *mut dl_phdr_info,
    _size: size_t,
    data: *mut c_void,
) -> i32 {
    let cb = &mut *(data as *mut MaxSizeData);
    if (*info).dlpi_addr as usize != cb.addr {
        return 0;
    }
    for i in 0..(*info).dlpi_phnum as usize {
        let header = &*((*info).dlpi_phdr.add(i));
        if header.p_type != PT_LOAD {
            continue;
        }
        let end = fast_align_up(
            header.p_vaddr as usize + header.p_memsz as usize,
            if header.p_align != 0 { header.p_align as usize } else { 1 },
        );
        if end > *cb.max_ptr {
            *cb.max_ptr = end;
        }
    }
    0
}

pub fn get_section_data<'a>(_module: &'a Module, _name: &str) -> Option<&'a [u8]> {
    None
}

pub fn for_each_segment(module: &Module, callback: &mut dyn FnMut(&[u8], Protection) -> bool) {
    let addr = module.address();
    let addr_raw = addr;

    let mut data = SegmentData { addr: addr_raw, cb: Some(callback) };
    unsafe {
        dl_iterate_phdr(Some(segment_cb), &mut data as *mut _ as *mut c_void);
    }
}

type SegmentCallback<'a> = &'a mut dyn FnMut(&[u8], Protection) -> bool;

struct SegmentData<'a> {
    addr: usize,
    cb: Option<SegmentCallback<'a>>,
}

unsafe extern "C" fn segment_cb(
    info: *mut dl_phdr_info,
    _size: size_t,
    data: *mut c_void,
) -> i32 {
    let seg = &mut *(data as *mut SegmentData);
    if (*info).dlpi_addr as usize != seg.addr {
        return 0;
    }
    let cb = seg.cb.as_mut().unwrap_unchecked();
    for i in 0..(*info).dlpi_phnum as usize {
        let header = &*((*info).dlpi_phdr.add(i));
        if header.p_type != PT_LOAD {
            continue;
        }

        let seg_data = slice::from_raw_parts(
            (seg.addr + header.p_vaddr as usize) as *const u8,
            header.p_memsz as usize,
        );

        let mut prot = Protection::empty();
        if header.p_flags & PF_R != 0 { prot |= Protection::READ; }
        if header.p_flags & PF_W != 0 { prot |= Protection::WRITE; }
        if header.p_flags & PF_X != 0 { prot |= Protection::EXECUTE; }

        if !cb(seg_data, prot) {
            return 0;
        }
    }
    1
}

pub fn module_at(address: *const u8, _size: Option<usize>) -> Option<Module> {
    let addr = address as usize;
    let mut module: Option<Module> = None;
    let mod_ptr = &mut module as *mut Option<Module>;

    let mut data = ModuleAtData { addr, mod_ptr };
    unsafe {
        dl_iterate_phdr(Some(module_at_cb), &mut data as *mut _ as *mut c_void);
    }

    module
}

struct ModuleAtData {
    addr: usize,
    mod_ptr: *mut Option<Module>,
}

unsafe extern "C" fn module_at_cb(
    info: *mut dl_phdr_info,
    _size: size_t,
    data: *mut c_void,
) -> i32 {
    let cb = &mut *(data as *mut ModuleAtData);
    if (*info).dlpi_addr as usize == cb.addr {
        *cb.mod_ptr = Some(Module::new(cb.addr));
        return 1;
    }
    0
}

pub fn region_has_flags(region: &[u8], flags: u32) -> bool {
    if region.is_empty() {
        return false;
    }

    let start = region.as_ptr() as usize;
    let end = start + region.len();
    let mut current = start;

    let file = match File::open("/proc/self/maps") {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut found = false;
    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let parts: Vec<&str> = line.splitn(5, ' ').collect();
        if parts.len() < 2 {
            continue;
        }

        let range: Vec<&str> = parts[0].split('-').collect();
        if range.len() != 2 {
            continue;
        }

        let begin = usize::from_str_radix(range[0], 16).unwrap_or(0);
        let end_range = usize::from_str_radix(range[1], 16).unwrap_or(0);

        let prot_str = parts[1].as_bytes();
        let prot_bits: u32 = {
            let mut p = 0u32;
            if !prot_str.is_empty() && prot_str[0] == b'r' { p |= libc::PROT_READ as u32; }
            if prot_str.len() > 1 && prot_str[1] == b'w' { p |= libc::PROT_WRITE as u32; }
            if prot_str.len() > 2 && prot_str[2] == b'x' { p |= libc::PROT_EXEC as u32; }
            p
        };

        if !found {
            if current >= begin && current < end_range {
                found = true;
            } else {
                continue;
            }
        } else if current != begin {
            break;
        }

        if found {
            if prot_bits & flags != flags {
                return false;
            }
            current = end_range;
        }

        if current >= end {
            break;
        }
    }

    current >= end
}
