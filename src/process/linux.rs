use std::ffi::{CStr, CString};
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

pub fn get_section_data<'a>(module: &'a Module, name: &str) -> Option<&'a [u8]> {
    let addr = module.address();
    let file_path = get_module_path(addr)?;

    let elf_data = std::fs::read(&file_path).ok()?;
    if elf_data.len() < 64 || &elf_data[..4] != b"\x7fELF" || elf_data[4] != 2 {
        return None;
    }

    let e_shoff = read_u64_ne(&elf_data, 40)? as usize;
    let e_shentsize = read_u16_ne(&elf_data, 58)? as usize;
    let e_shnum = read_u16_ne(&elf_data, 60)? as usize;
    let e_shstrndx = read_u16_ne(&elf_data, 62)? as usize;

    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 || e_shstrndx >= e_shnum {
        return None;
    }

    let strtab_hdr = e_shoff + e_shstrndx * e_shentsize;
    let strtab_off = read_u64_ne(&elf_data, strtab_hdr + 24)? as usize;
    let strtab_size = read_u64_ne(&elf_data, strtab_hdr + 32)? as usize;

    if strtab_off + strtab_size > elf_data.len() {
        return None;
    }

    for i in 0..e_shnum {
        let shdr_off = e_shoff + i * e_shentsize;
        if shdr_off + 64 > elf_data.len() {
            continue;
        }

        let sh_name = read_u32_ne(&elf_data, shdr_off)? as usize;
        let sh_addr = read_u64_ne(&elf_data, shdr_off + 16)? as usize;
        let sh_size = read_u64_ne(&elf_data, shdr_off + 32)? as usize;

        if sh_addr == 0 || sh_size == 0 || sh_name >= strtab_size {
            continue;
        }

        let name_start = strtab_off + sh_name;
        let end = elf_data[name_start..strtab_off + strtab_size]
            .iter()
            .position(|&b| b == 0)?;
        let sec_name = std::str::from_utf8(&elf_data[name_start..name_start + end]).ok()?;

        if sec_name == name {
            return unsafe {
                Some(slice::from_raw_parts((addr + sh_addr) as *const u8, sh_size))
            };
        }
    }

    None
}

fn get_module_path(addr: usize) -> Option<String> {
    unsafe {
        let mut path: Option<String> = None;
        let mut data = ModulePathData { addr, path: &mut path };
        dl_iterate_phdr(Some(module_path_cb), &mut data as *mut _ as *mut c_void);
        path
    }
}

struct ModulePathData<'a> {
    addr: usize,
    path: &'a mut Option<String>,
}

unsafe extern "C" fn module_path_cb(
    info: *mut dl_phdr_info,
    _size: size_t,
    data: *mut c_void,
) -> i32 {
    let cb = &mut *(data as *mut ModulePathData);
    if (*info).dlpi_addr as usize != cb.addr {
        return 0;
    }
    let c_str = CStr::from_ptr((*info).dlpi_name);
    let name = match c_str.to_str() {
        Ok(n) => n,
        Err(_) => return 1,
    };
    if name.is_empty() {
        *cb.path = std::fs::read_link("/proc/self/exe")
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()));
    } else {
        *cb.path = Some(name.to_string());
    }
    1
}

fn read_u16_ne(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(data.get(offset..offset + 2)?.try_into().ok()?))
}

fn read_u32_ne(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(data.get(offset..offset + 4)?.try_into().ok()?))
}

fn read_u64_ne(data: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(data.get(offset..offset + 8)?.try_into().ok()?))
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
