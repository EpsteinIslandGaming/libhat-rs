use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::slice;
use std::sync::{Mutex, OnceLock};

use libc::{c_void, dl_iterate_phdr, dl_phdr_info, dladdr, dlclose, dlopen, size_t, Dl_info};
use libc::{PF_R, PF_W, PF_X, PT_LOAD, RTLD_LAZY, RTLD_NOLOAD};

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

        let mut cb = HandleMatchData {
            handle,
            mod_ptr,
            found: false,
        };
        dl_iterate_phdr(Some(handle_match_cb), &mut cb as *mut _ as *mut c_void);
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

    unsafe {
        let mut cb = MaxSizeData {
            addr,
            max_size: &mut max_size,
        };
        dl_iterate_phdr(Some(max_size_cb), &mut cb as *mut _ as *mut c_void);
    }

    if max_size == 0 {
        return &[];
    }
    unsafe { slice::from_raw_parts(addr as *const u8, max_size) }
}

struct MaxSizeData {
    addr: usize,
    max_size: *mut usize,
}

unsafe extern "C" fn max_size_cb(info: *mut dl_phdr_info, _size: size_t, data: *mut c_void) -> i32 {
    let cb = &mut *(data as *mut MaxSizeData);
    if (*info).dlpi_addr as usize != cb.addr {
        return 0;
    }
    let mut max = 0usize;
    for i in 0..(*info).dlpi_phnum as usize {
        let header = &*((*info).dlpi_phdr.add(i));
        if header.p_type != PT_LOAD {
            continue;
        }
        let end = fast_align_up(
            header.p_vaddr as usize + header.p_memsz as usize,
            if header.p_align != 0 {
                header.p_align as usize
            } else {
                1
            },
        );
        if end > max {
            max = end;
        }
    }
    *cb.max_size = max;
    1
}

struct SectionEntry {
    data_start: usize,
    data_size: usize,
    protection: Protection,
}

struct CachedSections {
    map: HashMap<String, SectionEntry>,
}

struct ModuleInner {
    base_address: usize,
    path: OnceLock<String>,
    sections: OnceLock<CachedSections>,
}

static MODULE_CACHE: OnceLock<Mutex<HashMap<usize, Box<ModuleInner>>>> = OnceLock::new();

fn get_or_create_inner(module: &Module) -> &'static ModuleInner {
    let cache = MODULE_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let addr = module.address();

    {
        let map = cache.lock().unwrap();
        if let Some(inner) = map.get(&addr) {
            // SAFETY: entries are never removed from the static HashMap, so the Box<ModuleInner> lives at a stable address for the program's lifetime.
            return unsafe { &*(inner.as_ref() as *const ModuleInner) };
        }
    }

    {
        let mut map = cache.lock().unwrap();
        if !map.contains_key(&addr) {
            map.insert(
                addr,
                Box::new(ModuleInner {
                    base_address: addr,
                    path: OnceLock::new(),
                    sections: OnceLock::new(),
                }),
            );
        }
    }

    let map = cache.lock().unwrap();
    let inner = map.get(&addr).unwrap();
    // Safety: entries are never removed from the static HashMap, so the
    // Box<ModuleInner> lives at a stable address for the program's lifetime.
    unsafe { &*(inner.as_ref() as *const ModuleInner) }
}

fn get_module_path(module: &Module) -> &'static str {
    let inner = get_or_create_inner(module);
    inner.path.get_or_init(|| {
        let addr = inner.base_address;
        let mut result = String::new();
        unsafe {
            let mut cb_data = PathData {
                addr,
                path: &mut result,
            };
            dl_iterate_phdr(Some(path_cb), &mut cb_data as *mut _ as *mut c_void);
        }
        result
    })
}

struct PathData<'a> {
    addr: usize,
    path: &'a mut String,
}

unsafe extern "C" fn path_cb(info: *mut dl_phdr_info, _size: size_t, data: *mut c_void) -> i32 {
    let cb = &mut *(data as *mut PathData);
    if (*info).dlpi_addr as usize != cb.addr {
        return 0;
    }
    let c_str = CStr::from_ptr((*info).dlpi_name);
    if c_str.to_bytes().is_empty() {
        *cb.path = std::fs::read_link("/proc/self/exe")
            .ok()
            .and_then(|p| p.to_str().map(|s| s.to_string()))
            .unwrap_or_default();
    } else {
        *cb.path = c_str.to_string_lossy().into_owned();
    }
    1
}

fn get_or_init_sections(module: &Module) -> &'static CachedSections {
    let inner = get_or_create_inner(module);
    inner.sections.get_or_init(|| init_sections(inner))
}

fn init_sections(inner: &ModuleInner) -> CachedSections {
    let path = match inner.path.get() {
        Some(p) => p.as_str(),
        None => {
            return CachedSections {
                map: HashMap::new(),
            }
        }
    };

    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            return CachedSections {
                map: HashMap::new(),
            }
        }
    };

    let mut reader = BufReader::new(file);
    let mut ehdr_buf = [0u8; 64];
    if reader.read_exact(&mut ehdr_buf).is_err() {
        return CachedSections {
            map: HashMap::new(),
        };
    }

    if &ehdr_buf[..4] != b"\x7fELF" || ehdr_buf[4] != 2 {
        return CachedSections {
            map: HashMap::new(),
        };
    }

    let e_shoff = u64::from_ne_bytes(ehdr_buf[40..48].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_ne_bytes(ehdr_buf[58..60].try_into().unwrap()) as usize;
    let e_shnum = u16::from_ne_bytes(ehdr_buf[60..62].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_ne_bytes(ehdr_buf[62..64].try_into().unwrap()) as usize;

    if e_shoff == 0 || e_shnum == 0 || e_shentsize < 64 || e_shstrndx >= e_shnum {
        return CachedSections {
            map: HashMap::new(),
        };
    }

    let sections_total = e_shnum * e_shentsize;
    let mut sections_buf = vec![0u8; sections_total];
    if reader.seek(SeekFrom::Start(e_shoff as u64)).is_err() {
        return CachedSections {
            map: HashMap::new(),
        };
    }
    if reader.read_exact(&mut sections_buf).is_err() {
        return CachedSections {
            map: HashMap::new(),
        };
    }

    let strtab_hdr_off = e_shstrndx * e_shentsize;
    let strtab_off = u64::from_ne_bytes(
        sections_buf[strtab_hdr_off + 24..strtab_hdr_off + 32]
            .try_into()
            .unwrap(),
    ) as usize;
    let strtab_size = u64::from_ne_bytes(
        sections_buf[strtab_hdr_off + 32..strtab_hdr_off + 40]
            .try_into()
            .unwrap(),
    ) as usize;

    let mut strings_buf = vec![0u8; strtab_size];
    if reader.seek(SeekFrom::Start(strtab_off as u64)).is_err() {
        return CachedSections {
            map: HashMap::new(),
        };
    }
    if reader.read_exact(&mut strings_buf).is_err() {
        return CachedSections {
            map: HashMap::new(),
        };
    }

    let mut map = HashMap::new();

    for i in 0..e_shnum {
        let shdr_off = i * e_shentsize;
        if shdr_off + 64 > sections_buf.len() {
            continue;
        }

        let sh_name =
            u32::from_ne_bytes(sections_buf[shdr_off..shdr_off + 4].try_into().unwrap()) as usize;
        let sh_addr = u64::from_ne_bytes(
            sections_buf[shdr_off + 16..shdr_off + 24]
                .try_into()
                .unwrap(),
        ) as usize;
        let sh_size = u64::from_ne_bytes(
            sections_buf[shdr_off + 32..shdr_off + 40]
                .try_into()
                .unwrap(),
        ) as usize;
        let sh_flags = u64::from_ne_bytes(
            sections_buf[shdr_off + 8..shdr_off + 16]
                .try_into()
                .unwrap(),
        );

        if sh_addr == 0 || sh_size == 0 || sh_name >= strtab_size {
            continue;
        }

        if sh_flags & 0x2 == 0 {
            continue;
        }

        let name_end = strings_buf[sh_name..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(strings_buf.len() - sh_name);
        let sec_name = match std::str::from_utf8(&strings_buf[sh_name..sh_name + name_end]) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let mut prot = Protection::READ;
        if sh_flags & 0x1 != 0 {
            prot |= Protection::WRITE;
        }
        if sh_flags & 0x4 != 0 {
            prot |= Protection::EXECUTE;
        }

        map.insert(
            sec_name.to_string(),
            SectionEntry {
                data_start: inner.base_address + sh_addr,
                data_size: sh_size,
                protection: prot,
            },
        );
    }

    CachedSections { map }
}

pub fn get_executable_data(module: &Module) -> &[u8] {
    let sections = get_or_init_sections(module);

    if let Some(entry) = sections.map.get(".text") {
        return unsafe { slice::from_raw_parts(entry.data_start as *const u8, entry.data_size) };
    }

    for entry in sections.map.values() {
        if entry.protection == (Protection::READ | Protection::EXECUTE) && entry.data_size > 0 {
            return unsafe {
                slice::from_raw_parts(entry.data_start as *const u8, entry.data_size)
            };
        }
    }

    let mut result_ptr: *const u8 = std::ptr::null();
    let mut result_len: usize = 0;
    let mut found = false;
    for_each_segment(module, &mut |data, prot| {
        if !found
            && prot.contains(Protection::READ)
            && !prot.contains(Protection::WRITE)
            && prot.contains(Protection::EXECUTE)
            && !data.is_empty()
        {
            result_ptr = data.as_ptr();
            result_len = data.len();
            found = true;
        }
        false
    });
    if found && !result_ptr.is_null() {
        unsafe { slice::from_raw_parts(result_ptr, result_len) }
    } else {
        &[]
    }
}

pub fn get_section_data<'a>(module: &'a Module, name: &str) -> Option<&'a [u8]> {
    let sections = get_or_init_sections(module);
    let entry = sections.map.get(name)?;
    Some(unsafe { slice::from_raw_parts(entry.data_start as *const u8, entry.data_size) })
}

pub fn for_each_section(
    module: &Module,
    callback: &mut dyn FnMut(&str, &[u8], Protection) -> bool,
) {
    let sections = get_or_init_sections(module);
    for (name, entry) in &sections.map {
        let data = unsafe { slice::from_raw_parts(entry.data_start as *const u8, entry.data_size) };
        if !callback(name, data, entry.protection) {
            break;
        }
    }
}

pub fn for_each_segment(module: &Module, callback: &mut dyn FnMut(&[u8], Protection) -> bool) {
    let addr = module.address();

    let mut data = SegmentData {
        addr,
        cb: Some(callback),
    };
    unsafe {
        dl_iterate_phdr(Some(segment_cb), &mut data as *mut _ as *mut c_void);
    }
}

type SegmentCallback<'a> = &'a mut dyn FnMut(&[u8], Protection) -> bool;

struct SegmentData<'a> {
    addr: usize,
    cb: Option<SegmentCallback<'a>>,
}

unsafe extern "C" fn segment_cb(info: *mut dl_phdr_info, _size: size_t, data: *mut c_void) -> i32 {
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
        if header.p_flags & PF_R != 0 {
            prot |= Protection::READ;
        }
        if header.p_flags & PF_W != 0 {
            prot |= Protection::WRITE;
        }
        if header.p_flags & PF_X != 0 {
            prot |= Protection::EXECUTE;
        }

        if !cb(seg_data, prot) {
            return 0;
        }
    }
    1
}

pub fn module_at(address: *const u8) -> Option<Module> {
    unsafe {
        let mut dlinfo: Dl_info = std::mem::zeroed();
        if dladdr(address as *const c_void, &mut dlinfo) == 0 {
            return None;
        }
        let fbase = dlinfo.dli_fbase as usize;

        let mut module: Option<Module> = None;
        let mod_ptr = &mut module as *mut Option<Module>;

        let mut data = ModuleAtData { fbase, mod_ptr };
        dl_iterate_phdr(Some(module_at_cb), &mut data as *mut _ as *mut c_void);

        module
    }
}

struct ModuleAtData {
    fbase: usize,
    mod_ptr: *mut Option<Module>,
}

unsafe extern "C" fn module_at_cb(
    info: *mut dl_phdr_info,
    _size: size_t,
    data: *mut c_void,
) -> i32 {
    let cb = &mut *(data as *mut ModuleAtData);
    if (*info).dlpi_addr as usize == cb.fbase {
        *cb.mod_ptr = Some(Module::new(cb.fbase));
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
            if !prot_str.is_empty() && prot_str[0] == b'r' {
                p |= libc::PROT_READ as u32;
            }
            if prot_str.len() > 1 && prot_str[1] == b'w' {
                p |= libc::PROT_WRITE as u32;
            }
            if prot_str.len() > 2 && prot_str[2] == b'x' {
                p |= libc::PROT_EXEC as u32;
            }
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
