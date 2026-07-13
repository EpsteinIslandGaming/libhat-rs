use std::ffi::CStr;
use std::slice;

use crate::process::Module;
use crate::protection::Protection;

const MH_MAGIC_64: u32 = 0xFEED_FACF; // macOS ts is NOT tuff
const LC_SEGMENT_64: u32 = 0x19;
const SECT_NAME_SIZE: usize = 16;

#[repr(C)]
struct MachHeader64 {
    magic: u32,
    cputype: u32,
    cpusubtype: u32,
    filetype: u32,
    ncmds: u32,
    sizeofcmds: u32,
    flags: u32,
    reserved: u32,
}

#[repr(C)]
struct Section64 {
    sectname: [i8; SECT_NAME_SIZE],
    segname: [i8; SECT_NAME_SIZE],
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

extern "C" {
    fn _dyld_image_count() -> u32;
    fn _dyld_get_image_header(image_index: u32) -> *const MachHeader64;
    fn _dyld_get_image_name(image_index: u32) -> *const libc::c_char;
    fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;

    fn mach_task_self_() -> libc::mach_port_t;
    fn mach_vm_region(
        target_task: libc::vm_map_t,
        address: *mut u64,
        size: *mut u64,
        flavor: i32,
        info: *mut u32,
        count: *mut u32,
        object_name: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;
}

fn header_is_valid(header: *const MachHeader64) -> bool {
    if header.is_null() {
        return false;
    }
    unsafe { (*header).magic == MH_MAGIC_64 }
}

fn find_image_index(addr: usize) -> Option<u32> {
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            if _dyld_get_image_header(i) as usize == addr {
                return Some(i);
            }
        }
        None
    }
}

fn slide_for_module(module: &Module) -> Option<isize> {
    Some(unsafe { _dyld_get_image_vmaddr_slide(find_image_index(module.address())?) })
}

fn get_image_name(index: u32) -> Option<String> {
    unsafe {
        let name = _dyld_get_image_name(index);
        if name.is_null() {
            return None;
        }
        CStr::from_ptr(name).to_str().ok().map(|s| s.to_string())
    }
}

fn module_from_index(index: u32) -> Option<Module> {
    unsafe {
        let header = _dyld_get_image_header(index);
        if !header_is_valid(header) {
            return None;
        }
        Some(Module::new(header as usize))
    }
}

fn cmds_slice(module: &Module) -> &[u8] {
    let addr = module.address();
    unsafe {
        let header = &*(addr as *const MachHeader64);
        slice::from_raw_parts(
            (addr + size_of::<MachHeader64>()) as *const u8,
            header.sizeofcmds as usize,
        )
    }
}

fn segment_data<'a>(seg: &libc::segment_command_64, slide: usize) -> &'a [u8] {
    unsafe {
        slice::from_raw_parts(
            (slide + seg.vmaddr as usize) as *const u8,
            seg.vmsize as usize,
        )
    }
}

fn segname_str(segname: &[libc::c_char; 16]) -> &str {
    let bytes = unsafe { slice::from_raw_parts(segname.as_ptr() as *const u8, 16) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(16);
    std::str::from_utf8(&bytes[..end]).unwrap_or("")
}

pub fn get_process_module() -> Option<Module> {
    module_from_index(0)
}

pub fn get_module(name: &str) -> Option<Module> {
    if name.is_empty() {
        return get_process_module();
    }
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let img_name = match get_image_name(i) {
                Some(n) => n,
                None => continue,
            };
            let fname = img_name.rsplit('/').next().unwrap_or(&img_name);
            if img_name.contains(name) || fname == name {
                return module_from_index(i);
            }
        }
        None
    }
}

pub fn get_module_data(module: &Module) -> &[u8] {
    let slide = match slide_for_module(module) {
        Some(s) => s as usize,
        None => return &[],
    };
    let addr = module.address();
    let cmds = cmds_slice(module);

    let mut max_end: usize = 0;
    let mut i = 0;
    while i + size_of::<libc::load_command>() <= cmds.len() {
        let lc = unsafe { &*(cmds.as_ptr().add(i) as *const libc::load_command) };
        if lc.cmdsize == 0 || i + lc.cmdsize as usize > cmds.len() {
            break;
        }
        if lc.cmd == LC_SEGMENT_64 {
            let seg_size = size_of::<libc::segment_command_64>();
            if i + seg_size <= cmds.len() {
                let seg =
                    unsafe { &*(cmds.as_ptr().add(i) as *const libc::segment_command_64) };
                if seg.vmsize > 0 && segname_str(&seg.segname) != "__PAGEZERO" {
                    let end = slide + seg.vmaddr as usize + seg.vmsize as usize;
                    if end > max_end {
                        max_end = end;
                    }
                }
            }
        }
        i += lc.cmdsize as usize;
    }

    if max_end <= addr {
        return &[];
    }
    unsafe { slice::from_raw_parts(addr as *const u8, max_end - addr) }
}

fn section_matches(sec: &Section64, name: &str) -> bool {
    let sname = segname_str(&sec.sectname);
    if sname == name {
        return true;
    }
    let gname = segname_str(&sec.segname);
    let qualified = format!("{},{}", gname, sname);
    qualified == name
}

pub fn get_section_data<'a>(module: &'a Module, name: &str) -> Option<&'a [u8]> {
    let slide = slide_for_module(module)? as usize;
    let cmds = cmds_slice(module);

    let mut i = 0;
    while i + size_of::<libc::load_command>() <= cmds.len() {
        let lc = unsafe { &*(cmds.as_ptr().add(i) as *const libc::load_command) };
        if lc.cmdsize == 0 || i + lc.cmdsize as usize > cmds.len() {
            break;
        }
        if lc.cmd == LC_SEGMENT_64 {
            let seg_size = size_of::<libc::segment_command_64>();
            if i + seg_size <= cmds.len() {
                let seg =
                    unsafe { &*(cmds.as_ptr().add(i) as *const libc::segment_command_64) };
                let sec_base = i + seg_size;
                let sec_total = seg.nsects as usize * size_of::<Section64>();
                if sec_base + sec_total <= i + lc.cmdsize as usize {
                    for j in 0..seg.nsects as usize {
                        let sec_off = sec_base + j * size_of::<Section64>();
                        let sec =
                            unsafe { &*(cmds.as_ptr().add(sec_off) as *const Section64) };
                        if section_matches(sec, name) && sec.size > 0 {
                            return unsafe {
                                Some(slice::from_raw_parts(
                                    (slide + sec.addr as usize) as *const u8,
                                    sec.size as usize,
                                ))
                            };
                        }
                    }
                }
            }
        }
        i += lc.cmdsize as usize;
    }
    None
}

fn segment_protection(initprot: libc::vm_prot_t) -> Protection {
    let mut p = Protection::empty();
    if initprot & libc::VM_PROT_READ != 0 {
        p |= Protection::READ;
    }
    if initprot & libc::VM_PROT_WRITE != 0 {
        p |= Protection::WRITE;
    }
    if initprot & libc::VM_PROT_EXECUTE != 0 {
        p |= Protection::EXECUTE;
    }
    p
}

pub fn for_each_segment(module: &Module, callback: &mut dyn FnMut(&[u8], Protection) -> bool) {
    let slide = match slide_for_module(module) {
        Some(s) => s as usize,
        None => return,
    };
    let cmds = cmds_slice(module);

    let mut i = 0;
    while i + size_of::<libc::load_command>() <= cmds.len() {
        let lc = unsafe { &*(cmds.as_ptr().add(i) as *const libc::load_command) };
        if lc.cmdsize == 0 || i + lc.cmdsize as usize > cmds.len() {
            break;
        }
        if lc.cmd == LC_SEGMENT_64 {
            let seg_size = size_of::<libc::segment_command_64>();
            if i + seg_size <= cmds.len() {
                let seg =
                    unsafe { &*(cmds.as_ptr().add(i) as *const libc::segment_command_64) };
                if seg.vmsize > 0 {
                    let data = segment_data(seg, slide);
                    if !callback(data, segment_protection(seg.initprot)) {
                        return;
                    }
                }
            }
        }
        i += lc.cmdsize as usize;
    }
}

pub fn get_executable_data(module: &Module) -> &[u8] {
    if let Some(text) = get_section_data(module, ".text") {
        return text;
    }

    let slide = match slide_for_module(module) {
        Some(s) => s as usize,
        None => return &[],
    };
    let cmds = cmds_slice(module);

    let mut i = 0;
    while i + size_of::<libc::load_command>() <= cmds.len() {
        let lc = unsafe { &*(cmds.as_ptr().add(i) as *const libc::load_command) };
        if lc.cmdsize == 0 || i + lc.cmdsize as usize > cmds.len() {
            break;
        }
        if lc.cmd == LC_SEGMENT_64 {
            let seg_size = size_of::<libc::segment_command_64>();
            if i + seg_size <= cmds.len() {
                let seg =
                    unsafe { &*(cmds.as_ptr().add(i) as *const libc::segment_command_64) };
                if seg.vmsize > 0 && segname_str(&seg.segname) != "__PAGEZERO" {
                    let prot = segment_protection(seg.initprot);
                    if prot.contains(Protection::READ) && !prot.contains(Protection::WRITE) && prot.contains(Protection::EXECUTE) {
                        return segment_data(seg, slide);
                    }
                }
            }
        }
        i += lc.cmdsize as usize;
    }
    &[]
}

pub fn for_each_section(module: &Module, callback: &mut dyn FnMut(&str, &[u8], Protection) -> bool) {
    let slide = match slide_for_module(module) {
        Some(s) => s as usize,
        None => return,
    };
    let cmds = cmds_slice(module);

    let mut i = 0;
    while i + size_of::<libc::load_command>() <= cmds.len() {
        let lc = unsafe { &*(cmds.as_ptr().add(i) as *const libc::load_command) };
        if lc.cmdsize == 0 || i + lc.cmdsize as usize > cmds.len() {
            break;
        }
        if lc.cmd == LC_SEGMENT_64 {
            let seg_size = size_of::<libc::segment_command_64>();
            if i + seg_size <= cmds.len() {
                let seg =
                    unsafe { &*(cmds.as_ptr().add(i) as *const libc::segment_command_64) };
                let sec_base = i + seg_size;
                let sec_total = seg.nsects as usize * size_of::<Section64>();
                if sec_base + sec_total <= i + lc.cmdsize as usize {
                    for j in 0..seg.nsects as usize {
                        let sec_off = sec_base + j * size_of::<Section64>();
                        let sec =
                            unsafe { &*(cmds.as_ptr().add(sec_off) as *const Section64) };
                        if sec.size > 0 {
                            let sname = segname_str(&sec.sectname);
                            let gname = segname_str(&sec.segname);
                            let data = unsafe {
                                slice::from_raw_parts(
                                    (slide + sec.addr as usize) as *const u8,
                                    sec.size as usize,
                                )
                            };
                            let mut prot = segment_protection(seg.initprot);
                            if sec.flags & 0x800 != 0 { prot |= Protection::READ; }
                            if sec.flags & 0x400 != 0 { prot |= Protection::WRITE; }
                            if sec.flags & 0x200 != 0 { prot |= Protection::EXECUTE; }
                            if !callback(sname, data, prot) {
                                return;
                            }
                        }
                    }
                }
            }
        }
        i += lc.cmdsize as usize;
    }
}

pub fn module_at(address: *const u8) -> Option<Module> {
    let target = address as usize;
    unsafe {
        let count = _dyld_image_count();
        for i in 0..count {
            let header = _dyld_get_image_header(i);
            if !header_is_valid(header) {
                continue;
            }
            let module = Module::new(header as usize);
            let slide = match slide_for_module(&module) {
                Some(s) => s as usize,
                None => continue,
            };
            let cmds = cmds_slice(&module);
            let mut found = false;
            let mut j = 0;
            while j + size_of::<libc::load_command>() <= cmds.len() {
                let lc = &*(cmds.as_ptr().add(j) as *const libc::load_command);
                if lc.cmdsize == 0 || j + lc.cmdsize as usize > cmds.len() {
                    break;
                }
                if lc.cmd == LC_SEGMENT_64 {
                    let seg_size = size_of::<libc::segment_command_64>();
                    if j + seg_size <= cmds.len() {
                        let seg =
                            &*(cmds.as_ptr().add(j) as *const libc::segment_command_64);
                        if seg.vmsize > 0 {
                            let seg_start = slide + seg.vmaddr as usize;
                            let seg_end = seg_start + seg.vmsize as usize;
                            if target >= seg_start && target < seg_end {
                                found = true;
                                break;
                            }
                        }
                    }
                }
                j += lc.cmdsize as usize;
            }
            if found {
                return Some(module);
            }
        }
        None
    }
}

pub fn region_has_flags(region: &[u8], flags: u32) -> bool {
    if region.is_empty() {
        return false;
    }

    let start = region.as_ptr() as u64;
    let end = start + region.len() as u64;
    let mut current = start;

    unsafe {
        let task = mach_task_self_();
        let flavor: i32 = 9;
        let mut info = [0u32; 16];

        while current < end {
            let mut addr = current;
            let mut size: u64 = 0;
            let mut count = 16u32;
            let mut object_name: libc::mach_port_t = 0;

            let kr = mach_vm_region(
                task,
                &mut addr,
                &mut size,
                flavor,
                &mut info as *mut u32,
                &mut count,
                &mut object_name,
            );

            if kr != 0 {
                return false;
            }

            if current < addr {
                return false;
            }

            let prot = info[0];

            let need_read = flags & libc::PROT_READ as u32;
            let need_write = flags & libc::PROT_WRITE as u32;
            let need_exec = flags & libc::PROT_EXEC as u32;

            if (need_read != 0 && (prot & libc::VM_PROT_READ as u32) == 0)
                || (need_write != 0 && (prot & libc::VM_PROT_WRITE as u32) == 0)
                || (need_exec != 0 && (prot & libc::VM_PROT_EXECUTE as u32) == 0)
            {
                return false;
            }

            current = addr + size;
        }
    }

    true
}
