use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::slice;

use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::VirtualQuery;
use windows_sys::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
    IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE,
};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION;

use crate::process::Module;
use crate::protection::Protection;

const PROT_READ: u32 = 1;
const PROT_WRITE: u32 = 2;
const PROT_EXEC: u32 = 4;

pub fn get_process_module() -> Option<Module> {
    get_module("")
}

pub fn get_module(name: &str) -> Option<Module> {
    unsafe {
        if name.is_empty() {
            let handle = GetModuleHandleW(std::ptr::null());
            if handle == 0 { return None; }
            let mut info = std::mem::zeroed::<MODULEINFO>();
            if GetModuleInformation(GetCurrentProcess(), handle, &mut info, std::mem::size_of_val(&info) as u32) == 0 {
                return None;
            }
            Some(Module::new(info.lpBaseOfDll as usize))
        } else {
            let wide: Vec<u16> = OsStr::new(name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let handle = GetModuleHandleW(wide.as_ptr());
            if handle == 0 { return None; }
            let mut info = std::mem::zeroed::<MODULEINFO>();
            if GetModuleInformation(GetCurrentProcess(), handle, &mut info, std::mem::size_of_val(&info) as u32) == 0 {
                return None;
            }
            Some(Module::new(info.lpBaseOfDll as usize))
        }
    }
}

unsafe fn get_nt_headers(base: usize) -> Option<*mut IMAGE_NT_HEADERS64> {
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != 0x5A4D { return None; }
    let nt = (base + (*dos).e_lfanew as usize) as *mut IMAGE_NT_HEADERS64;
    if (*nt).Signature != 0x00004550 { return None; }
    Some(nt)
}

pub fn get_module_data(module: &Module) -> &[u8] {
    unsafe {
        let base = module.address() as *const u8;
        let nt = match get_nt_headers(module.address()) {
            Some(h) => h,
            None => return &[],
        };
        let size = (*nt).OptionalHeader.SizeOfImage as usize;
        slice::from_raw_parts(base, size)
    }
}

pub fn get_section_data<'a>(module: &'a Module, name: &str) -> Option<&'a [u8]> {
    unsafe {
        let base = module.address();
        let nt = get_nt_headers(base)?;
        let sections = (nt as usize + std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        let num_sections = (*nt).FileHeader.NumberOfSections;

        for i in 0..num_sections {
            let section = sections.add(i as usize);
            let sec_name = std::slice::from_raw_parts((*section).Name.as_ptr(), 8);
            let sec_name_trimmed = std::str::from_utf8(sec_name)
                .unwrap_or("")
                .trim_end_matches('\0');
            if sec_name_trimmed == name {
                let data = slice::from_raw_parts(
                    (base + (*section).VirtualAddress as usize) as *const u8,
                    (*section).SizeOfRawData as usize,
                );
                return Some(data);
            }
        }
        None
    }
}

pub fn for_each_segment(module: &Module, callback: &mut dyn FnMut(&[u8], Protection) -> bool) {
    unsafe {
        let base = module.address();
        let nt = match get_nt_headers(base) {
            Some(h) => h,
            None => return,
        };
        let sections = (nt as usize + std::mem::size_of::<u32>() + std::mem::size_of::<IMAGE_NT_HEADERS64>())
            as *const IMAGE_SECTION_HEADER;
        let num_sections = (*nt).FileHeader.NumberOfSections;

        for i in 0..num_sections {
            let section = sections.add(i as usize);
            let data = slice::from_raw_parts(
                (base + (*section).VirtualAddress as usize) as *const u8,
                (*section).SizeOfRawData as usize,
            );

            let mut prot = Protection::empty();
            let charact = (*section).Characteristics;
            if charact & IMAGE_SCN_MEM_READ != 0 { prot |= Protection::READ; }
            if charact & IMAGE_SCN_MEM_WRITE != 0 { prot |= Protection::WRITE; }
            if charact & IMAGE_SCN_MEM_EXECUTE != 0 { prot |= Protection::EXECUTE; }

            if !callback(data, prot) {
                break;
            }
        }
    }
}

pub fn module_at(address: *const u8, _size: Option<usize>) -> Option<Module> {
    unsafe {
        let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let result = VirtualQuery(
            address as *const std::ffi::c_void,
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if result == 0 { return None; }
        let alloc_base = mbi.AllocationBase as usize;
        if alloc_base == 0 { return None; }

        let dos = alloc_base as *const IMAGE_DOS_HEADER;
        if (*dos).e_magic != 0x5A4D { return None; }
        let nt = (alloc_base + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
        if (*nt).Signature != 0x00004550 { return None; }

        Some(Module::new(alloc_base))
    }
}

pub fn region_has_flags(region: &[u8], flags: u32) -> bool {
    if region.is_empty() {
        return false;
    }

    let start = region.as_ptr() as usize;
    let end = start + region.len();
    let mut current = start;

    unsafe {
        while current < end {
            let mut mbi: MEMORY_BASIC_INFORMATION = std::mem::zeroed();
            let result = VirtualQuery(
                current as *const std::ffi::c_void,
                &mut mbi,
                std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            );
            if result == 0 { return false; }

            let region_start = mbi.BaseAddress as usize;
            let region_end = region_start + mbi.RegionSize;

            if current != region_start {
                return false;
            }

            let prot = mbi.Protect;
            let mut has_flags = false;
            if flags & PROT_READ != 0 {
                has_flags |= prot & (windows_sys::Win32::System::Memory::PAGE_READONLY
                    | windows_sys::Win32::System::Memory::PAGE_READWRITE
                    | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ
                    | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE) != 0;
            }
            if flags & PROT_WRITE != 0 {
                has_flags |= prot & (windows_sys::Win32::System::Memory::PAGE_READWRITE
                    | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE) != 0;
            }
            if flags & PROT_EXEC != 0 {
                has_flags |= prot & (windows_sys::Win32::System::Memory::PAGE_EXECUTE
                    | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ
                    | windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE) != 0;
            }

            if !has_flags { return false; }
            current = region_end;
        }
    }

    true
}
