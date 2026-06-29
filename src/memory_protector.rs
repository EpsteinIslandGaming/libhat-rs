use crate::protection::Protection;
use crate::system;

pub struct MemoryProtector {
    address: usize,
    size: usize,
    old_protection: u32,
    set: bool,
}

impl MemoryProtector {
    pub fn new(address: usize, size: usize, flags: Protection) -> Self {
        let mut prot = MemoryProtector {
            address,
            size,
            old_protection: 0,
            set: false,
        };

        #[cfg(target_os = "linux")]
        {
            prot.init_linux(flags);
        }

        #[cfg(windows)]
        {
            prot.init_windows(flags);
        }

        prot
    }

    #[cfg(target_os = "linux")]
    fn init_linux(&mut self, flags: Protection) {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let page_size = system::get_system().page_size;
        let page_start = self.address & !(page_size - 1);
        let mapped_size = (self.address + self.size - page_start + page_size - 1) & !(page_size - 1);

        let file = match File::open("/proc/self/maps") {
            Ok(f) => f,
            Err(_) => return,
        };

        let mut old_prot: Option<u32> = None;
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => continue,
            };
            let parts: Vec<&str> = line.splitn(5, ' ').collect();
            if parts.len() < 2 { continue; }
            let range: Vec<&str> = parts[0].split('-').collect();
            if range.len() != 2 { continue; }
            let begin = usize::from_str_radix(range[0], 16).unwrap_or(0);
            let end_range = usize::from_str_radix(range[1], 16).unwrap_or(0);
            if page_start >= begin && page_start < end_range {
                let prot_str = parts[1].as_bytes();
                let mut p = 0u32;
                if !prot_str.is_empty() && prot_str[0] == b'r' { p |= libc::PROT_READ as u32; }
                if prot_str.len() > 1 && prot_str[1] == b'w' { p |= libc::PROT_WRITE as u32; }
                if prot_str.len() > 2 && prot_str[2] == b'x' { p |= libc::PROT_EXEC as u32; }
                old_prot = Some(p);
                break;
            }
        }

        let old_prot = match old_prot {
            Some(p) => p,
            None => return,
        };

        let mut new_prot = 0i32;
        if flags.contains(Protection::READ) { new_prot |= libc::PROT_READ; }
        if flags.contains(Protection::WRITE) { new_prot |= libc::PROT_WRITE; }
        if flags.contains(Protection::EXECUTE) { new_prot |= libc::PROT_EXEC; }

        let result = unsafe {
            libc::mprotect(page_start as *mut libc::c_void, mapped_size, new_prot)
        };

        if result == 0 {
            self.old_protection = old_prot;
            self.set = true;
        }
    }

    #[cfg(windows)]
    fn init_windows(&mut self, flags: Protection) {
        use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_PROTECTION_FLAGS};
        use windows_sys::Win32::System::Memory::{
            PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
        };

        let mut old_prot: u32 = 0;
        let mut new_prot: u32 = 0;

        if flags.contains(Protection::EXECUTE) {
            if flags.contains(Protection::WRITE) {
                new_prot = PAGE_EXECUTE_READWRITE;
            } else if flags.contains(Protection::READ) {
                new_prot = PAGE_EXECUTE_READ;
            } else {
                new_prot = PAGE_EXECUTE;
            }
        } else if flags.contains(Protection::WRITE) {
            new_prot = PAGE_READWRITE;
        } else if flags.contains(Protection::READ) {
            new_prot = PAGE_READONLY;
        }

        let result = unsafe {
            VirtualProtect(
                self.address as *const std::ffi::c_void,
                self.size,
                new_prot,
                &mut old_prot,
            )
        };

        if result != 0 {
            self.old_protection = old_prot;
            self.set = true;
        }
    }

    pub fn is_set(&self) -> bool {
        self.set
    }

    fn restore(&mut self) {
        if !self.set {
            return;
        }

        #[cfg(target_os = "linux")]
        {
            let page_size = system::get_system().page_size;
            let page_start = self.address & !(page_size - 1);
            let mapped_size = (self.address + self.size - page_start + page_size - 1) & !(page_size - 1);
            unsafe {
                libc::mprotect(
                    page_start as *mut libc::c_void,
                    mapped_size,
                    self.old_protection as i32,
                );
            }
        }

        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Memory::VirtualProtect;
            let mut old: u32 = 0;
            unsafe {
                VirtualProtect(
                    self.address as *const std::ffi::c_void,
                    self.size,
                    self.old_protection,
                    &mut old,
                );
            }
        }

        self.set = false;
    }
}

impl Drop for MemoryProtector {
    fn drop(&mut self) {
        self.restore();
    }
}
