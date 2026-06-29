use crate::protection::Protection;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module {
    base_address: usize,
}

impl Module {
    pub fn new(base_address: usize) -> Self {
        Module { base_address }
    }

    pub fn address(&self) -> usize {
        self.base_address
    }

    pub fn get_module_data(&self) -> &[u8] {
        get_module_data_impl(self)
    }

    pub fn get_section_data<'a>(&'a self, name: &str) -> Option<&'a [u8]> {
        get_section_data_impl(self, name)
    }

    pub fn for_each_segment(&self, callback: &mut dyn FnMut(&[u8], Protection) -> bool) {
        for_each_segment_impl(self, callback)
    }
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
use linux as platform;

#[cfg(windows)]
mod windows;

#[cfg(windows)]
use windows as platform;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
use macos as platform;

fn get_module_data_impl(module: &Module) -> &[u8] {
    platform::get_module_data(module)
}

fn get_section_data_impl<'a>(module: &'a Module, name: &str) -> Option<&'a [u8]> {
    platform::get_section_data(module, name)
}

fn for_each_segment_impl(module: &Module, callback: &mut dyn FnMut(&[u8], Protection) -> bool) {
    platform::for_each_segment(module, callback)
}

pub fn get_process_module() -> Option<Module> {
    platform::get_process_module()
}

pub fn get_module(name: &str) -> Option<Module> {
    platform::get_module(name)
}

pub fn module_at(address: *const u8, size: Option<usize>) -> Option<Module> {
    platform::module_at(address, size)
}

pub fn is_readable(_region: &[u8]) -> bool {
    #[cfg(unix)]
    { platform::region_has_flags(_region, libc::PROT_READ as u32) }
    #[cfg(not(unix))]
    { false }
}

pub fn is_writable(_region: &[u8]) -> bool {
    #[cfg(unix)]
    { platform::region_has_flags(_region, libc::PROT_WRITE as u32) }
    #[cfg(not(unix))]
    { false }
}

pub fn is_executable(_region: &[u8]) -> bool {
    #[cfg(unix)]
    { platform::region_has_flags(_region, libc::PROT_EXEC as u32) }
    #[cfg(not(unix))]
    { false }
}
