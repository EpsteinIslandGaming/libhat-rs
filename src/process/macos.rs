use crate::process::Module;
use crate::protection::Protection;

pub fn get_process_module() -> Option<Module> {
    None
}

pub fn get_module(_name: &str) -> Option<Module> {
    None
}

pub fn get_module_data<'a>(_module: &'a Module) -> &'a [u8] {
    &[]
}

pub fn get_section_data<'a>(_module: &'a Module, _name: &str) -> Option<&'a [u8]> {
    None
}

pub fn for_each_segment(_module: &Module, _callback: &mut dyn FnMut(&[u8], Protection) -> bool) {}

pub fn module_at(_address: *const u8, _size: Option<usize>) -> Option<Module> {
    None
}

pub fn region_has_flags(_region: &[u8], _flags: u32) -> bool {
    false
}
