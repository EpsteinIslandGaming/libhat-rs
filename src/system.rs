pub struct SystemInfo {
    pub page_size: usize,
}

#[cfg(unix)]
fn get_page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

#[cfg(windows)]
fn get_page_size() -> usize {
    use std::mem;
    unsafe {
        let mut info: windows_sys::Win32::System::SystemInformation::SYSTEM_INFO =
            mem::zeroed();
        windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut info);
        info.dwPageSize as usize
    }
}

impl SystemInfo {
    pub fn new() -> Self {
        SystemInfo {
            page_size: get_page_size(),
        }
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Debug)]
pub struct CpuExtensions {
    pub sse41: bool,
    pub avx2: bool,
    pub avx512f: bool,
    pub avx512bw: bool,
    pub bmi: bool,
}

#[cfg(target_arch = "x86_64")]
fn detect_cpu_extensions() -> CpuExtensions {
    CpuExtensions {
        sse41: is_x86_feature_detected!("sse4.1"),
        avx2: is_x86_feature_detected!("avx2"),
        avx512f: is_x86_feature_detected!("avx512f"),
        avx512bw: is_x86_feature_detected!("avx512bw"),
        bmi: is_x86_feature_detected!("bmi1") | is_x86_feature_detected!("bmi2"),
    }
}

use std::sync::OnceLock;

#[cfg(target_arch = "x86_64")]
struct SystemInfoHolder {
    base: SystemInfo,
    extensions: CpuExtensions,
}

#[cfg(target_arch = "x86_64")]
static SYSTEM_INFO_X86: OnceLock<SystemInfoHolder> = OnceLock::new();

#[cfg(target_arch = "x86_64")]
pub fn get_system_x86() -> &'static CpuExtensions {
    let holder = SYSTEM_INFO_X86.get_or_init(|| SystemInfoHolder {
        base: SystemInfo::new(),
        extensions: detect_cpu_extensions(),
    });
    &holder.extensions
}

#[cfg(not(target_arch = "x86_64"))]
static SYSTEM_INFO: OnceLock<SystemInfo> = OnceLock::new();

pub fn get_system() -> &'static SystemInfo {
    #[cfg(target_arch = "x86_64")]
    {
        let holder = SYSTEM_INFO_X86.get_or_init(|| SystemInfoHolder {
            base: SystemInfo::new(),
            extensions: detect_cpu_extensions(),
        });
        &holder.base
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        SYSTEM_INFO.get_or_init(SystemInfo::new)
    }
}
