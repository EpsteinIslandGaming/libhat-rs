#[cfg(target_arch = "x86_64")]
pub mod sse;
#[cfg(target_arch = "x86_64")]
pub mod avx2;
#[cfg(target_arch = "x86_64")]
pub mod avx512;
