#![allow(dead_code)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::type_complexity)]

pub mod access;
pub mod protection;
pub mod signature;
pub mod result;
pub mod scanner;
pub mod system;

pub mod process;
pub mod memory_protector;

mod arch;
mod frequency;
pub mod c;

pub use access::member_at;
pub use protection::Protection;
pub use signature::{SignatureElement, Signature, SignatureView, FixedSignature};
pub use signature::{compile_signature, parse_signature, parse_signature_to, to_string};
pub use signature::SignatureError as signature_error;
pub use result::ScanResult;
pub use scanner::{ScanAlignment, ScanHint, find_pattern, find_all_pattern};

/// Compile-time signature parsing macro.
///
/// Parses a signature string at compile time, producing a `&'static [SignatureElement]`.
/// This avoids runtime parsing overhead and allocation.
///
/// # Example
/// ```
/// # use hat::signature::parse_signature;
/// let sig = hat::sig!("48 8D 05 ? ? ? ? E8");
/// assert_eq!(sig.len(), 8);
/// ```
pub use libhat_macros::sig;
