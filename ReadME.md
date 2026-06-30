# libhat-rs

A Rust rewrite of [libhat](https://github.com/BasedInc/libhat), a high-performance byte-pattern scanning library for game hacking,
Rewritten from C++20 to Rust with matching C, C++, C#, Java, Python, and Zig bindings.

## Why?

C and C++ are both fake languages.
Rust gives memory safety and is overall 20x better than those languages,
the project offers C/C++ bindings if you really don't want to rewrite your stuff in Rust
(not memory leaking is worth an entire rewrite).

## Feature overview

- Cross-platform (Linux, Windows, macOS)
- Vectorized scanning for byte patterns using CPU SIMD intrinsics:
  - SSE 4.1 and AVX2 on x86/x64 (`std::arch`)
  - AVX-512 on x64 (optional feature `avx512`)
  - NEON on ARM
  - Scalar fallback
- Compile-time signature parsing via proc-macro (`libhat-macros`)
- C API exported as a `cdylib` for FFI from any language
- C++ binding headers wrapping the C API
- C# bindings (P/Invoke)
- Java bindings (JNA)
- Criterion benchmarks

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
libhat = { git = "https://github.com/EpsteinIslandGaming/libhat-rs.git" }
libhat-macros = { git = "https://github.com/EpsteinIslandGaming/libhat-rs.git" }
```

Basic scanning:

```rust
use libhat::{find_pattern, sig};

fn main() {
  let data: &[u8] = &[0x48, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01];
  let signature = sig!("48 8D 05 ? ? ? ?");

  let result = find_pattern(data, &signature);
  if let Some(addr) = result {
    println!("Found at offset: {}", addr as usize - data.as_ptr() as usize);
  }
}
```

## Language bindings

The shared library (`libhat.so` / `libhat.dylib` / `hat.dll`) exports a `extern "C"` API.
Headers and bindings are in the `bindings/` directory, and their examples are in the `examples/` directory.

### C API (`bindings/c/libhat.h`)

[Module Example](examples/c/module/main.c)
[Buffer Example](examples/c/buffer/main.c)

### C++ API (`bindings/cpp/libhat.hpp`)

[Example](examples/cpp/header/main.cpp)

### C++20 module (`bindings/cpp/module/libhat.cppm`)

[Example](examples/cpp/module/main.cpp)

### C# bindings (`bindings/cs/`)

[Buffer Example](examples/cs/buffer/Program.cs)
[Module Example](examples/cs/module/Program.cs)

### Java bindings (`bindings/java/`)

[Example](examples/java/HatExample.java)

### Python bindings (`bindings/python/`)

[Example](examples/python/basic.py)

### Zig bindings (`bindings/zig/`)

- [Scanning in a module](examples/zig/module/main.zig)
- [Scanning a buffer](examples/zig/buffer/main.zig)

## Pattern/Signature syntax

LibHat's signature syntax consists of space-delimited tokens and is backwards compatible with IDA syntax:

- 8 character sequences are interpreted as binary
- 2 character sequences are interpreted as hex
- 1 character must be a wildcard (`?`)

Any digit can be substituted for a wildcard, for example:
- `????1111` is a binary sequence, and matches any byte with all ones in the lower nibble
- `A?` is a hex sequence, and matches any byte of the form `1010????`
- Both `????????` and `??` are equivalent to `?`, and will match any byte

A complete pattern might look like `AB ? 12 ?3`. This matches any 4-byte
subrange `s` for which all the following conditions are met:
- `s[0] == 0xAB`
- `s[2] == 0x12`
- `s[3] & 0x0F == 0x03`

As a scanning optimization, all patterns are required to have at least one fully masked byte. Attempting to find a
pattern that does not meet this requirement will result in undefined behavior. Additionally, it is recommended
(but not required) that patterns contain at least 2 consecutive fully masked bytes, as this will greatly speed
up the vectorized scanning algorithms.
- `?1 02` is allowed
- `?? 02` is allowed
- `01 02` is allowed (*and recommended*)

## Platform support


| API                        | Linux | Windows | macOS |
|----------------------------|:-----:|:-------:|:-----:|
| `get_process_module`       |   ✅  |    ✅    |  ✅  |
| `get_module`               |   ✅  |    ✅    |  ✅  |
| `module::get_section_data` |   ✅  |    ✅    |  ✅  |
| Scanning (SSE/AVX2)        |   ✅  |    ✅    |  ✅  |

## Versioning

This project adheres to [semantic versioning](https://semver.org/spec/v2.0.0.html).
