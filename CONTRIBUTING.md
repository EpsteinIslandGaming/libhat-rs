# Contributing

## Project structure

| Path             | Description                                                          |
|------------------|----------------------------------------------------------------------|
| `src/`           | Rust source (scanners, signature parsing, OS process modules, C API) |
| `libhat-macros/` | Proc-macro crate for compile-time `sig!("...")` expansion            |
| `include/`       | C and C++ binding headers                                            |
| `module/`        | C++20 module interface                                               |
| `bindings/cs/`   | C# P/Invoke bindings                                                 |
| `bindings/java/` | Java JNA bindings                                                    |
| `benches/`       | Criterion benchmarks                                                 |
