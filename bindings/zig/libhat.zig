const std = @import("std");

/// Build the shared library with:
/// ```bash
/// cargo build --release --lib
/// ```
///
/// Then link it in your `build.zig`:
/// ```zig
/// exe.linkSystemLibrary("hat");
/// exe.linkLibC();
/// ```
///
/// The library file will be:
/// - Linux:   `target/release/libhat.so`
/// - macOS:   `target/release/libhat.dylib`
/// - Windows: `target/release/hat.dll`

/// Status codes returned by libhat C functions.
pub const Status = enum(c_int) {
    success = 0,
    err_unknown = 1,
    err_sig_invalid = 2,
    err_sig_empty = 3,
    err_sig_no_byte = 4,
};

/// Alignment requirement for scan result addresses.
pub const ScanAlignment = enum(c_int) {
    x1 = 0,
    x16 = 1,
};

/// Errors that can occur during libhat operations.
pub const Error = error{
    Unknown,
    SignatureInvalid,
    SignatureEmpty,
    SignatureNoByte,
};

fn checkStatus(raw: c_int) Error!void {
    const status: Status = @enumFromInt(raw);
    return switch (status) {
        .success => {},
        .err_unknown => error.Unknown,
        .err_sig_invalid => error.SignatureInvalid,
        .err_sig_empty => error.SignatureEmpty,
        .err_sig_no_byte => error.SignatureNoByte,
    };
}

const OpaqueSignature = opaque {};

extern fn libhat_parse_signature(
    signature_str: [*:0]const u8,
    signature_out: *?*OpaqueSignature,
) c_int;

extern fn libhat_create_signature(
    bytes: [*]const u8,
    mask: [*]const u8,
    size: usize,
    signature_out: *?*OpaqueSignature,
) c_int;

extern fn libhat_find_pattern(
    signature: *const OpaqueSignature,
    buffer: *const anyopaque,
    size: usize,
    alignment: c_int,
) ?*anyopaque;

extern fn libhat_find_pattern_mod(
    signature: *const OpaqueSignature,
    module: *const anyopaque,
    section: [*:0]const u8,
    alignment: c_int,
) ?*anyopaque;

extern fn libhat_module_at(address: *const anyopaque) ?*anyopaque;

extern fn libhat_get_module(name: ?[*:0]const u8) ?*anyopaque;

extern fn libhat_free(mem: ?*anyopaque) void;

/// A compiled byte-pattern signature backed by a native heap allocation.
/// Must be freed with `deinit()` when no longer needed.
pub const Signature = struct {
    handle: *OpaqueSignature,

    /// Parse a signature from its string representation.
    pub fn parse(sig_str: [:0]const u8) Error!Signature {
        var handle: ?*OpaqueSignature = null;
        const rc = libhat_parse_signature(sig_str.ptr, &handle);
        try checkStatus(rc);
        return .{ .handle = handle.? };
    }

    /// Create a signature from raw bytes and a mask.
    /// Mask bytes of `0` indicate a wildcard (any byte matches).
    pub fn create(bytes: []const u8, mask: []const u8) Error!Signature {
        var handle: ?*OpaqueSignature = null;
        const rc = libhat_create_signature(bytes.ptr, mask.ptr, bytes.len, &handle);
        try checkStatus(rc);
        return .{ .handle = handle.? };
    }

    pub fn deinit(self: Signature) void {
        libhat_free(@as(*anyopaque, @ptrCast(self.handle)));
    }
};

/// Find the first occurrence of a signature in a byte buffer.
/// Returns a pointer to the match, or `null` if not found.
pub fn findPattern(
    signature: Signature,
    buffer: []const u8,
    alignment: ScanAlignment,
) ?[*]const u8 {
    const result = libhat_find_pattern(
        signature.handle,
        @ptrCast(buffer.ptr),
        buffer.len,
        @intFromEnum(alignment),
    ) orelse return null;
    return @as([*]const u8, @ptrCast(result));
}

/// Find the first occurrence of a signature in a specific section of a loaded module.
/// `module` is the module base address (returned by `getModule` or `moduleAt`).
pub fn findPatternMod(
    signature: Signature,
    module: *const anyopaque,
    section: [:0]const u8,
    alignment: ScanAlignment,
) ?*anyopaque {
    return libhat_find_pattern_mod(
        signature.handle,
        module,
        section.ptr,
        @intFromEnum(alignment),
    );
}

/// Get the base address of the module containing the given address.
pub fn moduleAt(address: *const anyopaque) ?*anyopaque {
    return libhat_module_at(address);
}

/// Get the base address of a loaded module by name.
/// If `name` is `null`, returns the main process module.
pub fn getModule(name: ?[:0]const u8) ?*anyopaque {
    return libhat_get_module(if (name) |n| n.ptr else null);
}

/// Get the main process module.
pub fn getProcessModule() ?*anyopaque {
    return getModule(null);
}
