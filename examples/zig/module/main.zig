const std = @import("std");
const libhat = @import("libhat");

pub fn main() !void {
    const mod = libhat.getProcessModule() orelse {
        std.debug.print("Could not get process module\n", .{});
        return;
    };
    std.debug.print("Process module at: 0x{x:0>16}\n", .{@intFromPtr(mod)});

    const mod_at = libhat.moduleAt(mod) orelse {
        std.debug.print("module_at returned null\n", .{});
        return;
    };
    _ = mod_at;

    const sig = try libhat.Signature.parse("48 89 5C 24 ? 48 89 6C 24 ?");
    defer sig.deinit();

    if (libhat.findPatternMod(sig, mod, ".text", .x1)) |result| {
        std.debug.print("Found pattern in .text at: 0x{x:0>16}\n", .{@intFromPtr(result)});
    } else {
        std.debug.print("Pattern not found in .text\n", .{});
    }
}
