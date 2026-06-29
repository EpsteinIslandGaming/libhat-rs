const std = @import("std");
const libhat = @import("libhat");

pub fn main() !void {
    const data = [_]u8{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8D, 0x05, 0xBE, 0x53, 0x23, 0x01,
        0xE8, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x8B, 0x8D, 0x00, 0x00, 0x00, 0x00,
    };
    const buf = data[0..];

    // Parse a signature string and find it in the buffer.
    const sig = try libhat.Signature.parse("48 8D 05 ? ? ? ? E8");
    defer sig.deinit();

    if (libhat.findPattern(sig, buf, .x1)) |match| {
        const offset = @intFromPtr(match) - @intFromPtr(buf.ptr);
        std.debug.print("Found at offset: {d}\n", .{offset});
        std.debug.print("Match hex: ", .{});
        for (buf[offset..offset + 8]) |byte| {
            std.debug.print("{x:0>2} ", .{byte});
        }
        std.debug.print("\n", .{});
    } else {
        std.debug.print("Not found\n", .{});
    }

    // Create a signature from bytes and a mask, then search.
    const bytes = [_]u8{ 0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xE8 };
    const mask = [_]u8{ 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF };
    const sig2 = try libhat.Signature.create(&bytes, &mask);
    defer sig2.deinit();

    if (libhat.findPattern(sig2, buf, .x1)) |match| {
        const offset = @intFromPtr(match) - @intFromPtr(buf.ptr);
        std.debug.print("Found (create) at offset: {d}\n", .{offset});
    }
}
