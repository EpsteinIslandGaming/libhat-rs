const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.createModule(.{
        .root_source_file = b.path("libhat.zig"),
    });
}
