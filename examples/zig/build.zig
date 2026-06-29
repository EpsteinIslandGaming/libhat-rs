const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const libhat = b.createModule(.{
        .root_source_file = b.path("../../bindings/zig/libhat.zig"),
    });

    const lib_path = b.path("../../target/release");

    {
        const exe = b.addExecutable(.{
            .name = "buffer",
            .root_module = b.createModule(.{
                .root_source_file = b.path("buffer/main.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        const m = exe.root_module;
        m.addImport("libhat", libhat);
        m.link_libc = true;
        m.addLibraryPath(lib_path);
        m.linkSystemLibrary("hat", .{});
        b.installArtifact(exe);
    }

    {
        const exe = b.addExecutable(.{
            .name = "module",
            .root_module = b.createModule(.{
                .root_source_file = b.path("module/main.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        const m = exe.root_module;
        m.addImport("libhat", libhat);
        m.link_libc = true;
        m.addLibraryPath(lib_path);
        m.linkSystemLibrary("hat", .{});
        b.installArtifact(exe);
    }
}
