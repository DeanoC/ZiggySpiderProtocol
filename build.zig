const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addModule("ziggy-spider-protocol", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    const spiderweb_fs = b.addModule("spiderweb_fs", .{
        .root_source_file = b.path("src/spiderweb_fs/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_fs.addImport("ziggy-spider-protocol", lib);

    const spiderweb_node = b.addModule("spiderweb_node", .{
        .root_source_file = b.path("src/spiderweb_node/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_node.addImport("ziggy-spider-protocol", lib);
    spiderweb_node.addImport("spiderweb_fs", spiderweb_fs);

    const lib_tests = b.addTest(.{ .root_module = lib });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);
}
