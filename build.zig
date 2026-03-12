const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const zwasm = b.dependency("zwasm", .{
        .target = target,
        .optimize = optimize,
        .jit = false,
    });

    const lib = b.addModule("spider-protocol", .{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.addImport("zwasm", zwasm.module("zwasm"));
    const spiderweb_fs = b.addModule("spiderweb_fs", .{
        .root_source_file = b.path("src/spiderweb_fs/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_fs.addImport("spider-protocol", lib);

    const spiderweb_node = b.addModule("spiderweb_node", .{
        .root_source_file = b.path("src/spiderweb_node/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    spiderweb_node.addImport("spider-protocol", lib);
    spiderweb_node.addImport("spiderweb_fs", spiderweb_fs);
    spiderweb_node.addImport("zwasm", zwasm.module("zwasm"));

    const lib_tests = b.addTest(.{ .root_module = lib });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const sdk_artifacts_module = b.createModule(.{
        .root_source_file = b.path("src/sdk_artifacts.zig"),
        .target = target,
        .optimize = optimize,
    });
    const sdk_artifacts_tests = b.addTest(.{ .root_module = sdk_artifacts_module });
    const run_sdk_artifacts_tests = b.addRunArtifact(sdk_artifacts_tests);

    const sync_sdk_module = b.createModule(.{
        .root_source_file = b.path("src/sdk_sync_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const sync_sdk_exe = b.addExecutable(.{
        .name = "spider-protocol-sync",
        .root_module = sync_sdk_module,
    });
    sync_sdk_exe.root_module.addImport("spider-protocol", lib);
    sync_sdk_exe.root_module.addImport("spiderweb_fs", spiderweb_fs);
    sync_sdk_exe.root_module.addImport("spiderweb_node", spiderweb_node);
    const run_sync_sdk = b.addRunArtifact(sync_sdk_exe);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_sdk_artifacts_tests.step);

    const sync_sdk_step = b.step("sync-sdk", "Generate protocol spec, fixtures, docs, and generated SDK constants");
    sync_sdk_step.dependOn(&run_sync_sdk.step);
}
