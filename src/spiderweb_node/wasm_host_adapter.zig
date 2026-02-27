const std = @import("std");

pub const default_runner: []const u8 = "wasmtime";

pub const Config = struct {
    module_path: []const u8,
    entrypoint: ?[]const u8 = null,
    runner_path: ?[]const u8 = null,
    args: []const []const u8 = &.{},
};

pub fn validateConfig(config: Config) !void {
    if (!isSafeToken(config.module_path)) return error.InvalidWasmHostConfig;
    if (config.runner_path) |runner| {
        if (!isSafeToken(runner)) return error.InvalidWasmHostConfig;
    }
    if (config.entrypoint) |entrypoint| {
        if (!isSafeEntrypoint(entrypoint)) return error.InvalidWasmHostConfig;
    }
    for (config.args) |arg| {
        if (!isSafeToken(arg)) return error.InvalidWasmHostConfig;
    }
}

pub fn appendRunArgv(
    allocator: std.mem.Allocator,
    config: Config,
    out: *std.ArrayListUnmanaged([]const u8),
) !void {
    try validateConfig(config);

    const runner = if (config.runner_path) |value| value else default_runner;
    try out.append(allocator, runner);
    try out.append(allocator, "run");
    if (config.entrypoint) |entrypoint| {
        try out.append(allocator, "--invoke");
        try out.append(allocator, entrypoint);
    }
    try out.append(allocator, config.module_path);
    for (config.args) |arg| {
        try out.append(allocator, arg);
    }
}

fn isSafeToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |ch| {
        if (ch == 0 or ch == '\n' or ch == '\r') return false;
    }
    return true;
}

fn isSafeEntrypoint(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |ch| {
        if (std.ascii.isAlphanumeric(ch)) continue;
        if (ch == '_' or ch == '-' or ch == '.' or ch == ':') continue;
        return false;
    }
    return true;
}

test "wasm_host_adapter: validates fields" {
    try std.testing.expectError(error.InvalidWasmHostConfig, validateConfig(.{
        .module_path = "",
    }));
    try std.testing.expectError(error.InvalidWasmHostConfig, validateConfig(.{
        .module_path = "module.wasm",
        .entrypoint = "bad name",
    }));
    try std.testing.expectError(error.InvalidWasmHostConfig, validateConfig(.{
        .module_path = "module.wasm",
        .runner_path = "bad\nrunner",
    }));
}

test "wasm_host_adapter: builds runner argv" {
    const allocator = std.testing.allocator;
    var argv = std.ArrayListUnmanaged([]const u8){};
    defer argv.deinit(allocator);

    try appendRunArgv(allocator, .{
        .module_path = "drivers/pdf.wasm",
        .entrypoint = "invoke",
        .runner_path = "wasmtime",
        .args = &.{ "--dir", "." },
    }, &argv);

    try std.testing.expectEqual(@as(usize, 7), argv.items.len);
    try std.testing.expectEqualStrings("wasmtime", argv.items[0]);
    try std.testing.expectEqualStrings("run", argv.items[1]);
    try std.testing.expectEqualStrings("--invoke", argv.items[2]);
    try std.testing.expectEqualStrings("invoke", argv.items[3]);
    try std.testing.expectEqualStrings("drivers/pdf.wasm", argv.items[4]);
    try std.testing.expectEqualStrings("--dir", argv.items[5]);
    try std.testing.expectEqualStrings(".", argv.items[6]);
}
