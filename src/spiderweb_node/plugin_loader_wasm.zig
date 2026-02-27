const std = @import("std");

pub const WasmPluginConfig = struct {
    module_path: []const u8,
    entrypoint: []const u8 = "spiderweb_driver_v1",
    runner_path: ?[]const u8 = null,
    args: []const []const u8 = &.{},
};

pub const WasmPluginHandle = struct {
    module_path: []u8,
    entrypoint: []u8,
    runner_path: ?[]u8 = null,
    args: std.ArrayListUnmanaged([]u8) = .{},

    pub fn deinit(self: *WasmPluginHandle, allocator: std.mem.Allocator) void {
        allocator.free(self.module_path);
        allocator.free(self.entrypoint);
        if (self.runner_path) |value| allocator.free(value);
        for (self.args.items) |arg| allocator.free(arg);
        self.args.deinit(allocator);
        self.* = undefined;
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    config: WasmPluginConfig,
) !WasmPluginHandle {
    if (config.module_path.len == 0) return error.InvalidPluginConfig;
    if (config.entrypoint.len == 0) return error.InvalidPluginConfig;
    var handle = WasmPluginHandle{
        .module_path = try allocator.dupe(u8, config.module_path),
        .entrypoint = try allocator.dupe(u8, config.entrypoint),
        .runner_path = if (config.runner_path) |value| blk: {
            if (value.len == 0) return error.InvalidPluginConfig;
            break :blk try allocator.dupe(u8, value);
        } else null,
    };
    errdefer handle.deinit(allocator);
    for (config.args) |arg| {
        if (arg.len == 0) return error.InvalidPluginConfig;
        try handle.args.append(allocator, try allocator.dupe(u8, arg));
    }
    return handle;
}

test "plugin_loader_wasm: validates module path" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidPluginConfig, load(allocator, .{ .module_path = "" }));
}

test "plugin_loader_wasm: captures module and entrypoint" {
    const allocator = std.testing.allocator;
    var handle = try load(allocator, .{
        .module_path = "plugins/camera.wasm",
        .entrypoint = "spiderweb_driver_v1",
        .runner_path = "wasmtime",
        .args = &.{ "--dir", "." },
    });
    defer handle.deinit(allocator);

    try std.testing.expectEqualStrings("plugins/camera.wasm", handle.module_path);
    try std.testing.expectEqualStrings("spiderweb_driver_v1", handle.entrypoint);
    try std.testing.expectEqualStrings("wasmtime", handle.runner_path.?);
    try std.testing.expectEqual(@as(usize, 2), handle.args.items.len);
}
