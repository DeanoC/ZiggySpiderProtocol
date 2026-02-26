const std = @import("std");

pub const WasmPluginConfig = struct {
    module_path: []const u8,
    entrypoint: []const u8 = "spiderweb_driver_v1",
};

pub const WasmPluginHandle = struct {
    module_path: []u8,
    entrypoint: []u8,

    pub fn deinit(self: *WasmPluginHandle, allocator: std.mem.Allocator) void {
        allocator.free(self.module_path);
        allocator.free(self.entrypoint);
        self.* = undefined;
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    config: WasmPluginConfig,
) !WasmPluginHandle {
    if (config.module_path.len == 0) return error.InvalidPluginConfig;
    if (config.entrypoint.len == 0) return error.InvalidPluginConfig;
    return .{
        .module_path = try allocator.dupe(u8, config.module_path),
        .entrypoint = try allocator.dupe(u8, config.entrypoint),
    };
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
    });
    defer handle.deinit(allocator);

    try std.testing.expectEqualStrings("plugins/camera.wasm", handle.module_path);
    try std.testing.expectEqualStrings("spiderweb_driver_v1", handle.entrypoint);
}
