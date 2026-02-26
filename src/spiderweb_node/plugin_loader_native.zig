const std = @import("std");

pub const NativePluginConfig = struct {
    library_path: []const u8,
    in_process: bool = true,
};

pub const LoadedNativePlugin = struct {
    library_path: []u8,
    in_process: bool,

    pub fn deinit(self: *LoadedNativePlugin, allocator: std.mem.Allocator) void {
        allocator.free(self.library_path);
        self.* = undefined;
    }
};

pub fn load(
    allocator: std.mem.Allocator,
    config: NativePluginConfig,
) !LoadedNativePlugin {
    if (config.library_path.len == 0) return error.InvalidPluginConfig;
    return .{
        .library_path = try allocator.dupe(u8, config.library_path),
        .in_process = config.in_process,
    };
}

test "plugin_loader_native: validates config" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidPluginConfig, load(allocator, .{ .library_path = "" }));
}

test "plugin_loader_native: captures load metadata" {
    const allocator = std.testing.allocator;
    var plugin = try load(allocator, .{
        .library_path = "camera_plugin.dll",
        .in_process = false,
    });
    defer plugin.deinit(allocator);

    try std.testing.expectEqualStrings("camera_plugin.dll", plugin.library_path);
    try std.testing.expect(!plugin.in_process);
}
