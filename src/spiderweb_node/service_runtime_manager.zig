const std = @import("std");
const namespace_driver = @import("namespace_driver.zig");

pub const RuntimeManager = struct {
    allocator: std.mem.Allocator,
    services: std.ArrayListUnmanaged(ManagedService) = .{},

    const ManagedService = struct {
        descriptor: namespace_driver.ServiceDescriptor,
        driver: ?namespace_driver.DriverHandle = null,

        fn deinit(self: *ManagedService, allocator: std.mem.Allocator) void {
            self.descriptor.deinit(allocator);
            self.* = undefined;
        }
    };

    pub fn init(allocator: std.mem.Allocator) RuntimeManager {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RuntimeManager) void {
        for (self.services.items) |*service| service.deinit(self.allocator);
        self.services.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn register(self: *RuntimeManager, descriptor: *const namespace_driver.ServiceDescriptor, driver: ?namespace_driver.DriverHandle) !void {
        for (self.services.items) |service| {
            if (std.mem.eql(u8, service.descriptor.service_id, descriptor.service_id)) {
                return error.DuplicateServiceId;
            }
        }
        try self.services.append(self.allocator, .{
            .descriptor = try descriptor.clone(self.allocator),
            .driver = driver,
        });
    }

    pub fn startAll(self: *RuntimeManager) !void {
        for (self.services.items) |*service| {
            if (service.driver) |driver| {
                driver.start(self.allocator) catch |err| {
                    service.descriptor.state = .degraded;
                    std.log.warn("service start failed ({s}): {s}", .{ service.descriptor.service_id, @errorName(err) });
                    continue;
                };
                service.descriptor.state = .online;
            }
        }
    }

    pub fn stopAll(self: *RuntimeManager) void {
        for (self.services.items) |*service| {
            if (service.driver) |driver| {
                driver.stop(self.allocator);
            }
        }
    }

    pub fn registerFromServiceJson(self: *RuntimeManager, service_json: []const u8) !void {
        var descriptor = try parseServiceDescriptor(self.allocator, service_json);
        defer descriptor.deinit(self.allocator);
        try self.register(&descriptor, null);
    }
};

fn parseServiceDescriptor(
    allocator: std.mem.Allocator,
    service_json: []const u8,
) !namespace_driver.ServiceDescriptor {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, service_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidServiceCatalog;

    const obj = parsed.value.object;
    const service_id = getRequiredString(obj, "service_id") orelse return error.InvalidServiceCatalog;
    const kind = getRequiredString(obj, "kind") orelse return error.InvalidServiceCatalog;
    const version = getOptionalString(obj, "version") orelse "1";
    const state_raw = getOptionalString(obj, "state") orelse "unknown";

    var descriptor = namespace_driver.ServiceDescriptor{
        .service_id = try allocator.dupe(u8, service_id),
        .kind = try allocator.dupe(u8, kind),
        .version = try allocator.dupe(u8, version),
        .state = parseServiceState(state_raw),
        .runtime_type = parseRuntimeType(obj),
        .capabilities_json = if (obj.get("capabilities")) |value|
            if (value == .object) try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})}) else try allocator.dupe(u8, "{}")
        else
            try allocator.dupe(u8, "{}"),
        .ops_json = if (obj.get("ops")) |value|
            if (value == .object) try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})}) else try allocator.dupe(u8, "{}")
        else
            try allocator.dupe(u8, "{}"),
        .permissions_json = if (obj.get("permissions")) |value|
            if (value == .object) try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})}) else try allocator.dupe(u8, "{}")
        else
            try allocator.dupe(u8, "{}"),
        .schema_json = if (obj.get("schema")) |value|
            if (value == .object) try std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{})}) else try allocator.dupe(u8, "{}")
        else
            try allocator.dupe(u8, "{}"),
        .help_md = if (obj.get("help_md")) |value|
            if (value == .string and value.string.len > 0) try allocator.dupe(u8, value.string) else null
        else
            null,
    };
    errdefer descriptor.deinit(allocator);

    if (obj.get("mounts")) |mounts| {
        if (mounts == .array) {
            for (mounts.array.items) |item| {
                if (item != .object) continue;
                const mount_id = getRequiredString(item.object, "mount_id") orelse continue;
                const mount_path = getRequiredString(item.object, "mount_path") orelse continue;
                const mount_state_raw = getOptionalString(item.object, "state") orelse "online";
                try descriptor.mounts.append(allocator, .{
                    .mount_id = try allocator.dupe(u8, mount_id),
                    .mount_path = try allocator.dupe(u8, mount_path),
                    .state = parseServiceState(mount_state_raw),
                });
            }
        }
    }

    return descriptor;
}

fn parseRuntimeType(obj: std.json.ObjectMap) namespace_driver.RuntimeType {
    const runtime = obj.get("runtime") orelse return .builtin;
    if (runtime != .object) return .builtin;
    const runtime_type = getOptionalString(runtime.object, "type") orelse return .builtin;
    if (std.mem.eql(u8, runtime_type, "native_inproc")) return .native_inproc;
    if (std.mem.eql(u8, runtime_type, "native_proc")) return .native_proc;
    if (std.mem.eql(u8, runtime_type, "wasm")) return .wasm;
    return .builtin;
}

fn parseServiceState(raw: []const u8) namespace_driver.ServiceState {
    if (std.mem.eql(u8, raw, "degraded")) return .degraded;
    if (std.mem.eql(u8, raw, "offline")) return .offline;
    return .online;
}

fn getRequiredString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

fn getOptionalString(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = obj.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

test "service_runtime_manager: rejects duplicate service ids" {
    const allocator = std.testing.allocator;
    var manager = RuntimeManager.init(allocator);
    defer manager.deinit();

    var descriptor = namespace_driver.ServiceDescriptor{
        .service_id = try allocator.dupe(u8, "svc-1"),
        .kind = try allocator.dupe(u8, "test"),
        .version = try allocator.dupe(u8, "1"),
        .capabilities_json = try allocator.dupe(u8, "{}"),
        .ops_json = try allocator.dupe(u8, "{}"),
        .permissions_json = try allocator.dupe(u8, "{}"),
        .schema_json = try allocator.dupe(u8, "{}"),
    };
    defer descriptor.deinit(allocator);

    try manager.register(&descriptor, null);
    try std.testing.expectError(error.DuplicateServiceId, manager.register(&descriptor, null));
}

test "service_runtime_manager: registers descriptor from service json" {
    const allocator = std.testing.allocator;
    var manager = RuntimeManager.init(allocator);
    defer manager.deinit();

    try manager.registerFromServiceJson(
        "{\"service_id\":\"camera-main\",\"kind\":\"camera\",\"version\":\"1\",\"state\":\"degraded\",\"endpoints\":[\"/nodes/node-1/camera\"],\"capabilities\":{\"still\":true},\"mounts\":[{\"mount_id\":\"camera-main\",\"mount_path\":\"/nodes/node-1/camera\",\"state\":\"offline\"}],\"runtime\":{\"type\":\"native_proc\"},\"permissions\":{\"default\":\"deny-by-default\"},\"schema\":{\"model\":\"namespace\"}}",
    );

    try std.testing.expectEqual(@as(usize, 1), manager.services.items.len);
    try std.testing.expect(manager.services.items[0].descriptor.runtime_type == .native_proc);
    try std.testing.expect(manager.services.items[0].descriptor.state == .degraded);
    try std.testing.expectEqual(@as(usize, 1), manager.services.items[0].descriptor.mounts.items.len);
    try std.testing.expect(manager.services.items[0].descriptor.mounts.items[0].state == .offline);
}
