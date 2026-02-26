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
};

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
