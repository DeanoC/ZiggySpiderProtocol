const std = @import("std");
const namespace_driver = @import("namespace_driver.zig");

const supervisor_loop_sleep_ms: u64 = 25;

pub const ServiceSupervisionPolicy = struct {
    health_check_interval_ms: u64 = 5_000,
    restart_backoff_ms: u64 = 500,
    restart_backoff_max_ms: u64 = 30_000,
    max_consecutive_failures: u32 = 0,
    auto_disable_on_failures: bool = false,
};

pub const ServiceRuntimeStats = struct {
    enabled: bool,
    running: bool,
    start_attempts_total: u64,
    restarts_total: u64,
    consecutive_failures: u32,
    backoff_until_ms: i64,
};

pub const ParsedServiceRegistration = struct {
    descriptor: namespace_driver.ServiceDescriptor,
    policy: ServiceSupervisionPolicy,

    pub fn deinit(self: *ParsedServiceRegistration, allocator: std.mem.Allocator) void {
        self.descriptor.deinit(allocator);
        self.* = undefined;
    }
};

pub const RuntimeManager = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    services: std.ArrayListUnmanaged(ManagedService) = .{},
    supervisor_thread: ?std.Thread = null,
    stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    const ManagedService = struct {
        descriptor: namespace_driver.ServiceDescriptor,
        driver: ?namespace_driver.DriverHandle = null,
        policy: ServiceSupervisionPolicy = .{},

        enabled: bool = true,
        running: bool = false,
        started_once: bool = false,
        start_attempts_total: u64 = 0,
        restarts_total: u64 = 0,
        consecutive_failures: u32 = 0,
        next_health_check_ms: i64 = 0,
        backoff_until_ms: i64 = 0,
        last_start_ms: i64 = 0,
        last_stop_ms: i64 = 0,
        last_error: ?[]u8 = null,

        fn deinit(self: *ManagedService, allocator: std.mem.Allocator) void {
            self.descriptor.deinit(allocator);
            if (self.last_error) |value| allocator.free(value);
            self.* = undefined;
        }

        fn setLastError(self: *ManagedService, allocator: std.mem.Allocator, detail: []const u8) void {
            if (self.last_error) |value| allocator.free(value);
            self.last_error = allocator.dupe(u8, detail) catch null;
        }

        fn clearLastError(self: *ManagedService, allocator: std.mem.Allocator) void {
            if (self.last_error) |value| {
                allocator.free(value);
                self.last_error = null;
            }
        }

        fn runtimeStats(self: *const ManagedService) ServiceRuntimeStats {
            return .{
                .enabled = self.enabled,
                .running = self.running,
                .start_attempts_total = self.start_attempts_total,
                .restarts_total = self.restarts_total,
                .consecutive_failures = self.consecutive_failures,
                .backoff_until_ms = self.backoff_until_ms,
            };
        }
    };

    pub fn init(allocator: std.mem.Allocator) RuntimeManager {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RuntimeManager) void {
        self.stopAll();
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.services.items) |*service| service.deinit(self.allocator);
        self.services.deinit(self.allocator);
    }

    pub fn register(self: *RuntimeManager, descriptor: *const namespace_driver.ServiceDescriptor, driver: ?namespace_driver.DriverHandle) !void {
        return self.registerWithPolicy(descriptor, driver, .{});
    }

    pub fn registerWithPolicy(
        self: *RuntimeManager,
        descriptor: *const namespace_driver.ServiceDescriptor,
        driver: ?namespace_driver.DriverHandle,
        policy: ServiceSupervisionPolicy,
    ) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.findServiceIndexLocked(descriptor.service_id) != null) {
            return error.DuplicateServiceId;
        }

        var normalized = policy;
        normalizePolicy(&normalized);

        try self.services.append(self.allocator, .{
            .descriptor = try descriptor.clone(self.allocator),
            .driver = driver,
            .policy = normalized,
            .enabled = true,
        });
    }

    pub fn startAll(self: *RuntimeManager) !void {
        self.stop_requested.store(false, .release);

        self.mutex.lock();
        defer self.mutex.unlock();

        const now_ms = std.time.milliTimestamp();
        var has_supervised_drivers = false;

        for (self.services.items) |*service| {
            if (service.driver == null) continue;
            has_supervised_drivers = true;
            service.enabled = true;
            service.backoff_until_ms = 0;
            self.startServiceLocked(service, now_ms);
        }

        if (has_supervised_drivers and self.supervisor_thread == null) {
            self.supervisor_thread = try std.Thread.spawn(.{}, supervisorThreadMain, .{self});
        }
    }

    pub fn stopAll(self: *RuntimeManager) void {
        self.stop_requested.store(true, .release);

        var thread_to_join: ?std.Thread = null;

        self.mutex.lock();
        thread_to_join = self.supervisor_thread;
        self.supervisor_thread = null;

        const now_ms = std.time.milliTimestamp();
        for (self.services.items) |*service| {
            self.stopServiceLocked(service, now_ms, .offline);
            service.enabled = false;
            service.backoff_until_ms = 0;
            service.next_health_check_ms = 0;
        }
        self.mutex.unlock();

        if (thread_to_join) |thread| thread.join();
    }

    pub fn enableService(self: *RuntimeManager, service_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const idx = self.findServiceIndexLocked(service_id) orelse return error.ServiceNotFound;
        const service = &self.services.items[idx];
        service.enabled = true;
        service.backoff_until_ms = 0;

        if (service.driver != null and !service.running) {
            self.startServiceLocked(service, std.time.milliTimestamp());
        }
    }

    pub fn disableService(self: *RuntimeManager, service_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const idx = self.findServiceIndexLocked(service_id) orelse return error.ServiceNotFound;
        const service = &self.services.items[idx];
        service.enabled = false;
        service.backoff_until_ms = 0;
        self.stopServiceLocked(service, std.time.milliTimestamp(), .offline);
    }

    pub fn restartService(self: *RuntimeManager, service_id: []const u8) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const idx = self.findServiceIndexLocked(service_id) orelse return error.ServiceNotFound;
        const service = &self.services.items[idx];
        service.enabled = true;
        service.backoff_until_ms = 0;
        self.stopServiceLocked(service, std.time.milliTimestamp(), .degraded);
        self.startServiceLocked(service, std.time.milliTimestamp());
    }

    pub fn serviceState(self: *RuntimeManager, service_id: []const u8) ?namespace_driver.ServiceState {
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = self.findServiceIndexLocked(service_id) orelse return null;
        return self.services.items[idx].descriptor.state;
    }

    pub fn serviceRuntimeStats(self: *RuntimeManager, service_id: []const u8) ?ServiceRuntimeStats {
        self.mutex.lock();
        defer self.mutex.unlock();
        const idx = self.findServiceIndexLocked(service_id) orelse return null;
        return self.services.items[idx].runtimeStats();
    }

    pub fn registerFromServiceJson(self: *RuntimeManager, service_json: []const u8) !void {
        var parsed = try parseServiceRegistrationFromServiceJson(self.allocator, service_json);
        defer parsed.deinit(self.allocator);
        try self.registerWithPolicy(&parsed.descriptor, null, parsed.policy);
    }

    fn findServiceIndexLocked(self: *RuntimeManager, service_id: []const u8) ?usize {
        for (self.services.items, 0..) |service, idx| {
            if (std.mem.eql(u8, service.descriptor.service_id, service_id)) return idx;
        }
        return null;
    }

    fn startServiceLocked(self: *RuntimeManager, service: *ManagedService, now_ms: i64) void {
        const driver = service.driver orelse return;

        service.start_attempts_total +%= 1;
        driver.start(self.allocator) catch |err| {
            service.descriptor.state = .degraded;
            service.running = false;
            service.setLastError(self.allocator, @errorName(err));
            service.consecutive_failures +%= 1;
            self.applyFailurePolicyLocked(service, now_ms);
            std.log.warn("service start failed ({s}): {s}", .{ service.descriptor.service_id, @errorName(err) });
            return;
        };

        if (service.started_once) {
            service.restarts_total +%= 1;
        } else {
            service.started_once = true;
        }

        service.running = true;
        service.descriptor.state = .online;
        service.consecutive_failures = 0;
        service.backoff_until_ms = 0;
        service.last_start_ms = now_ms;
        service.next_health_check_ms = now_ms + @as(i64, @intCast(service.policy.health_check_interval_ms));
        service.clearLastError(self.allocator);
    }

    fn stopServiceLocked(
        self: *RuntimeManager,
        service: *ManagedService,
        now_ms: i64,
        target_state: namespace_driver.ServiceState,
    ) void {
        if (service.driver) |driver| {
            if (service.running) {
                driver.stop(self.allocator);
            }
        }
        service.running = false;
        service.last_stop_ms = now_ms;
        service.descriptor.state = target_state;
    }

    fn applyFailurePolicyLocked(self: *RuntimeManager, service: *ManagedService, now_ms: i64) void {
        _ = self;
        if (service.policy.auto_disable_on_failures and
            service.policy.max_consecutive_failures > 0 and
            service.consecutive_failures >= service.policy.max_consecutive_failures)
        {
            service.enabled = false;
            service.backoff_until_ms = 0;
            service.descriptor.state = .offline;
            return;
        }

        const backoff_ms = computeBackoffMs(service.policy, service.consecutive_failures);
        if (backoff_ms == 0) {
            service.backoff_until_ms = 0;
        } else {
            service.backoff_until_ms = now_ms + @as(i64, @intCast(backoff_ms));
        }
    }

    fn recordHealthFailureLocked(
        self: *RuntimeManager,
        service: *ManagedService,
        now_ms: i64,
        detail: []const u8,
        state: namespace_driver.ServiceState,
    ) void {
        service.setLastError(self.allocator, detail);
        service.consecutive_failures +%= 1;
        self.stopServiceLocked(service, now_ms, state);
        self.applyFailurePolicyLocked(service, now_ms);
        if (!service.enabled) {
            service.descriptor.state = .offline;
        } else {
            service.descriptor.state = .degraded;
        }
    }

    fn superviseTick(self: *RuntimeManager) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now_ms = std.time.milliTimestamp();

        for (self.services.items) |*service| {
            if (service.driver == null) continue;
            if (!service.enabled) continue;

            if (!service.running) {
                if (service.backoff_until_ms > now_ms) continue;
                self.startServiceLocked(service, now_ms);
                continue;
            }

            if (service.next_health_check_ms > now_ms) continue;
            service.next_health_check_ms = now_ms + @as(i64, @intCast(service.policy.health_check_interval_ms));

            const health = service.driver.?.health(self.allocator) catch |err| {
                self.recordHealthFailureLocked(
                    service,
                    now_ms,
                    @errorName(err),
                    .degraded,
                );
                continue;
            };

            if (health.state == .online) {
                service.descriptor.state = .online;
                service.consecutive_failures = 0;
                service.clearLastError(self.allocator);
                continue;
            }

            const detail = if (health.detail.len > 0) health.detail else "driver health check failed";
            self.recordHealthFailureLocked(service, now_ms, detail, health.state);
        }
    }

    fn supervisorThreadMain(self: *RuntimeManager) void {
        while (!self.stop_requested.load(.acquire)) {
            self.superviseTick();
            std.Thread.sleep(supervisor_loop_sleep_ms * std.time.ns_per_ms);
        }
    }
};

pub fn parseServiceRegistrationFromServiceJson(
    allocator: std.mem.Allocator,
    service_json: []const u8,
) !ParsedServiceRegistration {
    return .{
        .descriptor = try parseServiceDescriptor(allocator, service_json),
        .policy = try parseServiceSupervisionPolicy(allocator, service_json),
    };
}

fn normalizePolicy(policy: *ServiceSupervisionPolicy) void {
    if (policy.health_check_interval_ms == 0) policy.health_check_interval_ms = 5_000;
    if (policy.restart_backoff_max_ms == 0) policy.restart_backoff_max_ms = 30_000;
    if (policy.restart_backoff_ms > policy.restart_backoff_max_ms) {
        policy.restart_backoff_max_ms = policy.restart_backoff_ms;
    }
}

fn computeBackoffMs(policy: ServiceSupervisionPolicy, consecutive_failures: u32) u64 {
    if (policy.restart_backoff_ms == 0 or consecutive_failures == 0) return 0;

    var backoff = policy.restart_backoff_ms;
    var step: u32 = 1;
    while (step < consecutive_failures and backoff < policy.restart_backoff_max_ms) : (step += 1) {
        if (backoff > policy.restart_backoff_max_ms / 2) {
            backoff = policy.restart_backoff_max_ms;
            break;
        }
        backoff *= 2;
    }

    if (backoff > policy.restart_backoff_max_ms) return policy.restart_backoff_max_ms;
    return backoff;
}

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

fn parseServiceSupervisionPolicy(
    allocator: std.mem.Allocator,
    service_json: []const u8,
) !ServiceSupervisionPolicy {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, service_json, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidServiceCatalog;

    const runtime = parsed.value.object.get("runtime") orelse return .{};
    if (runtime != .object) return error.InvalidServiceCatalog;

    const supervision = runtime.object.get("supervision") orelse return .{};
    if (supervision != .object) return error.InvalidServiceCatalog;

    var policy = ServiceSupervisionPolicy{};

    if (supervision.object.get("health_check_interval_ms")) |value| {
        if (value != .integer or value.integer < 0) return error.InvalidServiceCatalog;
        policy.health_check_interval_ms = @intCast(value.integer);
    }
    if (supervision.object.get("restart_backoff_ms")) |value| {
        if (value != .integer or value.integer < 0) return error.InvalidServiceCatalog;
        policy.restart_backoff_ms = @intCast(value.integer);
    }
    if (supervision.object.get("restart_backoff_max_ms")) |value| {
        if (value != .integer or value.integer < 0) return error.InvalidServiceCatalog;
        policy.restart_backoff_max_ms = @intCast(value.integer);
    }
    if (supervision.object.get("max_consecutive_failures")) |value| {
        if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u32)) {
            return error.InvalidServiceCatalog;
        }
        policy.max_consecutive_failures = @intCast(value.integer);
    }
    if (supervision.object.get("auto_disable_on_failures")) |value| {
        if (value != .bool) return error.InvalidServiceCatalog;
        policy.auto_disable_on_failures = value.bool;
    }

    normalizePolicy(&policy);
    return policy;
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
        "{\"service_id\":\"camera-main\",\"kind\":\"camera\",\"version\":\"1\",\"state\":\"degraded\",\"endpoints\":[\"/nodes/node-1/camera\"],\"capabilities\":{\"still\":true},\"mounts\":[{\"mount_id\":\"camera-main\",\"mount_path\":\"/nodes/node-1/camera\",\"state\":\"offline\"}],\"runtime\":{\"type\":\"native_proc\",\"supervision\":{\"health_check_interval_ms\":10,\"restart_backoff_ms\":20}},\"permissions\":{\"default\":\"deny-by-default\"},\"schema\":{\"model\":\"namespace\"}}",
    );

    try std.testing.expectEqual(@as(usize, 1), manager.services.items.len);
    try std.testing.expect(manager.services.items[0].descriptor.runtime_type == .native_proc);
    try std.testing.expect(manager.services.items[0].descriptor.state == .degraded);
    try std.testing.expectEqual(@as(usize, 1), manager.services.items[0].descriptor.mounts.items.len);
    try std.testing.expect(manager.services.items[0].descriptor.mounts.items[0].state == .offline);
    try std.testing.expectEqual(@as(u64, 10), manager.services.items[0].policy.health_check_interval_ms);
    try std.testing.expectEqual(@as(u64, 20), manager.services.items[0].policy.restart_backoff_ms);
}

const MockDriver = struct {
    const HealthMode = enum {
        online,
        offline,
        error_state,
    };

    const Snapshot = struct {
        start_calls: u32,
        stop_calls: u32,
        health_calls: u32,
    };

    mutex: std.Thread.Mutex = .{},
    fail_starts_remaining: u32 = 0,
    health_mode: HealthMode = .online,
    start_calls: u32 = 0,
    stop_calls: u32 = 0,
    health_calls: u32 = 0,

    const vtable = namespace_driver.DriverVTable{
        .start = startFn,
        .stop = stopFn,
        .health = healthFn,
        .invoke_json = invokeFn,
    };

    fn handle(self: *MockDriver) namespace_driver.DriverHandle {
        return .{
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn snapshot(self: *MockDriver) Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .start_calls = self.start_calls,
            .stop_calls = self.stop_calls,
            .health_calls = self.health_calls,
        };
    }

    fn startFn(ctx: *anyopaque, allocator: std.mem.Allocator) anyerror!void {
        _ = allocator;
        const self: *MockDriver = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.start_calls +%= 1;
        if (self.fail_starts_remaining > 0) {
            self.fail_starts_remaining -= 1;
            return error.MockStartFailed;
        }
    }

    fn stopFn(ctx: *anyopaque, allocator: std.mem.Allocator) void {
        _ = allocator;
        const self: *MockDriver = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.stop_calls +%= 1;
    }

    fn healthFn(ctx: *anyopaque, allocator: std.mem.Allocator) anyerror!namespace_driver.Health {
        _ = allocator;
        const self: *MockDriver = @ptrCast(@alignCast(ctx));
        self.mutex.lock();
        defer self.mutex.unlock();
        self.health_calls +%= 1;
        return switch (self.health_mode) {
            .online => .{ .state = .online, .detail = "ok" },
            .offline => .{ .state = .offline, .detail = "offline" },
            .error_state => error.MockHealthFailed,
        };
    }

    fn invokeFn(ctx: *anyopaque, allocator: std.mem.Allocator, op: []const u8, args_json: []const u8) anyerror![]u8 {
        _ = ctx;
        _ = op;
        return allocator.dupe(u8, args_json);
    }
};

fn makeTestDescriptor(allocator: std.mem.Allocator, service_id: []const u8) !namespace_driver.ServiceDescriptor {
    return .{
        .service_id = try allocator.dupe(u8, service_id),
        .kind = try allocator.dupe(u8, "test"),
        .version = try allocator.dupe(u8, "1"),
        .capabilities_json = try allocator.dupe(u8, "{}"),
        .ops_json = try allocator.dupe(u8, "{}"),
        .permissions_json = try allocator.dupe(u8, "{}"),
        .schema_json = try allocator.dupe(u8, "{}"),
    };
}

test "service_runtime_manager: supervisor retries start with backoff" {
    const allocator = std.testing.allocator;
    var manager = RuntimeManager.init(allocator);
    defer manager.deinit();

    var descriptor = try makeTestDescriptor(allocator, "svc-supervise");
    defer descriptor.deinit(allocator);

    var mock = MockDriver{ .fail_starts_remaining = 1 };
    try manager.registerWithPolicy(&descriptor, mock.handle(), .{
        .health_check_interval_ms = 10,
        .restart_backoff_ms = 10,
        .restart_backoff_max_ms = 40,
    });

    try manager.startAll();
    defer manager.stopAll();

    const deadline = std.time.milliTimestamp() + 2_000;
    var online = false;
    while (std.time.milliTimestamp() < deadline) {
        const stats = manager.serviceRuntimeStats("svc-supervise") orelse return error.TestExpectedResponse;
        const state = manager.serviceState("svc-supervise") orelse return error.TestExpectedResponse;
        if (stats.running and stats.start_attempts_total >= 2 and state == .online) {
            online = true;
            break;
        }
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    try std.testing.expect(online);

    const snap = mock.snapshot();
    try std.testing.expect(snap.start_calls >= 2);
}

test "service_runtime_manager: auto disables after consecutive failures" {
    const allocator = std.testing.allocator;
    var manager = RuntimeManager.init(allocator);
    defer manager.deinit();

    var descriptor = try makeTestDescriptor(allocator, "svc-auto-disable");
    defer descriptor.deinit(allocator);

    var mock = MockDriver{ .health_mode = .offline };
    try manager.registerWithPolicy(&descriptor, mock.handle(), .{
        .health_check_interval_ms = 10,
        .restart_backoff_ms = 5,
        .restart_backoff_max_ms = 5,
        .max_consecutive_failures = 1,
        .auto_disable_on_failures = true,
    });

    try manager.startAll();
    defer manager.stopAll();

    const deadline = std.time.milliTimestamp() + 2_000;
    var disabled = false;
    while (std.time.milliTimestamp() < deadline) {
        const stats = manager.serviceRuntimeStats("svc-auto-disable") orelse return error.TestExpectedResponse;
        if (!stats.enabled and !stats.running) {
            disabled = true;
            break;
        }
        std.Thread.sleep(10 * std.time.ns_per_ms);
    }

    try std.testing.expect(disabled);
    try std.testing.expectEqual(namespace_driver.ServiceState.offline, manager.serviceState("svc-auto-disable").?);

    const snap = mock.snapshot();
    try std.testing.expect(snap.stop_calls >= 1);
}
