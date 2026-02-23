const std = @import("std");
const types = @import("unified_types.zig");

pub fn buildControlAck(
    allocator: std.mem.Allocator,
    msg_type: types.ControlType,
    id: ?[]const u8,
    payload_json: ?[]const u8,
) ![]u8 {
    if (msg_type == .unknown or msg_type == .err) return error.InvalidMessageType;
    const payload = payload_json orelse "{}";
    if (id) |request_id| {
        const escaped_id = try jsonEscape(allocator, request_id);
        defer allocator.free(escaped_id);
        return std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"control\",\"type\":\"{s}\",\"id\":\"{s}\",\"ok\":true,\"payload\":{s}}}",
            .{ types.controlTypeName(msg_type), escaped_id, payload },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"{s}\",\"ok\":true,\"payload\":{s}}}",
        .{ types.controlTypeName(msg_type), payload },
    );
}

pub fn buildControlError(
    allocator: std.mem.Allocator,
    id: ?[]const u8,
    code: []const u8,
    message: []const u8,
) ![]u8 {
    const escaped_code = try jsonEscape(allocator, code);
    defer allocator.free(escaped_code);
    const escaped_message = try jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    if (id) |request_id| {
        const escaped_id = try jsonEscape(allocator, request_id);
        defer allocator.free(escaped_id);
        return std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"control\",\"type\":\"control.error\",\"id\":\"{s}\",\"ok\":false,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ escaped_id, escaped_code, escaped_message },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"control\",\"type\":\"control.error\",\"ok\":false,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
        .{ escaped_code, escaped_message },
    );
}

pub fn buildFsrpcResponse(
    allocator: std.mem.Allocator,
    msg_type: types.FsrpcType,
    tag: ?u32,
    payload_json: ?[]const u8,
) ![]u8 {
    if (msg_type == .unknown or msg_type == .err or msg_type == .fs_err) return error.InvalidMessageType;
    const payload = payload_json orelse "{}";
    if (tag) |value| {
        return std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"fsrpc\",\"type\":\"{s}\",\"tag\":{d},\"ok\":true,\"payload\":{s}}}",
            .{ types.fsrpcTypeName(msg_type), value, payload },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"fsrpc\",\"type\":\"{s}\",\"ok\":true,\"payload\":{s}}}",
        .{ types.fsrpcTypeName(msg_type), payload },
    );
}

pub fn buildFsrpcError(
    allocator: std.mem.Allocator,
    tag: ?u32,
    code: []const u8,
    message: []const u8,
) ![]u8 {
    const escaped_code = try jsonEscape(allocator, code);
    defer allocator.free(escaped_code);
    const escaped_message = try jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    if (tag) |value| {
        return std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"fsrpc\",\"type\":\"fsrpc.error\",\"tag\":{d},\"ok\":false,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
            .{ value, escaped_code, escaped_message },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"fsrpc\",\"type\":\"fsrpc.error\",\"ok\":false,\"error\":{{\"code\":\"{s}\",\"message\":\"{s}\"}}}}",
        .{ escaped_code, escaped_message },
    );
}

pub fn buildFsrpcFsError(
    allocator: std.mem.Allocator,
    tag: ?u32,
    errno: i32,
    message: []const u8,
) ![]u8 {
    const escaped_message = try jsonEscape(allocator, message);
    defer allocator.free(escaped_message);

    if (tag) |value| {
        return std.fmt.allocPrint(
            allocator,
            "{{\"channel\":\"fsrpc\",\"type\":\"fsrpc.err_fs\",\"tag\":{d},\"ok\":false,\"error\":{{\"errno\":{d},\"message\":\"{s}\"}}}}",
            .{ value, errno, escaped_message },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"fsrpc\",\"type\":\"fsrpc.err_fs\",\"ok\":false,\"error\":{{\"errno\":{d},\"message\":\"{s}\"}}}}",
        .{ errno, escaped_message },
    );
}

pub fn buildFsrpcEvent(
    allocator: std.mem.Allocator,
    msg_type: types.FsrpcType,
    payload_json: ?[]const u8,
) ![]u8 {
    if (msg_type != .fs_evt_inval and msg_type != .fs_evt_inval_dir) return error.InvalidMessageType;
    const payload = payload_json orelse "{}";
    return std.fmt.allocPrint(
        allocator,
        "{{\"channel\":\"fsrpc\",\"type\":\"{s}\",\"payload\":{s}}}",
        .{ types.fsrpcTypeName(msg_type), payload },
    );
}

pub fn encodeDataB64(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded_len = encoder.calcSize(data.len);
    const out = try allocator.alloc(u8, encoded_len);
    _ = encoder.encode(out, data);
    return out;
}

pub fn jsonEscape(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    defer out.deinit(allocator);

    for (input) |char| {
        switch (char) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (char < 0x20) {
                    try out.writer(allocator).print("\\u00{x:0>2}", .{char});
                } else {
                    try out.append(allocator, char);
                }
            },
        }
    }

    return out.toOwnedSlice(allocator);
}

test "unified_build: builds fsrpc error with tag" {
    const allocator = std.testing.allocator;
    const payload = try buildFsrpcError(allocator, 7, "enoent", "not found");
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"channel\":\"fsrpc\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"tag\":7") != null);
}

test "unified_build: builds distributed fsrpc error with errno" {
    const allocator = std.testing.allocator;
    const payload = try buildFsrpcFsError(allocator, 3, 2, "not found");
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"type\":\"fsrpc.err_fs\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"errno\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"tag\":3") != null);
}

test "unified_build: builds distributed fsrpc event envelope" {
    const allocator = std.testing.allocator;
    const payload = try buildFsrpcEvent(allocator, .fs_evt_inval, "{\"node\":42,\"what\":\"all\"}");
    defer allocator.free(payload);

    try std.testing.expect(std.mem.indexOf(u8, payload, "\"type\":\"fsrpc.e_fs_inval\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "\"payload\":{\"node\":42") != null);
}
