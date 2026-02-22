const std = @import("std");
const types = @import("unified_types.zig");

pub fn parseMessage(allocator: std.mem.Allocator, raw_json: []const u8) !types.ParsedMessage {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw_json, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return types.ParseError.InvalidEnvelope;
    const obj = parsed.value.object;

    const type_value = obj.get("type") orelse return types.ParseError.MissingField;
    if (type_value != .string) return types.ParseError.InvalidType;
    const type_name = type_value.string;

    const channel = blk: {
        if (obj.get("channel")) |raw| {
            if (raw != .string) return types.ParseError.InvalidType;
            if (std.mem.eql(u8, raw.string, "control")) break :blk types.Channel.control;
            if (std.mem.eql(u8, raw.string, "fsrpc")) break :blk types.Channel.fsrpc;
            return types.ParseError.InvalidType;
        }

        if (std.mem.startsWith(u8, type_name, "control.")) break :blk types.Channel.control;
        if (std.mem.startsWith(u8, type_name, "fsrpc.")) break :blk types.Channel.fsrpc;
        return types.ParseError.InvalidType;
    };

    var out = types.ParsedMessage{
        .channel = channel,
    };

    errdefer out.deinit(allocator);

    if (obj.get("id")) |raw| {
        if (raw != .string) return types.ParseError.InvalidType;
        out.id = try allocator.dupe(u8, raw.string);
    }

    switch (channel) {
        .control => {
            out.control_type = types.controlTypeFromString(type_name);
            if (out.control_type.? == .unknown) return types.ParseError.UnsupportedType;
        },
        .fsrpc => {
            out.fsrpc_type = types.fsrpcTypeFromString(type_name);
            if (out.fsrpc_type.? == .unknown) return types.ParseError.UnsupportedType;

            out.tag = try parseOptionalU32(obj, "tag");
            out.fid = try parseOptionalU32(obj, "fid");
            out.newfid = try parseOptionalU32(obj, "newfid");
            out.offset = try parseOptionalU64(obj, "offset");
            out.count = try parseOptionalU32(obj, "count");
            out.msize = try parseOptionalU32(obj, "msize");

            if (obj.get("mode")) |raw| {
                if (raw != .string) return types.ParseError.InvalidType;
                out.mode = try allocator.dupe(u8, raw.string);
            }

            if (obj.get("version")) |raw| {
                if (raw != .string) return types.ParseError.InvalidType;
                out.version = try allocator.dupe(u8, raw.string);
            }

            if (obj.get("path")) |raw_path| {
                if (raw_path != .array) return types.ParseError.InvalidType;
                const items = raw_path.array.items;
                var segments = std.ArrayListUnmanaged([]u8){};
                defer if (segments.items.len == 0) segments.deinit(allocator);
                for (items) |item| {
                    if (item != .string) return types.ParseError.InvalidType;
                    try segments.append(allocator, try allocator.dupe(u8, item.string));
                }
                out.path = try segments.toOwnedSlice(allocator);
            }

            if (obj.get("data_b64")) |raw_data| {
                if (raw_data != .string) return types.ParseError.InvalidType;
                const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(raw_data.string) catch {
                    return types.ParseError.InvalidBase64;
                };
                out.data = try allocator.alloc(u8, decoded_len);
                _ = std.base64.standard.Decoder.decode(out.data.?, raw_data.string) catch {
                    return types.ParseError.InvalidBase64;
                };
            } else if (obj.get("data")) |raw_data| {
                if (raw_data != .string) return types.ParseError.InvalidType;
                out.data = try allocator.dupe(u8, raw_data.string);
            }
        },
    }

    if (obj.get("payload")) |payload| {
        var payload_buf = std.ArrayListUnmanaged(u8){};
        defer payload_buf.deinit(allocator);
        const formatter = std.json.fmt(payload, .{});
        try std.fmt.format(payload_buf.writer(allocator), "{f}", .{formatter});
        out.payload_json = try payload_buf.toOwnedSlice(allocator);
    }

    return out;
}

fn parseOptionalU32(obj: std.json.ObjectMap, name: []const u8) !?u32 {
    const raw = obj.get(name) orelse return null;
    if (raw != .integer or raw.integer < 0 or raw.integer > std.math.maxInt(u32)) return types.ParseError.InvalidType;
    return @intCast(raw.integer);
}

fn parseOptionalU64(obj: std.json.ObjectMap, name: []const u8) !?u64 {
    const raw = obj.get(name) orelse return null;
    if (raw != .integer or raw.integer < 0) return types.ParseError.InvalidType;
    return @intCast(raw.integer);
}

test "unified_parse: parses control connect envelope" {
    const allocator = std.testing.allocator;
    var parsed = try parseMessage(allocator, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"c1\"}");
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(types.Channel.control, parsed.channel);
    try std.testing.expectEqual(types.ControlType.connect, parsed.control_type.?);
    try std.testing.expectEqualStrings("c1", parsed.id.?);
}

test "unified_parse: parses fsrpc walk envelope" {
    const allocator = std.testing.allocator;
    const raw =
        "{\"channel\":\"fsrpc\",\"type\":\"fsrpc.t_walk\",\"tag\":3,\"fid\":1,\"newfid\":2,\"path\":[\"capabilities\",\"chat\"]}";
    var parsed = try parseMessage(allocator, raw);
    defer parsed.deinit(allocator);

    try std.testing.expectEqual(types.Channel.fsrpc, parsed.channel);
    try std.testing.expectEqual(types.FsrpcType.t_walk, parsed.fsrpc_type.?);
    try std.testing.expectEqual(@as(u32, 3), parsed.tag.?);
    try std.testing.expectEqual(@as(u32, 1), parsed.fid.?);
    try std.testing.expectEqual(@as(u32, 2), parsed.newfid.?);
    try std.testing.expectEqual(@as(usize, 2), parsed.path.len);
    try std.testing.expectEqualStrings("capabilities", parsed.path[0]);
}
