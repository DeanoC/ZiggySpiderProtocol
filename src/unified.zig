const std = @import("std");
const types = @import("unified_types.zig");
const parse = @import("unified_parse.zig");
const build = @import("unified_build.zig");

pub const ParseError = types.ParseError;
pub const Channel = types.Channel;
pub const ControlType = types.ControlType;
pub const FsrpcType = types.FsrpcType;
pub const ParsedMessage = types.ParsedMessage;

pub const controlTypeFromString = types.controlTypeFromString;
pub const fsrpcTypeFromString = types.fsrpcTypeFromString;
pub const controlTypeName = types.controlTypeName;
pub const fsrpcTypeName = types.fsrpcTypeName;

pub const parseMessage = parse.parseMessage;

pub const buildControlAck = build.buildControlAck;
pub const buildControlError = build.buildControlError;
pub const buildFsrpcResponse = build.buildFsrpcResponse;
pub const buildFsrpcError = build.buildFsrpcError;
pub const encodeDataB64 = build.encodeDataB64;
pub const jsonEscape = build.jsonEscape;

test "unified facade: parse and build are wired" {
    const allocator = std.testing.allocator;

    var parsed = try parseMessage(allocator, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"req1\"}");
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(Channel.control, parsed.channel);

    const ack = try buildControlAck(allocator, .connect_ack, "req1", "{}");
    defer allocator.free(ack);
    try std.testing.expect(std.mem.indexOf(u8, ack, "control.connect_ack") != null);
}
