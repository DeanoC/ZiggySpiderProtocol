const std = @import("std");

pub const ParseError = error{
    InvalidEnvelope,
    MissingField,
    InvalidType,
    UnsupportedType,
    InvalidBase64,
};

pub const Channel = enum {
    control,
    fsrpc,
};

pub const ControlType = enum {
    connect,
    connect_ack,
    session_attach,
    session_resume,
    debug_subscribe,
    debug_unsubscribe,
    ping,
    pong,
    err,
    unknown,
};

pub const FsrpcType = enum {
    t_version,
    r_version,
    t_attach,
    r_attach,
    t_walk,
    r_walk,
    t_open,
    r_open,
    t_read,
    r_read,
    t_write,
    r_write,
    t_stat,
    r_stat,
    t_clunk,
    r_clunk,
    t_flush,
    r_flush,
    err,
    unknown,
};

pub const ParsedMessage = struct {
    channel: Channel,
    control_type: ?ControlType = null,
    fsrpc_type: ?FsrpcType = null,

    id: ?[]u8 = null,
    tag: ?u32 = null,

    fid: ?u32 = null,
    newfid: ?u32 = null,
    mode: ?[]u8 = null,
    path: [][]u8 = &.{},

    msize: ?u32 = null,
    version: ?[]u8 = null,

    offset: ?u64 = null,
    count: ?u32 = null,
    data: ?[]u8 = null,

    payload_json: ?[]u8 = null,

    pub fn deinit(self: *ParsedMessage, allocator: std.mem.Allocator) void {
        if (self.id) |value| allocator.free(value);
        if (self.mode) |value| allocator.free(value);
        if (self.version) |value| allocator.free(value);
        if (self.data) |value| allocator.free(value);
        if (self.payload_json) |value| allocator.free(value);
        for (self.path) |segment| allocator.free(segment);
        if (self.path.len > 0) allocator.free(self.path);
        self.* = undefined;
    }
};

pub fn controlTypeFromString(value: []const u8) ControlType {
    if (std.mem.eql(u8, value, "control.connect")) return .connect;
    if (std.mem.eql(u8, value, "control.connect_ack")) return .connect_ack;
    if (std.mem.eql(u8, value, "control.session_attach")) return .session_attach;
    if (std.mem.eql(u8, value, "control.session_resume")) return .session_resume;
    if (std.mem.eql(u8, value, "control.debug_subscribe")) return .debug_subscribe;
    if (std.mem.eql(u8, value, "control.debug_unsubscribe")) return .debug_unsubscribe;
    if (std.mem.eql(u8, value, "control.ping")) return .ping;
    if (std.mem.eql(u8, value, "control.pong")) return .pong;
    if (std.mem.eql(u8, value, "control.error")) return .err;
    return .unknown;
}

pub fn fsrpcTypeFromString(value: []const u8) FsrpcType {
    if (std.mem.eql(u8, value, "fsrpc.t_version")) return .t_version;
    if (std.mem.eql(u8, value, "fsrpc.r_version")) return .r_version;
    if (std.mem.eql(u8, value, "fsrpc.t_attach")) return .t_attach;
    if (std.mem.eql(u8, value, "fsrpc.r_attach")) return .r_attach;
    if (std.mem.eql(u8, value, "fsrpc.t_walk")) return .t_walk;
    if (std.mem.eql(u8, value, "fsrpc.r_walk")) return .r_walk;
    if (std.mem.eql(u8, value, "fsrpc.t_open")) return .t_open;
    if (std.mem.eql(u8, value, "fsrpc.r_open")) return .r_open;
    if (std.mem.eql(u8, value, "fsrpc.t_read")) return .t_read;
    if (std.mem.eql(u8, value, "fsrpc.r_read")) return .r_read;
    if (std.mem.eql(u8, value, "fsrpc.t_write")) return .t_write;
    if (std.mem.eql(u8, value, "fsrpc.r_write")) return .r_write;
    if (std.mem.eql(u8, value, "fsrpc.t_stat")) return .t_stat;
    if (std.mem.eql(u8, value, "fsrpc.r_stat")) return .r_stat;
    if (std.mem.eql(u8, value, "fsrpc.t_clunk")) return .t_clunk;
    if (std.mem.eql(u8, value, "fsrpc.r_clunk")) return .r_clunk;
    if (std.mem.eql(u8, value, "fsrpc.t_flush")) return .t_flush;
    if (std.mem.eql(u8, value, "fsrpc.r_flush")) return .r_flush;
    if (std.mem.eql(u8, value, "fsrpc.error")) return .err;
    return .unknown;
}

pub fn controlTypeName(value: ControlType) []const u8 {
    return switch (value) {
        .connect => "control.connect",
        .connect_ack => "control.connect_ack",
        .session_attach => "control.session_attach",
        .session_resume => "control.session_resume",
        .debug_subscribe => "control.debug_subscribe",
        .debug_unsubscribe => "control.debug_unsubscribe",
        .ping => "control.ping",
        .pong => "control.pong",
        .err => "control.error",
        .unknown => "control.unknown",
    };
}

pub fn fsrpcTypeName(value: FsrpcType) []const u8 {
    return switch (value) {
        .t_version => "fsrpc.t_version",
        .r_version => "fsrpc.r_version",
        .t_attach => "fsrpc.t_attach",
        .r_attach => "fsrpc.r_attach",
        .t_walk => "fsrpc.t_walk",
        .r_walk => "fsrpc.r_walk",
        .t_open => "fsrpc.t_open",
        .r_open => "fsrpc.r_open",
        .t_read => "fsrpc.t_read",
        .r_read => "fsrpc.r_read",
        .t_write => "fsrpc.t_write",
        .r_write => "fsrpc.r_write",
        .t_stat => "fsrpc.t_stat",
        .r_stat => "fsrpc.r_stat",
        .t_clunk => "fsrpc.t_clunk",
        .r_clunk => "fsrpc.r_clunk",
        .t_flush => "fsrpc.t_flush",
        .r_flush => "fsrpc.r_flush",
        .err => "fsrpc.error",
        .unknown => "fsrpc.unknown",
    };
}
