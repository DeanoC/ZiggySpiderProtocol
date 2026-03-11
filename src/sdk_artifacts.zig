const std = @import("std");
const unified = @import("unified.zig");
const unified_build = @import("unified_build.zig");
const spider_venom_wasm_constants = @import("spiderweb_node/spider_venom_wasm_constants.zig");

pub const control_protocol_name = "unified-v2";
pub const acheron_runtime_version = "acheron-1";
pub const node_fs_protocol_name = "unified-v2-fs";
pub const node_fs_protocol_proto: u32 = 2;

const legacy_rejected_control_names = [_][]const u8{
    "session.send",
    "control.debug_subscribe",
    "control.debug_unsubscribe",
    "control.node_service_watch",
    "control.node_service_unwatch",
    "control.node_service_event",
    "control.venom_watch",
    "control.venom_unwatch",
    "control.venom_event",
};

const legacy_rejected_acheron_names = [_][]const u8{
    "acheron.t_hello",
    "acheron.fs_t_*",
    "acheron.fs_r_*",
    "acheron.fs_evt_*",
    "acheron.fs_error",
};

const internal_helper_envelopes = [_][]const u8{
    "{\"t\":\"req\",...}",
    "{\"t\":\"res\",...}",
    "{\"t\":\"evt\",...}",
};

const spiderdocs_protocol_overview_files = [_][]const []const u8{
    &.{ "..", "..", "..", "SpiderDocs", "protocols", "control-agent-session.md" },
    &.{ "..", "..", "..", "SpiderDocs", "protocols", "acheron-worldfs.md" },
    &.{ "..", "..", "..", "SpiderDocs", "protocols", "node-service-catalog.md" },
    &.{ "..", "..", "..", "SpiderDocs", "protocols", "unified-v2-fs-migration.md" },
};

const canonical_reference_links = [_][]const u8{
    "../../Spiderweb/deps/spider-protocol/docs/protocols/unified-v2-control.md",
    "../../Spiderweb/deps/spider-protocol/docs/protocols/acheron-runtime-v1.md",
    "../../Spiderweb/deps/spider-protocol/docs/protocols/node-fs-unified-v2.md",
    "../../Spiderweb/deps/spider-protocol/docs/protocols/spider-venom-wasm-abi-v1.md",
    "../../Spiderweb/deps/spider-protocol/docs/protocols/namespace-driver-abi-v1.md",
};

const ArtifactKind = enum {
    protocol_json,
    wasm_abi_json,
    fixture_control_version_request,
    fixture_control_version_ack_response,
    fixture_control_connect_request,
    fixture_control_connect_ack_response,
    fixture_control_error_response,
    fixture_acheron_t_version_request,
    fixture_acheron_r_version_response,
    fixture_acheron_t_attach_request,
    fixture_acheron_r_attach_response,
    fixture_acheron_t_fs_hello_request,
    fixture_acheron_r_fs_hello_response,
    fixture_acheron_t_fs_lookup_request,
    fixture_acheron_r_fs_lookup_response,
    fixture_acheron_t_fs_getattr_request,
    fixture_acheron_r_fs_getattr_response,
    fixture_acheron_t_fs_readdirp_request,
    fixture_acheron_r_fs_readdirp_response,
    fixture_acheron_t_fs_open_request,
    fixture_acheron_r_fs_open_response,
    fixture_acheron_t_fs_read_request,
    fixture_acheron_r_fs_read_response,
    fixture_acheron_t_fs_write_request,
    fixture_acheron_r_fs_write_response,
    fixture_acheron_t_fs_close_request,
    fixture_acheron_r_fs_close_response,
    fixture_acheron_error_response,
    fixture_acheron_err_fs_response,
    fixture_acheron_e_fs_inval_event,
    doc_control_reference,
    doc_acheron_reference,
    doc_node_fs_reference,
    doc_wasm_abi_reference,
    ts_generated,
    py_generated,
    go_generated,
};

const Artifact = struct {
    kind: ArtifactKind,
    rel_path: []const []const u8,
};

const artifacts = [_]Artifact{
    .{ .kind = .protocol_json, .rel_path = &.{ "sdk", "spec", "protocol.json" } },
    .{ .kind = .wasm_abi_json, .rel_path = &.{ "sdk", "spec", "wasm_abi.json" } },
    .{ .kind = .fixture_control_version_request, .rel_path = &.{ "sdk", "spec", "fixtures", "control", "version.request.json" } },
    .{ .kind = .fixture_control_version_ack_response, .rel_path = &.{ "sdk", "spec", "fixtures", "control", "version_ack.response.json" } },
    .{ .kind = .fixture_control_connect_request, .rel_path = &.{ "sdk", "spec", "fixtures", "control", "connect.request.json" } },
    .{ .kind = .fixture_control_connect_ack_response, .rel_path = &.{ "sdk", "spec", "fixtures", "control", "connect_ack.response.json" } },
    .{ .kind = .fixture_control_error_response, .rel_path = &.{ "sdk", "spec", "fixtures", "control", "error.response.json" } },
    .{ .kind = .fixture_acheron_t_version_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_version.request.json" } },
    .{ .kind = .fixture_acheron_r_version_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_version.response.json" } },
    .{ .kind = .fixture_acheron_t_attach_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_attach.request.json" } },
    .{ .kind = .fixture_acheron_r_attach_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_attach.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_hello_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_hello.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_hello_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_hello.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_lookup_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_lookup.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_lookup_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_lookup.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_getattr_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_getattr.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_getattr_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_getattr.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_readdirp_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_readdirp.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_readdirp_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_readdirp.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_open_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_open.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_open_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_open.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_read_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_read.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_read_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_read.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_write_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_write.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_write_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_write.response.json" } },
    .{ .kind = .fixture_acheron_t_fs_close_request, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "t_fs_close.request.json" } },
    .{ .kind = .fixture_acheron_r_fs_close_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "r_fs_close.response.json" } },
    .{ .kind = .fixture_acheron_error_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "error.response.json" } },
    .{ .kind = .fixture_acheron_err_fs_response, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "err_fs.response.json" } },
    .{ .kind = .fixture_acheron_e_fs_inval_event, .rel_path = &.{ "sdk", "spec", "fixtures", "acheron", "e_fs_inval.event.json" } },
    .{ .kind = .doc_control_reference, .rel_path = &.{ "docs", "protocols", "unified-v2-control.md" } },
    .{ .kind = .doc_acheron_reference, .rel_path = &.{ "docs", "protocols", "acheron-runtime-v1.md" } },
    .{ .kind = .doc_node_fs_reference, .rel_path = &.{ "docs", "protocols", "node-fs-unified-v2.md" } },
    .{ .kind = .doc_wasm_abi_reference, .rel_path = &.{ "docs", "protocols", "spider-venom-wasm-abi-v1.md" } },
    .{ .kind = .ts_generated, .rel_path = &.{ "sdk", "typescript", "spiderweb-protocol", "src", "generated.ts" } },
    .{ .kind = .py_generated, .rel_path = &.{ "sdk", "python", "spiderweb_protocol", "spiderweb_protocol", "generated.py" } },
    .{ .kind = .go_generated, .rel_path = &.{ "sdk", "go", "spiderwebprotocol", "generated.go" } },
};

pub fn syncWorkspace(allocator: std.mem.Allocator) !void {
    for (artifacts) |artifact| {
        const rendered = try renderArtifact(allocator, artifact.kind);
        defer allocator.free(rendered);
        try writeWorkspaceFile(allocator, artifact.rel_path, rendered);
    }
}

pub fn renderArtifact(allocator: std.mem.Allocator, kind: ArtifactKind) ![]u8 {
    return switch (kind) {
        .protocol_json => renderProtocolJson(allocator),
        .wasm_abi_json => renderWasmAbiJson(allocator),
        .fixture_control_version_request => renderFixtureControlVersionRequest(allocator),
        .fixture_control_version_ack_response => renderFixtureControlVersionAckResponse(allocator),
        .fixture_control_connect_request => renderFixtureControlConnectRequest(allocator),
        .fixture_control_connect_ack_response => renderFixtureControlConnectAckResponse(allocator),
        .fixture_control_error_response => renderFixtureControlErrorResponse(allocator),
        .fixture_acheron_t_version_request => renderFixtureAcheronTVersionRequest(allocator),
        .fixture_acheron_r_version_response => renderFixtureAcheronRVersionResponse(allocator),
        .fixture_acheron_t_attach_request => renderFixtureAcheronTAttachRequest(allocator),
        .fixture_acheron_r_attach_response => renderFixtureAcheronRAttachResponse(allocator),
        .fixture_acheron_t_fs_hello_request => renderFixtureAcheronTFsHelloRequest(allocator),
        .fixture_acheron_r_fs_hello_response => renderFixtureAcheronRFsHelloResponse(allocator),
        .fixture_acheron_t_fs_lookup_request => renderFixtureAcheronTFsLookupRequest(allocator),
        .fixture_acheron_r_fs_lookup_response => renderFixtureAcheronRFsLookupResponse(allocator),
        .fixture_acheron_t_fs_getattr_request => renderFixtureAcheronTFsGetattrRequest(allocator),
        .fixture_acheron_r_fs_getattr_response => renderFixtureAcheronRFsGetattrResponse(allocator),
        .fixture_acheron_t_fs_readdirp_request => renderFixtureAcheronTFsReaddirpRequest(allocator),
        .fixture_acheron_r_fs_readdirp_response => renderFixtureAcheronRFsReaddirpResponse(allocator),
        .fixture_acheron_t_fs_open_request => renderFixtureAcheronTFsOpenRequest(allocator),
        .fixture_acheron_r_fs_open_response => renderFixtureAcheronRFsOpenResponse(allocator),
        .fixture_acheron_t_fs_read_request => renderFixtureAcheronTFsReadRequest(allocator),
        .fixture_acheron_r_fs_read_response => renderFixtureAcheronRFsReadResponse(allocator),
        .fixture_acheron_t_fs_write_request => renderFixtureAcheronTFsWriteRequest(allocator),
        .fixture_acheron_r_fs_write_response => renderFixtureAcheronRFsWriteResponse(allocator),
        .fixture_acheron_t_fs_close_request => renderFixtureAcheronTFsCloseRequest(allocator),
        .fixture_acheron_r_fs_close_response => renderFixtureAcheronRFsCloseResponse(allocator),
        .fixture_acheron_error_response => renderFixtureAcheronErrorResponse(allocator),
        .fixture_acheron_err_fs_response => renderFixtureAcheronErrFsResponse(allocator),
        .fixture_acheron_e_fs_inval_event => renderFixtureAcheronEFsInvalEvent(allocator),
        .doc_control_reference => renderControlReferenceDoc(allocator),
        .doc_acheron_reference => renderAcheronReferenceDoc(allocator),
        .doc_node_fs_reference => renderNodeFsReferenceDoc(allocator),
        .doc_wasm_abi_reference => renderWasmAbiReferenceDoc(allocator),
        .ts_generated => renderTypescriptGenerated(allocator),
        .py_generated => renderPythonGenerated(allocator),
        .go_generated => renderGoGenerated(allocator),
    };
}

fn renderProtocolJson(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("{\n");
    try writer.writeAll("  \"generated_by\": \"src/sdk_artifacts.zig\",\n");
    try writer.writeAll("  \"canonical_repo\": \"Spiderweb/deps/spider-protocol\",\n");
    try writer.writeAll("  \"control_protocol\": ");
    try writeJsonString(writer, control_protocol_name);
    try writer.writeAll(",\n  \"acheron_runtime\": ");
    try writeJsonString(writer, acheron_runtime_version);
    try writer.writeAll(",\n  \"node_fs_protocol\": {\n    \"protocol\": ");
    try writeJsonString(writer, node_fs_protocol_name);
    try writer.writeAll(",\n    \"proto\": ");
    try writer.print("{d}", .{node_fs_protocol_proto});
    try writer.writeAll("\n  },\n");
    try writer.writeAll("  \"envelope_rules\": [\n");
    try writeJsonString(writer, "channel is required on every public control and acheron message");
    try writer.writeAll(",\n    ");
    try writeJsonString(writer, "type must match the selected channel namespace");
    try writer.writeAll(",\n    ");
    try writeJsonString(writer, "legacy compatibility names are rejected by the unified parser");
    try writer.writeAll(",\n    ");
    try writeJsonString(writer, "control request correlation uses id; acheron request correlation uses tag");
    try writer.writeAll("\n  ],\n");
    try writer.writeAll("  \"handshakes\": {\n");
    try writer.writeAll("    \"control\": [\n");
    try writer.writeAll("      {\"message\": \"control.version\", \"required_payload\": {\"protocol\": \"unified-v2\"}},\n");
    try writer.writeAll("      {\"message\": \"control.connect\"}\n");
    try writer.writeAll("    ],\n");
    try writer.writeAll("    \"acheron_runtime\": [\n");
    try writer.writeAll("      {\"message\": \"acheron.t_version\", \"required_fields\": {\"version\": \"acheron-1\"}},\n");
    try writer.writeAll("      {\"message\": \"acheron.t_attach\"}\n");
    try writer.writeAll("    ],\n");
    try writer.writeAll("    \"node_fs\": [\n");
    try writer.writeAll("      {\"message\": \"acheron.t_fs_hello\", \"required_payload\": {\"protocol\": \"unified-v2-fs\", \"proto\": 2}}\n");
    try writer.writeAll("    ]\n");
    try writer.writeAll("  },\n");
    try writer.writeAll("  \"messages\": {\n    \"control\": [\n");
    try writeControlMessageSpec(writer);
    try writer.writeAll("\n    ],\n    \"acheron\": [\n");
    try writeAcheronMessageSpec(writer);
    try writer.writeAll("\n    ]\n  },\n");
    try writer.writeAll("  \"errors\": {\n");
    try writer.writeAll("    \"control\": {\"type\": \"control.error\", \"fields\": [\"channel\", \"type\", \"id?\", \"ok=false\", \"error.code\", \"error.message\"]},\n");
    try writer.writeAll("    \"acheron\": {\"type\": \"acheron.error\", \"fields\": [\"channel\", \"type\", \"tag?\", \"ok=false\", \"error.code\", \"error.message\"]},\n");
    try writer.writeAll("    \"acheron_fs\": {\"type\": \"acheron.err_fs\", \"fields\": [\"channel\", \"type\", \"tag?\", \"ok=false\", \"error.errno\", \"error.message\"]}\n");
    try writer.writeAll("  },\n");
    try writer.writeAll("  \"legacy_exclusions\": {\n");
    try writer.writeAll("    \"control\": [\n");
    try writeStringArrayLines(writer, &legacy_rejected_control_names, 6);
    try writer.writeAll("    ],\n    \"acheron\": [\n");
    try writeStringArrayLines(writer, &legacy_rejected_acheron_names, 6);
    try writer.writeAll("    ],\n    \"internal_helpers\": [\n");
    try writeStringArrayLines(writer, &internal_helper_envelopes, 6);
    try writer.writeAll("    ]\n  }\n}\n");

    return out.toOwnedSlice(allocator);
}

fn renderWasmAbiJson(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("{\n");
    try writer.print("  \"abi_version\": {d},\n", .{spider_venom_wasm_constants.abi_version});
    try writer.writeAll("  \"exports\": {\n");
    try writer.writeAll("    \"abi_version\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.abi_version_export_name);
    try writer.writeAll(",\n    \"alloc\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.alloc_export_name);
    try writer.writeAll(",\n    \"invoke_json\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.invoke_json_export_name);
    try writer.writeAll("\n  },\n");
    try writer.writeAll("  \"imports\": {\n");
    try writer.writeAll("    \"module\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.import_module_name);
    try writer.writeAll(",\n");
    try writer.writeAll("    \"functions\": [\n");
    try writer.writeAll("      {\"name\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.capabilities_export_name);
    try writer.writeAll(", \"returns\": \"u64\"},\n");
    try writer.writeAll("      {\"name\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.now_ms_export_name);
    try writer.writeAll(", \"returns\": \"u64\"},\n");
    try writer.writeAll("      {\"name\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.log_export_name);
    try writer.writeAll(", \"returns\": \"u32\"},\n");
    try writer.writeAll("      {\"name\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.random_fill_export_name);
    try writer.writeAll(", \"returns\": \"u32\"},\n");
    try writer.writeAll("      {\"name\": ");
    try writeJsonString(writer, spider_venom_wasm_constants.emit_event_json_export_name);
    try writer.writeAll(", \"returns\": \"u32\"}\n");
    try writer.writeAll("    ]\n  },\n");
    try writer.writeAll("  \"capability_bits\": [\n");
    try writer.print("    {{\"bit\": {d}, \"name\": \"log\"}},\n", .{spider_venom_wasm_constants.capability_bit_log});
    try writer.print("    {{\"bit\": {d}, \"name\": \"clock\"}},\n", .{spider_venom_wasm_constants.capability_bit_clock});
    try writer.print("    {{\"bit\": {d}, \"name\": \"random\"}},\n", .{spider_venom_wasm_constants.capability_bit_random});
    try writer.print("    {{\"bit\": {d}, \"name\": \"emit_event\"}}\n", .{spider_venom_wasm_constants.capability_bit_emit_event});
    try writer.writeAll("  ]\n}\n");

    return out.toOwnedSlice(allocator);
}

fn renderControlReferenceDoc(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll(
        \\# Unified-v2 Control Protocol
        \\
        \\Status: generated from `sdk/spec/protocol.json`
        \\
        \\This is the canonical control-plane reference for public Spiderweb clients. The source of truth is the current Zig implementation in `unified_types.zig`, `unified_parse.zig`, and `unified_build.zig`.
        \\
        \\## Constants
        \\
        \\- protocol name: `unified-v2`
        \\- websocket endpoint: control lives on the base websocket path (`/`)
        \\- request correlation field: `id`
        \\- error message type: `control.error`
        \\
        \\## Envelope Rules
        \\
        \\- Every message must include `channel: "control"`.
        \\- Every message must include a `type` in the `control.*` namespace.
        \\- `id` is required for request/response correlation in normal client flows.
        \\- `control.error` uses `ok: false` plus `error.code` and `error.message`.
        \\- Legacy control names rejected by the current parser are excluded from this reference.
        \\
        \\## Required Handshake
        \\
        \\1. Send `control.version` with payload `{"protocol":"unified-v2"}`.
        \\2. Wait for `control.version_ack`.
        \\3. Send `control.connect`.
        \\4. Wait for `control.connect_ack`.
        \\
        \\## Public Message Catalog
        \\
        \\| Message | Category | Direction |
        \\| --- | --- | --- |
    );
    try writeControlDocRows(writer);
    try writer.writeAll(
        \\
        \\## Error Envelope
        \\
        \\Canonical error shape:
        \\
        \\```json
        \\{"channel":"control","type":"control.error","id":"req-1","ok":false,"error":{"code":"missing_field","message":"..."}}
        \\```
        \\
        \\See fixture: `sdk/spec/fixtures/control/error.response.json`.
        \\
        \\## Explicit Exclusions
        \\
        \\These names are not part of the public protocol surface represented here:
        \\
    );
    for (legacy_rejected_control_names) |name| {
        try writer.writeAll("- `");
        try writer.writeAll(name);
        try writer.writeAll("`\n");
    }
    return out.toOwnedSlice(allocator);
}

fn renderAcheronReferenceDoc(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll(
        \\# Acheron Runtime Protocol (`acheron-1`)
        \\
        \\Status: generated from `sdk/spec/protocol.json`
        \\
        \\This reference covers the public Acheron runtime message envelope used before node-FS specific operations. The source of truth is the current Zig implementation in `unified_types.zig`, `unified_parse.zig`, and `unified_build.zig`.
        \\
        \\## Constants
        \\
        \\- runtime version: `acheron-1`
        \\- channel: `acheron`
        \\- request correlation field: `tag`
        \\- generic error message type: `acheron.error`
        \\
        \\## Envelope Rules
        \\
        \\- Every runtime message must include `channel: "acheron"`.
        \\- Every `type` must be in the `acheron.*` namespace.
        \\- Runtime requests correlate by `tag`.
        \\- Generic runtime errors use `acheron.error`.
        \\
        \\## Required Runtime Handshake
        \\
        \\1. Send `acheron.t_version` with `version: "acheron-1"`.
        \\2. Wait for `acheron.r_version`.
        \\3. Send `acheron.t_attach`.
        \\4. Wait for `acheron.r_attach`.
        \\
        \\## Public Runtime Catalog
        \\
        \\| Message | Category | Direction |
        \\| --- | --- | --- |
    );
    try writeAcheronDocRows(writer, .runtime_only);
    try writer.writeAll(
        \\
        \\## Generic Error Envelope
        \\
        \\```json
        \\{"channel":"acheron","type":"acheron.error","tag":5,"ok":false,"error":{"code":"forbidden","message":"..."}}
        \\```
        \\
        \\See fixture: `sdk/spec/fixtures/acheron/error.response.json`.
        \\
        \\## Explicit Exclusions
        \\
    );
    for (legacy_rejected_acheron_names) |name| {
        try writer.writeAll("- `");
        try writer.writeAll(name);
        try writer.writeAll("`\n");
    }
    try writer.writeAll("- internal helper envelopes such as `{\"t\":\"req\"}` are implementation detail only\n");
    return out.toOwnedSlice(allocator);
}

fn renderNodeFsReferenceDoc(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll(
        \\# Node FS Protocol (`unified-v2-fs`)
        \\
        \\Status: generated from `sdk/spec/protocol.json`
        \\
        \\This is the canonical public reference for the node filesystem handshake and Acheron FS message family carried over websocket text frames on `/v2/fs`.
        \\
        \\## Constants
        \\
        \\- handshake message: `acheron.t_fs_hello`
        \\- required payload: `{"protocol":"unified-v2-fs","proto":2}`
        \\- request correlation field: `tag`
        \\- fs error message type: `acheron.err_fs`
        \\- fs invalidation events: `acheron.e_fs_inval`, `acheron.e_fs_inval_dir`
        \\
        \\## Required Node FS Handshake
        \\
        \\1. Open websocket to `/v2/fs`.
        \\2. Send `acheron.t_fs_hello` with payload `{"protocol":"unified-v2-fs","proto":2}`.
        \\3. Wait for `acheron.r_fs_hello`.
        \\
        \\If FS auth is enforced, the hello payload may also include `auth_token`. Node-to-node flows may also include `node_id` and `node_secret`.
        \\
        \\## Public Node FS Catalog
        \\
        \\| Message | Category | Direction |
        \\| --- | --- | --- |
    );
    try writeAcheronDocRows(writer, .node_fs_only);
    try writer.writeAll(
        \\
        \\## FS Error Envelope
        \\
        \\```json
        \\{"channel":"acheron","type":"acheron.err_fs","tag":7,"ok":false,"error":{"errno":2,"message":"not found"}}
        \\```
        \\
        \\## Representative Fixtures
        \\
        \\- `sdk/spec/fixtures/acheron/t_fs_lookup.request.json`
        \\- `sdk/spec/fixtures/acheron/r_fs_lookup.response.json`
        \\- `sdk/spec/fixtures/acheron/t_fs_read.request.json`
        \\- `sdk/spec/fixtures/acheron/r_fs_read.response.json`
        \\- `sdk/spec/fixtures/acheron/e_fs_inval.event.json`
        \\
        \\## Notes
        \\
        \\- Binary payload bytes are represented in JSON as `data_b64`.
        \\- The older helper envelope family `{"t":"req"}` / `{"t":"res"}` / `{"t":"evt"}` remains internal and is not part of the public SDK surface.
        \\
    );
    return out.toOwnedSlice(allocator);
}

fn renderWasmAbiReferenceDoc(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll(
        \\# Spider Venom WASM ABI v1
        \\
        \\Status: generated from `sdk/spec/wasm_abi.json`
        \\
        \\This document captures the current Spider Venom WASM ABI metadata exposed by the canonical Zig runtime. It is reference material for future SDK work; this milestone does not add language-specific venom authoring libraries.
        \\
        \\## Exports
        \\
    );
    try writer.writeAll("- `");
    try writer.writeAll(spider_venom_wasm_constants.abi_version_export_name);
    try writer.writeAll("`\n- `");
    try writer.writeAll(spider_venom_wasm_constants.alloc_export_name);
    try writer.writeAll("`\n- `");
    try writer.writeAll(spider_venom_wasm_constants.invoke_json_export_name);
    try writer.writeAll("`\n\n## Host Import Module\n\n- `");
    try writer.writeAll(spider_venom_wasm_constants.import_module_name);
    try writer.writeAll("`\n\n## Host Imports\n\n- `");
    try writer.writeAll(spider_venom_wasm_constants.capabilities_export_name);
    try writer.writeAll("() -> u64`\n- `");
    try writer.writeAll(spider_venom_wasm_constants.now_ms_export_name);
    try writer.writeAll("() -> u64`\n- `");
    try writer.writeAll(spider_venom_wasm_constants.log_export_name);
    try writer.writeAll("(level, ptr, len) -> u32`\n- `");
    try writer.writeAll(spider_venom_wasm_constants.random_fill_export_name);
    try writer.writeAll("(ptr, len) -> u32`\n- `");
    try writer.writeAll(spider_venom_wasm_constants.emit_event_json_export_name);
    try writer.writeAll("(ptr, len) -> u32`\n\n");
    try writer.writeAll(
        \\## Capability Bits
        \\
        \\- `0`: log
        \\- `1`: clock
        \\- `2`: random
        \\- `3`: emit_event
        \\
        \\## Related Canonical References
        \\
        \\- `docs/protocols/namespace-driver-abi-v1.md`
        \\- `sdk/spec/wasm_abi.json`
        \\
    );
    return out.toOwnedSlice(allocator);
}

fn renderTypescriptGenerated(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("// Generated from src/sdk_artifacts.zig. Do not edit by hand.\n");
    try writer.writeAll("export const controlProtocol = ");
    try writeTsString(writer, control_protocol_name);
    try writer.writeAll(" as const;\n");
    try writer.writeAll("export const acheronRuntimeVersion = ");
    try writeTsString(writer, acheron_runtime_version);
    try writer.writeAll(" as const;\n");
    try writer.writeAll("export const nodeFsProtocol = { protocol: ");
    try writeTsString(writer, node_fs_protocol_name);
    try writer.writeAll(", proto: ");
    try writer.print("{d}", .{node_fs_protocol_proto});
    try writer.writeAll(" } as const;\n\n");

    try writer.writeAll("export const controlMessageTypes = [\n");
    try writeTsMessageArray(writer, .control_all);
    try writer.writeAll("] as const;\n");
    try writer.writeAll("export type ControlMessageType = typeof controlMessageTypes[number];\n\n");
    try writer.writeAll("export const acheronMessageTypes = [\n");
    try writeTsMessageArray(writer, .acheron_all);
    try writer.writeAll("] as const;\n");
    try writer.writeAll("export type AcheronMessageType = typeof acheronMessageTypes[number];\n\n");
    try writer.writeAll("export const runtimeAcheronMessageTypes = [\n");
    try writeTsMessageArray(writer, .acheron_runtime_only);
    try writer.writeAll("] as const;\n");
    try writer.writeAll("export const nodeFsAcheronMessageTypes = [\n");
    try writeTsMessageArray(writer, .acheron_node_fs_only);
    try writer.writeAll("] as const;\n");
    try writer.writeAll("export const legacyRejectedControlMessageTypes = [\n");
    try writeTsStringArray(writer, &legacy_rejected_control_names, 2);
    try writer.writeAll("] as const;\n");
    try writer.writeAll("export const legacyRejectedAcheronMessageTypes = [\n");
    try writeTsStringArray(writer, &legacy_rejected_acheron_names, 2);
    try writer.writeAll("] as const;\n");
    try writer.writeAll("export type Channel = \"control\" | \"acheron\";\n");
    try writer.writeAll("export type ProtocolEnvelopeRule =\n");
    try writer.writeAll("  | \"channel-required\"\n  | \"type-must-match-channel\"\n  | \"legacy-names-rejected\"\n  | \"correlation-by-id-or-tag\";\n");
    try writer.writeAll("export const protocolEnvelopeRules: readonly ProtocolEnvelopeRule[] = [\n");
    try writer.writeAll("  \"channel-required\",\n  \"type-must-match-channel\",\n  \"legacy-names-rejected\",\n  \"correlation-by-id-or-tag\",\n];\n");
    return out.toOwnedSlice(allocator);
}

fn renderPythonGenerated(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("# Generated from src/sdk_artifacts.zig. Do not edit by hand.\n");
    try writer.writeAll("from __future__ import annotations\n\n");
    try writer.writeAll("CONTROL_PROTOCOL = ");
    try writePythonString(writer, control_protocol_name);
    try writer.writeAll("\nACHERON_RUNTIME_VERSION = ");
    try writePythonString(writer, acheron_runtime_version);
    try writer.writeAll("\nNODE_FS_PROTOCOL = ");
    try writePythonString(writer, node_fs_protocol_name);
    try writer.print("\nNODE_FS_PROTO = {d}\n\n", .{node_fs_protocol_proto});
    try writer.writeAll("CONTROL_MESSAGE_TYPES = (\n");
    try writePythonMessageTuple(writer, .control_all);
    try writer.writeAll(")\n\nACHERON_MESSAGE_TYPES = (\n");
    try writePythonMessageTuple(writer, .acheron_all);
    try writer.writeAll(")\n\nRUNTIME_ACHERON_MESSAGE_TYPES = (\n");
    try writePythonMessageTuple(writer, .acheron_runtime_only);
    try writer.writeAll(")\n\nNODE_FS_ACHERON_MESSAGE_TYPES = (\n");
    try writePythonMessageTuple(writer, .acheron_node_fs_only);
    try writer.writeAll(")\n\nLEGACY_REJECTED_CONTROL_MESSAGE_TYPES = (\n");
    try writePythonStringTuple(writer, &legacy_rejected_control_names, 1);
    try writer.writeAll(")\n\nLEGACY_REJECTED_ACHERON_MESSAGE_TYPES = (\n");
    try writePythonStringTuple(writer, &legacy_rejected_acheron_names, 1);
    try writer.writeAll(")\n");
    return out.toOwnedSlice(allocator);
}

fn renderGoGenerated(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const writer = out.writer(allocator);

    try writer.writeAll("// Code generated from src/sdk_artifacts.zig. DO NOT EDIT.\n");
    try writer.writeAll("package spiderwebprotocol\n\n");
    try writer.writeAll("const ControlProtocol = ");
    try writeGoString(writer, control_protocol_name);
    try writer.writeAll("\nconst AcheronRuntimeVersion = ");
    try writeGoString(writer, acheron_runtime_version);
    try writer.writeAll("\nconst NodeFSProtocol = ");
    try writeGoString(writer, node_fs_protocol_name);
    try writer.print("\nconst NodeFSProto uint32 = {d}\n\n", .{node_fs_protocol_proto});
    try writer.writeAll("var ControlMessageTypes = []string{\n");
    try writeGoMessageArray(writer, .control_all);
    try writer.writeAll("}\n\nvar AcheronMessageTypes = []string{\n");
    try writeGoMessageArray(writer, .acheron_all);
    try writer.writeAll("}\n\nvar RuntimeAcheronMessageTypes = []string{\n");
    try writeGoMessageArray(writer, .acheron_runtime_only);
    try writer.writeAll("}\n\nvar NodeFSAcheronMessageTypes = []string{\n");
    try writeGoMessageArray(writer, .acheron_node_fs_only);
    try writer.writeAll("}\n\nvar LegacyRejectedControlMessageTypes = []string{\n");
    try writeGoStringArray(writer, &legacy_rejected_control_names, 1);
    try writer.writeAll("}\n\nvar LegacyRejectedAcheronMessageTypes = []string{\n");
    try writeGoStringArray(writer, &legacy_rejected_acheron_names, 1);
    try writer.writeAll("}\n");
    return out.toOwnedSlice(allocator);
}

fn renderFixtureControlVersionRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"control\",\"type\":\"control.version\",\"id\":\"version-1\",\"payload\":{\"protocol\":\"unified-v2\"}}\n");
}

fn renderFixtureControlVersionAckResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildControlAck(
        allocator,
        .version_ack,
        "version-1",
        "{\"protocol\":\"unified-v2\",\"acheron_runtime\":\"acheron-1\",\"acheron_node\":\"unified-v2-fs\",\"acheron_node_proto\":2}",
    );
}

fn renderFixtureControlConnectRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"control\",\"type\":\"control.connect\",\"id\":\"connect-1\"}\n");
}

fn renderFixtureControlConnectAckResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildControlAck(
        allocator,
        .connect_ack,
        "connect-1",
        "{\"agent_id\":\"spiderweb\",\"project_id\":\"proj-demo\",\"session\":\"sess-demo\",\"protocol\":\"unified-v2\",\"role\":\"admin\",\"bootstrap_only\":false,\"bootstrap_message\":null,\"requires_session_attach\":true,\"workspace\":{\"mounts\":[{\"mount_path\":\"/nodes/local/fs\",\"fs_url\":\"ws://127.0.0.1:18891/v2/fs\",\"state\":\"online\",\"online\":true}]}}",
    );
}

fn renderFixtureControlErrorResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildControlError(allocator, "connect-1", "missing_field", "project_id is required");
}

fn renderFixtureAcheronTVersionRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_version\",\"tag\":1,\"msize\":1048576,\"version\":\"acheron-1\"}\n");
}

fn renderFixtureAcheronRVersionResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .r_version, 1, "{\"msize\":1048576,\"version\":\"acheron-1\"}");
}

fn renderFixtureAcheronTAttachRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_attach\",\"tag\":2,\"fid\":1}\n");
}

fn renderFixtureAcheronRAttachResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .r_attach, 2, "{\"layout\":\"unified-v2-fs\",\"roots\":[\"/\",\"/global\",\"/nodes\",\"/agents\"]}");
}

fn renderFixtureAcheronTFsHelloRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_hello\",\"tag\":3,\"payload\":{\"protocol\":\"unified-v2-fs\",\"proto\":2}}\n");
}

fn renderFixtureAcheronRFsHelloResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_hello, 3, "{\"protocol\":\"unified-v2-fs\",\"proto\":2,\"capabilities\":{\"exports\":true,\"read\":true,\"write\":true}}");
}

fn renderFixtureAcheronTFsLookupRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_lookup\",\"tag\":7,\"node\":42,\"payload\":{\"name\":\"README.md\"}}\n");
}

fn renderFixtureAcheronRFsLookupResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_lookup, 7, "{\"node\":42,\"name\":\"README.md\",\"kind\":\"file\"}");
}

fn renderFixtureAcheronTFsGetattrRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_getattr\",\"tag\":8,\"node\":42,\"payload\":{}}\n");
}

fn renderFixtureAcheronRFsGetattrResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_getattr, 8, "{\"node\":42,\"kind\":\"file\",\"size\":123,\"mode\":\"rw\"}");
}

fn renderFixtureAcheronTFsReaddirpRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_readdirp\",\"tag\":9,\"node\":41,\"payload\":{\"cookie\":0,\"count\":128}}\n");
}

fn renderFixtureAcheronRFsReaddirpResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_readdirp, 9, "{\"entries\":[{\"name\":\"README.md\",\"kind\":\"file\"},{\"name\":\"docs\",\"kind\":\"dir\"}],\"next\":0,\"eof\":true}");
}

fn renderFixtureAcheronTFsOpenRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_open\",\"tag\":10,\"node\":42,\"payload\":{\"mode\":\"r\"}}\n");
}

fn renderFixtureAcheronRFsOpenResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_open, 10, "{\"handle\":1001,\"mode\":\"r\"}");
}

fn renderFixtureAcheronTFsReadRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_read\",\"tag\":11,\"h\":1001,\"payload\":{\"offset\":0,\"count\":4096}}\n");
}

fn renderFixtureAcheronRFsReadResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_read, 11, "{\"data_b64\":\"SGVsbG8gU3BpZGVyd2ViCg==\",\"eof\":true}");
}

fn renderFixtureAcheronTFsWriteRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_write\",\"tag\":12,\"h\":1001,\"payload\":{\"offset\":0,\"data_b64\":\"aGk=\"}}\n");
}

fn renderFixtureAcheronRFsWriteResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_write, 12, "{\"count\":2}");
}

fn renderFixtureAcheronTFsCloseRequest(allocator: std.mem.Allocator) ![]u8 {
    return allocator.dupe(u8, "{\"channel\":\"acheron\",\"type\":\"acheron.t_fs_close\",\"tag\":13,\"h\":1001,\"payload\":{}}\n");
}

fn renderFixtureAcheronRFsCloseResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcResponse(allocator, .fs_r_close, 13, "{}");
}

fn renderFixtureAcheronErrorResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcError(allocator, 4, "forbidden", "attach requires an active session");
}

fn renderFixtureAcheronErrFsResponse(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcFsError(allocator, 7, 2, "not found");
}

fn renderFixtureAcheronEFsInvalEvent(allocator: std.mem.Allocator) ![]u8 {
    return unified_build.buildFsrpcEvent(allocator, .fs_evt_inval, "{\"node\":42,\"what\":\"all\"}");
}

const AcheronDocFilter = enum {
    runtime_only,
    node_fs_only,
};

const GeneratedMessageArrayKind = enum {
    control_all,
    acheron_all,
    acheron_runtime_only,
    acheron_node_fs_only,
};

fn writeControlMessageSpec(writer: anytype) !void {
    var first = true;
    inline for (@typeInfo(unified.ControlType).@"enum".fields) |field| {
        const value: unified.ControlType = @enumFromInt(field.value);
        if (value == .unknown) continue;
        if (!first) try writer.writeAll(",\n");
        first = false;
        const name = unified.controlTypeName(value);
        try writer.writeAll("      {\"name\": ");
        try writeJsonString(writer, name);
        try writer.writeAll(", \"category\": ");
        try writeJsonString(writer, controlCategory(name));
        try writer.writeAll(", \"direction\": ");
        try writeJsonString(writer, controlDirection(name));
        try writer.writeAll("}");
    }
}

fn writeAcheronMessageSpec(writer: anytype) !void {
    var first = true;
    inline for (@typeInfo(unified.FsrpcType).@"enum".fields) |field| {
        const value: unified.FsrpcType = @enumFromInt(field.value);
        if (value == .unknown) continue;
        if (!first) try writer.writeAll(",\n");
        first = false;
        const name = unified.acheronTypeName(value);
        try writer.writeAll("      {\"name\": ");
        try writeJsonString(writer, name);
        try writer.writeAll(", \"category\": ");
        try writeJsonString(writer, acheronCategory(name));
        try writer.writeAll(", \"direction\": ");
        try writeJsonString(writer, acheronDirection(name));
        try writer.writeAll("}");
    }
}

fn writeControlDocRows(writer: anytype) !void {
    inline for (@typeInfo(unified.ControlType).@"enum".fields) |field| {
        const value: unified.ControlType = @enumFromInt(field.value);
        if (value == .unknown) continue;
        const name = unified.controlTypeName(value);
        try writer.writeAll("| `");
        try writer.writeAll(name);
        try writer.writeAll("` | ");
        try writer.writeAll(controlCategory(name));
        try writer.writeAll(" | ");
        try writer.writeAll(controlDirection(name));
        try writer.writeAll(" |\n");
    }
}

fn writeAcheronDocRows(writer: anytype, comptime filter: AcheronDocFilter) !void {
    inline for (@typeInfo(unified.FsrpcType).@"enum".fields) |field| {
        const value: unified.FsrpcType = @enumFromInt(field.value);
        if (value == .unknown) continue;
        const name = unified.acheronTypeName(value);
        const category = acheronCategory(name);
        const include = switch (filter) {
            .runtime_only => std.mem.eql(u8, category, "runtime") or std.mem.eql(u8, name, "acheron.error"),
            .node_fs_only => std.mem.eql(u8, category, "node_fs") or std.mem.eql(u8, name, "acheron.err_fs"),
        };
        if (include) {
            try writer.writeAll("| `");
            try writer.writeAll(name);
            try writer.writeAll("` | ");
            try writer.writeAll(category);
            try writer.writeAll(" | ");
            try writer.writeAll(acheronDirection(name));
            try writer.writeAll(" |\n");
        }
    }
}

fn writeTsMessageArray(writer: anytype, comptime kind: GeneratedMessageArrayKind) !void {
    switch (kind) {
        .control_all => {
            inline for (@typeInfo(unified.ControlType).@"enum".fields) |field| {
                const value: unified.ControlType = @enumFromInt(field.value);
                if (value == .unknown) continue;
                try writer.writeAll("  ");
                try writeTsString(writer, unified.controlTypeName(value));
                try writer.writeAll(",\n");
            }
        },
        .acheron_all, .acheron_runtime_only, .acheron_node_fs_only => {
            inline for (@typeInfo(unified.FsrpcType).@"enum".fields) |field| {
                const value: unified.FsrpcType = @enumFromInt(field.value);
                if (value == .unknown) continue;
                const name = unified.acheronTypeName(value);
                const include = switch (kind) {
                    .acheron_all => true,
                    .acheron_runtime_only => std.mem.eql(u8, acheronCategory(name), "runtime"),
                    .acheron_node_fs_only => std.mem.eql(u8, acheronCategory(name), "node_fs"),
                    else => false,
                };
                if (include) {
                    try writer.writeAll("  ");
                    try writeTsString(writer, name);
                    try writer.writeAll(",\n");
                }
            }
        },
    }
}

fn writePythonMessageTuple(writer: anytype, comptime kind: GeneratedMessageArrayKind) !void {
    switch (kind) {
        .control_all => {
            inline for (@typeInfo(unified.ControlType).@"enum".fields) |field| {
                const value: unified.ControlType = @enumFromInt(field.value);
                if (value == .unknown) continue;
                try writer.writeAll("    ");
                try writePythonString(writer, unified.controlTypeName(value));
                try writer.writeAll(",\n");
            }
        },
        .acheron_all, .acheron_runtime_only, .acheron_node_fs_only => {
            inline for (@typeInfo(unified.FsrpcType).@"enum".fields) |field| {
                const value: unified.FsrpcType = @enumFromInt(field.value);
                if (value == .unknown) continue;
                const name = unified.acheronTypeName(value);
                const include = switch (kind) {
                    .acheron_all => true,
                    .acheron_runtime_only => std.mem.eql(u8, acheronCategory(name), "runtime"),
                    .acheron_node_fs_only => std.mem.eql(u8, acheronCategory(name), "node_fs"),
                    else => false,
                };
                if (include) {
                    try writer.writeAll("    ");
                    try writePythonString(writer, name);
                    try writer.writeAll(",\n");
                }
            }
        },
    }
}

fn writeGoMessageArray(writer: anytype, comptime kind: GeneratedMessageArrayKind) !void {
    switch (kind) {
        .control_all => {
            inline for (@typeInfo(unified.ControlType).@"enum".fields) |field| {
                const value: unified.ControlType = @enumFromInt(field.value);
                if (value == .unknown) continue;
                try writer.writeAll("    ");
                try writeGoString(writer, unified.controlTypeName(value));
                try writer.writeAll(",\n");
            }
        },
        .acheron_all, .acheron_runtime_only, .acheron_node_fs_only => {
            inline for (@typeInfo(unified.FsrpcType).@"enum".fields) |field| {
                const value: unified.FsrpcType = @enumFromInt(field.value);
                if (value == .unknown) continue;
                const name = unified.acheronTypeName(value);
                const include = switch (kind) {
                    .acheron_all => true,
                    .acheron_runtime_only => std.mem.eql(u8, acheronCategory(name), "runtime"),
                    .acheron_node_fs_only => std.mem.eql(u8, acheronCategory(name), "node_fs"),
                    else => false,
                };
                if (include) {
                    try writer.writeAll("    ");
                    try writeGoString(writer, name);
                    try writer.writeAll(",\n");
                }
            }
        },
    }
}

fn writeStringArrayLines(writer: anytype, values: []const []const u8, indent_spaces: usize) !void {
    var index: usize = 0;
    while (index < values.len) : (index += 1) {
        try writeIndent(writer, indent_spaces);
        try writeJsonString(writer, values[index]);
        if (index + 1 < values.len) try writer.writeAll(",");
        try writer.writeAll("\n");
    }
}

fn writeTsStringArray(writer: anytype, values: []const []const u8, indent_spaces: usize) !void {
    for (values) |value| {
        try writeIndent(writer, indent_spaces);
        try writeTsString(writer, value);
        try writer.writeAll(",\n");
    }
}

fn writePythonStringTuple(writer: anytype, values: []const []const u8, indent_level: usize) !void {
    for (values) |value| {
        try writeIndent(writer, indent_level * 4);
        try writePythonString(writer, value);
        try writer.writeAll(",\n");
    }
}

fn writeGoStringArray(writer: anytype, values: []const []const u8, indent_tabs: usize) !void {
    for (values) |value| {
        var idx: usize = 0;
        while (idx < indent_tabs) : (idx += 1) try writer.writeByte('\t');
        try writeGoString(writer, value);
        try writer.writeAll(",\n");
    }
}

fn writeWorkspaceFile(allocator: std.mem.Allocator, rel_path: []const []const u8, contents: []const u8) !void {
    const full_path = try std.fs.path.join(allocator, rel_path);
    defer allocator.free(full_path);
    if (std.fs.path.dirname(full_path)) |dir_name| {
        try std.fs.cwd().makePath(dir_name);
    }

    const existing = std.fs.cwd().readFileAlloc(allocator, full_path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    defer if (existing) |value| allocator.free(value);

    if (existing) |value| {
        if (std.mem.eql(u8, value, contents)) return;
    }

    try std.fs.cwd().writeFile(.{
        .sub_path = full_path,
        .data = contents,
    });
}

fn controlCategory(name: []const u8) []const u8 {
    const bare = name["control.".len..];
    if (std.mem.eql(u8, bare, "version") or std.mem.eql(u8, bare, "version_ack") or std.mem.eql(u8, bare, "connect") or std.mem.eql(u8, bare, "connect_ack")) return "handshake";
    if (std.mem.startsWith(u8, bare, "session_")) return "session";
    if (std.mem.startsWith(u8, bare, "agent_")) return "agent";
    if (std.mem.startsWith(u8, bare, "node_")) return "node";
    if (std.mem.startsWith(u8, bare, "venom_")) return "venom";
    if (std.mem.startsWith(u8, bare, "workspace_") or std.mem.eql(u8, bare, "reconcile_status")) return "workspace";
    if (std.mem.startsWith(u8, bare, "project_")) return "project";
    if (std.mem.startsWith(u8, bare, "auth_")) return "auth";
    if (std.mem.eql(u8, bare, "audit_tail")) return "audit";
    if (std.mem.eql(u8, bare, "error")) return "error";
    return "operations";
}

fn controlDirection(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "control.error")) return "error";
    if (std.mem.eql(u8, name, "control.pong") or std.mem.endsWith(u8, name, "_ack")) return "response";
    return "request";
}

fn acheronCategory(name: []const u8) []const u8 {
    const bare = name["acheron.".len..];
    if (std.mem.eql(u8, bare, "error")) return "runtime";
    if (std.mem.eql(u8, bare, "err_fs") or std.mem.startsWith(u8, bare, "t_fs_") or std.mem.startsWith(u8, bare, "r_fs_") or std.mem.startsWith(u8, bare, "e_fs_")) return "node_fs";
    return "runtime";
}

fn acheronDirection(name: []const u8) []const u8 {
    const bare = name["acheron.".len..];
    if (std.mem.eql(u8, bare, "error") or std.mem.eql(u8, bare, "err_fs")) return "error";
    if (std.mem.startsWith(u8, bare, "e_")) return "event";
    if (std.mem.startsWith(u8, bare, "r_")) return "response";
    return "request";
}

fn writeJsonString(writer: anytype, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |char| {
        switch (char) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (char < 0x20) {
                    try writer.print("\\u00{x:0>2}", .{char});
                } else {
                    try writer.writeByte(char);
                }
            },
        }
    }
    try writer.writeByte('"');
}

fn writeTsString(writer: anytype, value: []const u8) !void {
    try writeJsonString(writer, value);
}

fn writePythonString(writer: anytype, value: []const u8) !void {
    try writeJsonString(writer, value);
}

fn writeGoString(writer: anytype, value: []const u8) !void {
    try writeJsonString(writer, value);
}

fn writeIndent(writer: anytype, count: usize) !void {
    var idx: usize = 0;
    while (idx < count) : (idx += 1) try writer.writeByte(' ');
}

fn readExpectedArtifact(allocator: std.mem.Allocator, rel_path: []const []const u8) ![]u8 {
    const full_path = try std.fs.path.join(allocator, rel_path);
    defer allocator.free(full_path);
    return std.fs.cwd().readFileAlloc(allocator, full_path, 16 * 1024 * 1024);
}

fn collectCanonicalDocContents(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    for (artifacts) |artifact| {
        switch (artifact.kind) {
            .doc_control_reference, .doc_acheron_reference, .doc_node_fs_reference, .doc_wasm_abi_reference => {
                const contents = try readExpectedArtifact(allocator, artifact.rel_path);
                defer allocator.free(contents);
                try out.appendSlice(allocator, contents);
                try out.append(allocator, '\n');
            },
            else => {},
        }
    }
    return out.toOwnedSlice(allocator);
}

fn scanProtocolNames(allocator: std.mem.Allocator, contents: []const u8) !std.StringHashMap(void) {
    var found = std.StringHashMap(void).init(allocator);
    errdefer {
        var it = found.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        found.deinit();
    }

    var index: usize = 0;
    while (index < contents.len) : (index += 1) {
        if (std.mem.startsWith(u8, contents[index..], "control.") or std.mem.startsWith(u8, contents[index..], "acheron.")) {
            var end = index;
            while (end < contents.len and isProtocolNameByte(contents[end])) : (end += 1) {}
            const name = contents[index..end];
            if (std.mem.endsWith(u8, name, ".") or std.mem.eql(u8, name, "control.*") or std.mem.eql(u8, name, "acheron.*")) {
                index = end;
                continue;
            }
            if (!found.contains(name)) {
                try found.put(try allocator.dupe(u8, name), {});
            }
            index = end;
        }
    }
    return found;
}

fn isProtocolNameByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or byte == '*';
}

test "sdk_artifacts: generated artifact files are current" {
    const allocator = std.testing.allocator;
    for (artifacts) |artifact| {
        const expected = try renderArtifact(allocator, artifact.kind);
        defer allocator.free(expected);
        const current = try readExpectedArtifact(allocator, artifact.rel_path);
        defer allocator.free(current);
        try std.testing.expectEqualStrings(expected, current);
    }
}

test "sdk_artifacts: canonical docs mention every public protocol name" {
    const allocator = std.testing.allocator;
    const docs = try collectCanonicalDocContents(allocator);
    defer allocator.free(docs);

    inline for (@typeInfo(unified.ControlType).@"enum".fields) |field| {
        const value: unified.ControlType = @enumFromInt(field.value);
        if (value == .unknown) continue;
        try std.testing.expect(std.mem.indexOf(u8, docs, unified.controlTypeName(value)) != null);
    }

    inline for (@typeInfo(unified.FsrpcType).@"enum".fields) |field| {
        const value: unified.FsrpcType = @enumFromInt(field.value);
        if (value == .unknown) continue;
        try std.testing.expect(std.mem.indexOf(u8, docs, unified.acheronTypeName(value)) != null);
    }
}

test "sdk_artifacts: generated fixtures parse with the canonical parser" {
    const allocator = std.testing.allocator;
    const cases = [_]struct {
        kind: ArtifactKind,
        channel: unified.Channel,
        control_type: ?unified.ControlType = null,
        acheron_type: ?unified.FsrpcType = null,
    }{
        .{ .kind = .fixture_control_version_request, .channel = .control, .control_type = .version },
        .{ .kind = .fixture_control_version_ack_response, .channel = .control, .control_type = .version_ack },
        .{ .kind = .fixture_control_connect_request, .channel = .control, .control_type = .connect },
        .{ .kind = .fixture_control_connect_ack_response, .channel = .control, .control_type = .connect_ack },
        .{ .kind = .fixture_control_error_response, .channel = .control, .control_type = .err },
        .{ .kind = .fixture_acheron_t_version_request, .channel = .acheron, .acheron_type = .t_version },
        .{ .kind = .fixture_acheron_r_version_response, .channel = .acheron, .acheron_type = .r_version },
        .{ .kind = .fixture_acheron_t_attach_request, .channel = .acheron, .acheron_type = .t_attach },
        .{ .kind = .fixture_acheron_r_attach_response, .channel = .acheron, .acheron_type = .r_attach },
        .{ .kind = .fixture_acheron_t_fs_hello_request, .channel = .acheron, .acheron_type = .fs_t_hello },
        .{ .kind = .fixture_acheron_r_fs_hello_response, .channel = .acheron, .acheron_type = .fs_r_hello },
        .{ .kind = .fixture_acheron_t_fs_lookup_request, .channel = .acheron, .acheron_type = .fs_t_lookup },
        .{ .kind = .fixture_acheron_r_fs_lookup_response, .channel = .acheron, .acheron_type = .fs_r_lookup },
        .{ .kind = .fixture_acheron_t_fs_getattr_request, .channel = .acheron, .acheron_type = .fs_t_getattr },
        .{ .kind = .fixture_acheron_r_fs_getattr_response, .channel = .acheron, .acheron_type = .fs_r_getattr },
        .{ .kind = .fixture_acheron_t_fs_readdirp_request, .channel = .acheron, .acheron_type = .fs_t_readdirp },
        .{ .kind = .fixture_acheron_r_fs_readdirp_response, .channel = .acheron, .acheron_type = .fs_r_readdirp },
        .{ .kind = .fixture_acheron_t_fs_open_request, .channel = .acheron, .acheron_type = .fs_t_open },
        .{ .kind = .fixture_acheron_r_fs_open_response, .channel = .acheron, .acheron_type = .fs_r_open },
        .{ .kind = .fixture_acheron_t_fs_read_request, .channel = .acheron, .acheron_type = .fs_t_read },
        .{ .kind = .fixture_acheron_r_fs_read_response, .channel = .acheron, .acheron_type = .fs_r_read },
        .{ .kind = .fixture_acheron_t_fs_write_request, .channel = .acheron, .acheron_type = .fs_t_write },
        .{ .kind = .fixture_acheron_r_fs_write_response, .channel = .acheron, .acheron_type = .fs_r_write },
        .{ .kind = .fixture_acheron_t_fs_close_request, .channel = .acheron, .acheron_type = .fs_t_close },
        .{ .kind = .fixture_acheron_r_fs_close_response, .channel = .acheron, .acheron_type = .fs_r_close },
        .{ .kind = .fixture_acheron_error_response, .channel = .acheron, .acheron_type = .err },
        .{ .kind = .fixture_acheron_err_fs_response, .channel = .acheron, .acheron_type = .fs_err },
        .{ .kind = .fixture_acheron_e_fs_inval_event, .channel = .acheron, .acheron_type = .fs_evt_inval },
    };

    for (cases) |case| {
        const rendered = try renderArtifact(allocator, case.kind);
        defer allocator.free(rendered);

        var parsed = try unified.parseMessage(allocator, rendered);
        defer parsed.deinit(allocator);

        try std.testing.expectEqual(case.channel, parsed.channel);
        if (case.control_type) |expected| {
            try std.testing.expectEqual(expected, parsed.control_type.?);
        }
        if (case.acheron_type) |expected| {
            try std.testing.expectEqual(expected, parsed.acheron_type.?);
        }
    }
}

test "sdk_artifacts: canonical docs do not introduce undocumented protocol names" {
    const allocator = std.testing.allocator;
    const docs = try collectCanonicalDocContents(allocator);
    defer allocator.free(docs);

    var found = try scanProtocolNames(allocator, docs);
    defer {
        var it = found.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        found.deinit();
    }

    var key_it = found.keyIterator();
    while (key_it.next()) |key| {
        const name = key.*;
        if (std.mem.startsWith(u8, name, "control.")) {
            try std.testing.expect(unified.controlTypeFromString(name) != .unknown or stringInSlice(name, &legacy_rejected_control_names));
        } else if (std.mem.startsWith(u8, name, "acheron.")) {
            try std.testing.expect(unified.acheronTypeFromString(name) != .unknown or stringInSlice(name, &legacy_rejected_acheron_names));
        }
    }
}

test "sdk_artifacts: SpiderDocs protocol pages point to canonical references without hand-maintained operation tables" {
    const allocator = std.testing.allocator;
    for (spiderdocs_protocol_overview_files) |rel_path| {
        const contents = readExpectedArtifact(allocator, rel_path) catch |err| switch (err) {
            error.FileNotFound => return error.SkipZigTest,
            else => return err,
        };
        defer allocator.free(contents);

        try std.testing.expect(std.mem.indexOf(u8, contents, "Canonical reference") != null);
        try std.testing.expect(std.mem.indexOf(u8, contents, "- `control.") == null);
        try std.testing.expect(std.mem.indexOf(u8, contents, "- `acheron.") == null);

        var has_reference_link = false;
        for (canonical_reference_links) |link| {
            if (std.mem.indexOf(u8, contents, link) != null) {
                has_reference_link = true;
                break;
            }
        }
        try std.testing.expect(has_reference_link);
    }
}

fn stringInSlice(needle: []const u8, haystack: []const []const u8) bool {
    for (haystack) |value| {
        if (std.mem.eql(u8, needle, value)) return true;
    }
    return false;
}
