const std = @import("std");
const unified = @import("unified.zig");

pub const SchemaKind = enum {
    object,
    string,
    boolean,
    u32,
    u64,
    i64,
    any,
};

pub const MessageDirection = enum {
    request,
    response,
    event,
    @"error",
};

pub const FieldSpec = struct {
    name: []const u8,
    type_name: []const u8,
    optional: bool = false,
    nullable: bool = false,
    is_array: bool = false,
    aliases: []const []const u8 = &.{},
};

pub const SchemaSpec = struct {
    name: []const u8,
    kind: SchemaKind,
    fields: []const FieldSpec = &.{},
};

pub const MessageSchemaSpec = struct {
    channel: unified.Channel,
    wire_name: []const u8,
    category: []const u8,
    direction: MessageDirection,
    correlation_field: ?[]const u8 = null,
    root_fields: []const FieldSpec = &.{},
    payload_schema: ?[]const u8 = null,
    result_schema: ?[]const u8 = null,
    error_schema: ?[]const u8 = null,
    alias_of: ?[]const u8 = null,
};

fn field(name: []const u8, type_name: []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name };
}

fn optionalField(name: []const u8, type_name: []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .optional = true };
}

fn nullableField(name: []const u8, type_name: []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .nullable = true };
}

fn optionalNullableField(name: []const u8, type_name: []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .optional = true, .nullable = true };
}

fn arrayField(name: []const u8, type_name: []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .is_array = true };
}

fn optionalArrayField(name: []const u8, type_name: []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .optional = true, .is_array = true };
}

fn aliasField(name: []const u8, type_name: []const u8, aliases: []const []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .aliases = aliases };
}

fn optionalAliasField(name: []const u8, type_name: []const u8, aliases: []const []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .optional = true, .aliases = aliases };
}

fn optionalNullableAliasField(name: []const u8, type_name: []const u8, aliases: []const []const u8) FieldSpec {
    return .{ .name = name, .type_name = type_name, .optional = true, .nullable = true, .aliases = aliases };
}

const id_aliases = [_][]const u8{"id"};
const workspace_id_aliases = [_][]const u8{ "id", "project_id" };
const project_id_aliases = [_][]const u8{ "id", "workspace_id" };
const workspace_token_aliases = [_][]const u8{"project_token"};
const project_token_aliases = [_][]const u8{"workspace_token"};

const control_error_fields = [_]FieldSpec{
    field("code", "string"),
    field("message", "string"),
};

const acheron_error_fields = [_]FieldSpec{
    optionalField("code", "string"),
    field("message", "string"),
};

const acheron_fs_error_fields = [_]FieldSpec{
    field("errno", "u32"),
    field("message", "string"),
};

const control_version_request_payload_fields = [_]FieldSpec{
    field("protocol", "string"),
};

const control_version_ack_payload_fields = [_]FieldSpec{
    field("protocol", "string"),
    field("acheron_runtime", "string"),
    field("acheron_node", "string"),
    field("acheron_node_proto", "u32"),
};

const connect_ack_mount_fields = [_]FieldSpec{
    field("mount_path", "string"),
    optionalNullableField("fs_url", "string"),
    optionalField("state", "string"),
    optionalField("online", "boolean"),
};

const connect_ack_workspace_fields = [_]FieldSpec{
    optionalArrayField("mounts", "ConnectAckWorkspaceMount"),
};

const connect_ack_payload_fields = [_]FieldSpec{
    field("agent_id", "string"),
    optionalNullableField("project_id", "string"),
    optionalNullableField("session", "string"),
    field("protocol", "string"),
    optionalField("role", "string"),
    optionalField("bootstrap_only", "boolean"),
    optionalNullableField("bootstrap_message", "string"),
    optionalField("requires_session_attach", "boolean"),
    optionalNullableField("workspace", "ConnectAckWorkspace"),
};

const node_ensure_request_fields = [_]FieldSpec{
    field("node_name", "string"),
    optionalField("fs_url", "string"),
    optionalField("lease_ttl_ms", "u64"),
};

const ensured_node_identity_fields = [_]FieldSpec{
    field("node_id", "string"),
    field("node_name", "string"),
    field("node_secret", "string"),
};

const mount_view_fields = [_]FieldSpec{
    field("mount_path", "string"),
    field("node_id", "string"),
    optionalNullableField("node_name", "string"),
    optionalNullableField("fs_url", "string"),
    field("export_name", "string"),
};

const bind_view_fields = [_]FieldSpec{
    field("bind_path", "string"),
    field("target_path", "string"),
};

const workspace_summary_fields = [_]FieldSpec{
    aliasField("workspace_id", "string", &workspace_id_aliases),
    field("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalNullableField("template_id", "string"),
    optionalNullableField("kind", "string"),
    optionalField("is_delete_protected", "boolean"),
    optionalField("token_locked", "boolean"),
    optionalField("mount_count", "u64"),
    optionalField("bind_count", "u64"),
    optionalField("created_at_ms", "i64"),
    optionalField("updated_at_ms", "i64"),
};

const project_summary_fields = [_]FieldSpec{
    aliasField("project_id", "string", &project_id_aliases),
    field("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalNullableField("template_id", "string"),
    optionalNullableField("kind", "string"),
    optionalField("is_delete_protected", "boolean"),
    optionalField("token_locked", "boolean"),
    optionalField("mount_count", "u64"),
    optionalField("bind_count", "u64"),
    optionalField("created_at_ms", "i64"),
    optionalField("updated_at_ms", "i64"),
};

const workspace_detail_fields = [_]FieldSpec{
    aliasField("workspace_id", "string", &workspace_id_aliases),
    field("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalNullableField("template_id", "string"),
    optionalNullableField("kind", "string"),
    optionalField("is_delete_protected", "boolean"),
    optionalField("token_locked", "boolean"),
    optionalField("created_at_ms", "i64"),
    optionalField("updated_at_ms", "i64"),
    optionalNullableAliasField("workspace_token", "string", &workspace_token_aliases),
    optionalArrayField("mounts", "MountView"),
    optionalArrayField("binds", "BindView"),
};

const project_detail_fields = [_]FieldSpec{
    aliasField("project_id", "string", &project_id_aliases),
    field("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalNullableField("template_id", "string"),
    optionalNullableField("kind", "string"),
    optionalField("is_delete_protected", "boolean"),
    optionalField("token_locked", "boolean"),
    optionalField("created_at_ms", "i64"),
    optionalField("updated_at_ms", "i64"),
    optionalNullableAliasField("project_token", "string", &project_token_aliases),
    optionalArrayField("mounts", "MountView"),
    optionalArrayField("binds", "BindView"),
};

const workspace_ref_request_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    optionalField("workspace_token", "string"),
};

const project_ref_request_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalField("project_token", "string"),
};

const node_id_request_fields = [_]FieldSpec{
    field("node_id", "string"),
};

const agent_id_request_fields = [_]FieldSpec{
    field("agent_id", "string"),
};

const template_get_request_fields = [_]FieldSpec{
    field("template_id", "string"),
};

const session_key_request_fields = [_]FieldSpec{
    field("session_key", "string"),
};

const session_attach_request_fields = [_]FieldSpec{
    field("session_key", "string"),
    field("agent_id", "string"),
    field("project_id", "string"),
    optionalField("project_token", "string"),
};

const session_status_request_fields = [_]FieldSpec{
    optionalField("session_key", "string"),
};

const session_history_request_fields = [_]FieldSpec{
    optionalField("agent_id", "string"),
    optionalField("limit", "u64"),
};

const workspace_create_request_fields = [_]FieldSpec{
    field("name", "string"),
    field("vision", "string"),
    optionalField("status", "string"),
    optionalField("template_id", "string"),
    optionalField("operator_token", "string"),
    optionalField("access_policy", "AnyJson"),
};

const project_create_request_fields = [_]FieldSpec{
    field("name", "string"),
    field("vision", "string"),
    optionalField("status", "string"),
    optionalField("template_id", "string"),
    optionalField("operator_token", "string"),
    optionalField("access_policy", "AnyJson"),
};

const workspace_update_request_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    optionalField("workspace_token", "string"),
    optionalField("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalField("template_id", "string"),
    optionalField("access_policy", "AnyJson"),
};

const project_update_request_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalField("project_token", "string"),
    optionalField("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalField("template_id", "string"),
    optionalField("access_policy", "AnyJson"),
};

const workspace_mount_set_request_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    optionalField("workspace_token", "string"),
    field("node_id", "string"),
    field("export_name", "string"),
    field("mount_path", "string"),
};

const project_mount_set_request_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalField("project_token", "string"),
    field("node_id", "string"),
    field("export_name", "string"),
    field("mount_path", "string"),
};

const workspace_mount_remove_request_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    optionalField("workspace_token", "string"),
    field("mount_path", "string"),
    optionalField("node_id", "string"),
    optionalField("export_name", "string"),
};

const project_mount_remove_request_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalField("project_token", "string"),
    field("mount_path", "string"),
    optionalField("node_id", "string"),
    optionalField("export_name", "string"),
};

const workspace_bind_set_request_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    optionalField("workspace_token", "string"),
    field("bind_path", "string"),
    field("target_path", "string"),
};

const project_bind_set_request_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalField("project_token", "string"),
    field("bind_path", "string"),
    field("target_path", "string"),
};

const workspace_bind_remove_request_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    optionalField("workspace_token", "string"),
    field("bind_path", "string"),
};

const project_bind_remove_request_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalField("project_token", "string"),
    field("bind_path", "string"),
};

const workspace_up_request_fields = [_]FieldSpec{
    optionalField("workspace_id", "string"),
    optionalField("workspace_name", "string"),
    optionalField("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalField("template_id", "string"),
    optionalField("workspace_token", "string"),
    optionalField("access_policy", "AnyJson"),
    optionalField("desired_mounts", "AnyJson"),
    optionalField("desired_binds", "AnyJson"),
    optionalField("activate", "boolean"),
};

const project_up_request_fields = [_]FieldSpec{
    optionalField("project_id", "string"),
    optionalField("project_name", "string"),
    optionalField("name", "string"),
    optionalField("vision", "string"),
    optionalField("status", "string"),
    optionalField("template_id", "string"),
    optionalField("project_token", "string"),
    optionalField("access_policy", "AnyJson"),
    optionalField("desired_mounts", "AnyJson"),
    optionalField("desired_binds", "AnyJson"),
    optionalField("activate", "boolean"),
};

const workspace_status_request_fields = [_]FieldSpec{
    optionalField("workspace_id", "string"),
    optionalField("workspace_token", "string"),
};

const reconcile_status_request_fields = [_]FieldSpec{
    optionalField("workspace_id", "string"),
};

const venom_bind_request_fields = [_]FieldSpec{
    field("venom_id", "string"),
    optionalField("node_id", "string"),
    optionalField("scope", "string"),
    optionalField("project_id", "string"),
    optionalField("agent_id", "string"),
};

const workspace_template_bind_fields = [_]FieldSpec{
    field("bind_path", "string"),
    field("venom_id", "string"),
    field("provider_scope", "string"),
};

const workspace_template_fields = [_]FieldSpec{
    field("id", "string"),
    field("description", "string"),
    optionalArrayField("binds", "WorkspaceTemplateBind"),
};

const workspace_template_list_response_fields = [_]FieldSpec{
    arrayField("templates", "WorkspaceTemplate"),
};

const workspace_template_get_response_fields = [_]FieldSpec{
    field("template", "WorkspaceTemplate"),
};

const workspace_list_response_fields = [_]FieldSpec{
    arrayField("workspaces", "WorkspaceSummary"),
};

const project_list_response_fields = [_]FieldSpec{
    arrayField("projects", "ProjectSummary"),
};

const workspace_mount_list_response_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    arrayField("mounts", "MountView"),
};

const project_mount_list_response_fields = [_]FieldSpec{
    field("project_id", "string"),
    arrayField("mounts", "MountView"),
};

const workspace_bind_list_response_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    arrayField("binds", "BindView"),
};

const project_bind_list_response_fields = [_]FieldSpec{
    field("project_id", "string"),
    arrayField("binds", "BindView"),
};

const delete_response_fields = [_]FieldSpec{
    field("deleted", "boolean"),
    optionalAliasField("workspace_id", "string", &workspace_id_aliases),
};

const delete_project_response_fields = [_]FieldSpec{
    field("deleted", "boolean"),
    optionalAliasField("project_id", "string", &project_id_aliases),
};

const token_mutation_workspace_fields = [_]FieldSpec{
    aliasField("workspace_id", "string", &workspace_id_aliases),
    optionalNullableAliasField("workspace_token", "string", &workspace_token_aliases),
    optionalField("updated_at_ms", "i64"),
    optionalField("rotated", "boolean"),
    optionalField("revoked", "boolean"),
};

const token_mutation_project_fields = [_]FieldSpec{
    aliasField("project_id", "string", &project_id_aliases),
    optionalNullableAliasField("project_token", "string", &project_token_aliases),
    optionalField("updated_at_ms", "i64"),
    optionalField("rotated", "boolean"),
    optionalField("revoked", "boolean"),
};

const drift_item_fields = [_]FieldSpec{
    optionalNullableField("mount_path", "string"),
    optionalNullableField("kind", "string"),
    optionalNullableField("severity", "string"),
    optionalNullableField("selected_node_id", "string"),
    optionalNullableField("desired_node_id", "string"),
    optionalNullableField("message", "string"),
};

const drift_summary_fields = [_]FieldSpec{
    optionalField("count", "u64"),
    optionalArrayField("items", "DriftItem"),
};

const availability_fields = [_]FieldSpec{
    optionalField("mounts_total", "u64"),
    optionalField("online", "u64"),
    optionalField("degraded", "u64"),
    optionalField("missing", "u64"),
};

const workspace_status_fields = [_]FieldSpec{
    field("agent_id", "string"),
    optionalNullableAliasField("workspace_id", "string", &workspace_id_aliases),
    optionalNullableField("workspace_root", "string"),
    optionalArrayField("mounts", "MountView"),
    optionalArrayField("desired_mounts", "MountView"),
    optionalArrayField("actual_mounts", "MountView"),
    optionalNullableField("drift", "DriftSummary"),
    optionalNullableField("availability", "AvailabilitySummary"),
    optionalNullableField("reconcile_state", "string"),
    optionalField("last_reconcile_ms", "i64"),
    optionalField("last_success_ms", "i64"),
    optionalNullableField("last_error", "string"),
    optionalField("queue_depth", "u64"),
};

const project_activation_fields = [_]FieldSpec{
    field("agent_id", "string"),
    aliasField("project_id", "string", &project_id_aliases),
    optionalNullableField("workspace_root", "string"),
};

const session_attach_state_fields = [_]FieldSpec{
    field("state", "string"),
    optionalField("runtime_ready", "boolean"),
    optionalField("mount_ready", "boolean"),
    optionalNullableField("error_code", "string"),
    optionalNullableField("error_message", "string"),
    optionalField("updated_at_ms", "i64"),
};

const session_status_response_fields = [_]FieldSpec{
    field("session_key", "string"),
    field("agent_id", "string"),
    optionalNullableField("project_id", "string"),
    field("attach", "SessionAttachState"),
};

const session_summary_fields = [_]FieldSpec{
    field("session_key", "string"),
    field("agent_id", "string"),
    optionalNullableField("project_id", "string"),
    optionalField("last_active_ms", "i64"),
    optionalField("message_count", "u64"),
    optionalNullableField("summary", "string"),
};

const session_list_response_fields = [_]FieldSpec{
    field("active_session", "string"),
    arrayField("sessions", "SessionSummary"),
};

const session_close_response_fields = [_]FieldSpec{
    field("session_key", "string"),
    field("closed", "boolean"),
    field("active_session", "string"),
};

const session_restore_response_fields = [_]FieldSpec{
    field("found", "boolean"),
    optionalNullableField("session", "SessionSummary"),
};

const session_history_response_fields = [_]FieldSpec{
    arrayField("sessions", "SessionSummary"),
};

const reconcile_project_status_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalField("mounts", "u64"),
    optionalField("selected_mounts", "u64"),
    optionalField("online_mounts", "u64"),
    optionalField("degraded_mounts", "u64"),
    optionalField("missing_mounts", "u64"),
    optionalField("drift_count", "u64"),
    optionalField("queue_depth", "u64"),
};

const reconcile_status_response_fields = [_]FieldSpec{
    optionalNullableField("reconcile_state", "string"),
    optionalField("last_reconcile_ms", "i64"),
    optionalField("last_success_ms", "i64"),
    optionalNullableField("last_error", "string"),
    optionalField("queue_depth", "u64"),
    optionalField("failed_ops_total", "u64"),
    optionalField("cycles_total", "u64"),
    optionalArrayField("failed_ops", "string"),
    optionalArrayField("projects", "ReconcileProjectStatus"),
};

const node_info_fields = [_]FieldSpec{
    field("node_id", "string"),
    field("node_name", "string"),
    optionalField("fs_url", "string"),
    optionalField("joined_at_ms", "i64"),
    optionalField("last_seen_ms", "i64"),
    optionalField("lease_expires_at_ms", "i64"),
};

const node_list_response_fields = [_]FieldSpec{
    arrayField("nodes", "NodeInfo"),
};

const node_get_response_fields = [_]FieldSpec{
    field("node", "NodeInfo"),
};

const agent_info_fields = [_]FieldSpec{
    aliasField("agent_id", "string", &id_aliases),
    field("name", "string"),
    optionalField("description", "string"),
    optionalField("is_default", "boolean"),
    optionalField("identity_loaded", "boolean"),
    optionalField("needs_hatching", "boolean"),
    optionalArrayField("capabilities", "string"),
};

const agent_list_response_fields = [_]FieldSpec{
    arrayField("agents", "AgentInfo"),
};

const agent_get_response_fields = [_]FieldSpec{
    field("agent", "AgentInfo"),
};

const workspace_up_response_fields = [_]FieldSpec{
    field("workspace_id", "string"),
    optionalNullableField("workspace_token", "string"),
    field("created", "boolean"),
    field("activated", "boolean"),
    field("workspace", "AnyJson"),
};

const project_up_response_fields = [_]FieldSpec{
    field("project_id", "string"),
    optionalNullableField("project_token", "string"),
    field("created", "boolean"),
    field("activated", "boolean"),
    field("workspace", "AnyJson"),
};

const acheron_attach_response_fields = [_]FieldSpec{
    field("layout", "string"),
    optionalArrayField("roots", "string"),
};

const fs_hello_request_fields = [_]FieldSpec{
    field("protocol", "string"),
    field("proto", "u32"),
    optionalField("auth_token", "string"),
    optionalField("node_id", "string"),
    optionalField("node_secret", "string"),
};

const fs_hello_capabilities_fields = [_]FieldSpec{
    optionalField("exports", "boolean"),
    optionalField("read", "boolean"),
    optionalField("write", "boolean"),
};

const fs_hello_response_fields = [_]FieldSpec{
    field("protocol", "string"),
    field("proto", "u32"),
    optionalNullableField("capabilities", "FsHelloCapabilities"),
    optionalNullableField("caps", "AnyJson"),
    optionalNullableField("node", "AnyJson"),
};

const fs_lookup_request_fields = [_]FieldSpec{
    field("name", "string"),
};

const fs_lookup_response_fields = [_]FieldSpec{
    field("node", "u64"),
    optionalField("name", "string"),
    optionalField("kind", "string"),
    optionalField("attr", "AnyJson"),
};

const fs_getattr_response_fields = [_]FieldSpec{
    optionalField("node", "u64"),
    optionalField("kind", "string"),
    optionalField("size", "u64"),
    optionalField("mode", "string"),
    optionalField("attr", "AnyJson"),
};

const fs_readdirp_request_fields = [_]FieldSpec{
    optionalField("cookie", "u64"),
    optionalField("count", "u32"),
    optionalField("max", "u32"),
};

const fs_dir_entry_fields = [_]FieldSpec{
    optionalField("node", "u64"),
    optionalField("name", "string"),
    optionalField("kind", "string"),
    optionalField("size", "u64"),
};

const fs_readdirp_response_fields = [_]FieldSpec{
    optionalArrayField("entries", "FsDirEntry"),
    optionalArrayField("ents", "FsDirEntry"),
    optionalField("next", "u64"),
    optionalField("eof", "boolean"),
};

const fs_open_request_fields = [_]FieldSpec{
    optionalField("mode", "string"),
    optionalField("flags", "u32"),
};

const fs_open_response_fields = [_]FieldSpec{
    field("handle", "u64"),
    optionalField("mode", "string"),
    optionalField("generation", "u64"),
};

const fs_read_request_fields = [_]FieldSpec{
    field("offset", "u64"),
    field("count", "u32"),
};

const fs_read_response_fields = [_]FieldSpec{
    field("data_b64", "string"),
    optionalField("eof", "boolean"),
};

const fs_write_request_fields = [_]FieldSpec{
    field("offset", "u64"),
    field("data_b64", "string"),
};

const fs_write_response_fields = [_]FieldSpec{
    optionalField("count", "u32"),
    optionalField("n", "u32"),
};

const fs_inval_event_fields = [_]FieldSpec{
    field("node", "u64"),
    optionalField("what", "string"),
    optionalField("gen", "u64"),
};

const fs_inval_dir_event_fields = [_]FieldSpec{
    field("dir", "u64"),
    optionalField("dir_gen", "u64"),
};

pub const all_schemas = [_]SchemaSpec{
    .{ .name = "AnyJson", .kind = .any },
    .{ .name = "EmptyObject", .kind = .object },
    .{ .name = "ControlError", .kind = .object, .fields = &control_error_fields },
    .{ .name = "AcheronError", .kind = .object, .fields = &acheron_error_fields },
    .{ .name = "AcheronFsError", .kind = .object, .fields = &acheron_fs_error_fields },
    .{ .name = "ControlVersionRequestPayload", .kind = .object, .fields = &control_version_request_payload_fields },
    .{ .name = "ControlVersionAckPayload", .kind = .object, .fields = &control_version_ack_payload_fields },
    .{ .name = "ConnectAckWorkspaceMount", .kind = .object, .fields = &connect_ack_mount_fields },
    .{ .name = "ConnectAckWorkspace", .kind = .object, .fields = &connect_ack_workspace_fields },
    .{ .name = "ControlConnectAckPayload", .kind = .object, .fields = &connect_ack_payload_fields },
    .{ .name = "NodeEnsureRequest", .kind = .object, .fields = &node_ensure_request_fields },
    .{ .name = "EnsuredNodeIdentity", .kind = .object, .fields = &ensured_node_identity_fields },
    .{ .name = "MountView", .kind = .object, .fields = &mount_view_fields },
    .{ .name = "BindView", .kind = .object, .fields = &bind_view_fields },
    .{ .name = "WorkspaceSummary", .kind = .object, .fields = &workspace_summary_fields },
    .{ .name = "ProjectSummary", .kind = .object, .fields = &project_summary_fields },
    .{ .name = "WorkspaceDetail", .kind = .object, .fields = &workspace_detail_fields },
    .{ .name = "ProjectDetail", .kind = .object, .fields = &project_detail_fields },
    .{ .name = "WorkspaceRefRequest", .kind = .object, .fields = &workspace_ref_request_fields },
    .{ .name = "ProjectRefRequest", .kind = .object, .fields = &project_ref_request_fields },
    .{ .name = "NodeIdRequest", .kind = .object, .fields = &node_id_request_fields },
    .{ .name = "AgentIdRequest", .kind = .object, .fields = &agent_id_request_fields },
    .{ .name = "WorkspaceTemplateGetRequest", .kind = .object, .fields = &template_get_request_fields },
    .{ .name = "SessionKeyRequest", .kind = .object, .fields = &session_key_request_fields },
    .{ .name = "SessionAttachRequest", .kind = .object, .fields = &session_attach_request_fields },
    .{ .name = "SessionStatusRequest", .kind = .object, .fields = &session_status_request_fields },
    .{ .name = "SessionHistoryRequest", .kind = .object, .fields = &session_history_request_fields },
    .{ .name = "WorkspaceCreateRequest", .kind = .object, .fields = &workspace_create_request_fields },
    .{ .name = "ProjectCreateRequest", .kind = .object, .fields = &project_create_request_fields },
    .{ .name = "WorkspaceUpdateRequest", .kind = .object, .fields = &workspace_update_request_fields },
    .{ .name = "ProjectUpdateRequest", .kind = .object, .fields = &project_update_request_fields },
    .{ .name = "WorkspaceMountSetRequest", .kind = .object, .fields = &workspace_mount_set_request_fields },
    .{ .name = "ProjectMountSetRequest", .kind = .object, .fields = &project_mount_set_request_fields },
    .{ .name = "WorkspaceMountRemoveRequest", .kind = .object, .fields = &workspace_mount_remove_request_fields },
    .{ .name = "ProjectMountRemoveRequest", .kind = .object, .fields = &project_mount_remove_request_fields },
    .{ .name = "WorkspaceBindSetRequest", .kind = .object, .fields = &workspace_bind_set_request_fields },
    .{ .name = "ProjectBindSetRequest", .kind = .object, .fields = &project_bind_set_request_fields },
    .{ .name = "WorkspaceBindRemoveRequest", .kind = .object, .fields = &workspace_bind_remove_request_fields },
    .{ .name = "ProjectBindRemoveRequest", .kind = .object, .fields = &project_bind_remove_request_fields },
    .{ .name = "WorkspaceUpRequest", .kind = .object, .fields = &workspace_up_request_fields },
    .{ .name = "ProjectUpRequest", .kind = .object, .fields = &project_up_request_fields },
    .{ .name = "WorkspaceStatusRequest", .kind = .object, .fields = &workspace_status_request_fields },
    .{ .name = "ReconcileStatusRequest", .kind = .object, .fields = &reconcile_status_request_fields },
    .{ .name = "VenomBindRequest", .kind = .object, .fields = &venom_bind_request_fields },
    .{ .name = "WorkspaceTemplateBind", .kind = .object, .fields = &workspace_template_bind_fields },
    .{ .name = "WorkspaceTemplate", .kind = .object, .fields = &workspace_template_fields },
    .{ .name = "WorkspaceTemplateListResponse", .kind = .object, .fields = &workspace_template_list_response_fields },
    .{ .name = "WorkspaceTemplateGetResponse", .kind = .object, .fields = &workspace_template_get_response_fields },
    .{ .name = "WorkspaceListResponse", .kind = .object, .fields = &workspace_list_response_fields },
    .{ .name = "ProjectListResponse", .kind = .object, .fields = &project_list_response_fields },
    .{ .name = "WorkspaceMountListResponse", .kind = .object, .fields = &workspace_mount_list_response_fields },
    .{ .name = "ProjectMountListResponse", .kind = .object, .fields = &project_mount_list_response_fields },
    .{ .name = "WorkspaceBindListResponse", .kind = .object, .fields = &workspace_bind_list_response_fields },
    .{ .name = "ProjectBindListResponse", .kind = .object, .fields = &project_bind_list_response_fields },
    .{ .name = "WorkspaceDeleteResponse", .kind = .object, .fields = &delete_response_fields },
    .{ .name = "ProjectDeleteResponse", .kind = .object, .fields = &delete_project_response_fields },
    .{ .name = "WorkspaceTokenMutation", .kind = .object, .fields = &token_mutation_workspace_fields },
    .{ .name = "ProjectTokenMutation", .kind = .object, .fields = &token_mutation_project_fields },
    .{ .name = "DriftItem", .kind = .object, .fields = &drift_item_fields },
    .{ .name = "DriftSummary", .kind = .object, .fields = &drift_summary_fields },
    .{ .name = "AvailabilitySummary", .kind = .object, .fields = &availability_fields },
    .{ .name = "WorkspaceStatus", .kind = .object, .fields = &workspace_status_fields },
    .{ .name = "ProjectActivation", .kind = .object, .fields = &project_activation_fields },
    .{ .name = "SessionAttachState", .kind = .object, .fields = &session_attach_state_fields },
    .{ .name = "SessionStatusResponse", .kind = .object, .fields = &session_status_response_fields },
    .{ .name = "SessionSummary", .kind = .object, .fields = &session_summary_fields },
    .{ .name = "SessionListResponse", .kind = .object, .fields = &session_list_response_fields },
    .{ .name = "SessionCloseResponse", .kind = .object, .fields = &session_close_response_fields },
    .{ .name = "SessionRestoreResponse", .kind = .object, .fields = &session_restore_response_fields },
    .{ .name = "SessionHistoryResponse", .kind = .object, .fields = &session_history_response_fields },
    .{ .name = "ReconcileProjectStatus", .kind = .object, .fields = &reconcile_project_status_fields },
    .{ .name = "ReconcileStatusResponse", .kind = .object, .fields = &reconcile_status_response_fields },
    .{ .name = "NodeInfo", .kind = .object, .fields = &node_info_fields },
    .{ .name = "NodeListResponse", .kind = .object, .fields = &node_list_response_fields },
    .{ .name = "NodeGetResponse", .kind = .object, .fields = &node_get_response_fields },
    .{ .name = "AgentInfo", .kind = .object, .fields = &agent_info_fields },
    .{ .name = "AgentListResponse", .kind = .object, .fields = &agent_list_response_fields },
    .{ .name = "AgentGetResponse", .kind = .object, .fields = &agent_get_response_fields },
    .{ .name = "WorkspaceUpResponse", .kind = .object, .fields = &workspace_up_response_fields },
    .{ .name = "ProjectUpResponse", .kind = .object, .fields = &project_up_response_fields },
    .{ .name = "AcheronAttachResponse", .kind = .object, .fields = &acheron_attach_response_fields },
    .{ .name = "FsHelloRequest", .kind = .object, .fields = &fs_hello_request_fields },
    .{ .name = "FsHelloCapabilities", .kind = .object, .fields = &fs_hello_capabilities_fields },
    .{ .name = "FsHelloResponse", .kind = .object, .fields = &fs_hello_response_fields },
    .{ .name = "FsLookupRequest", .kind = .object, .fields = &fs_lookup_request_fields },
    .{ .name = "FsLookupResponse", .kind = .object, .fields = &fs_lookup_response_fields },
    .{ .name = "FsGetattrResponse", .kind = .object, .fields = &fs_getattr_response_fields },
    .{ .name = "FsReaddirpRequest", .kind = .object, .fields = &fs_readdirp_request_fields },
    .{ .name = "FsDirEntry", .kind = .object, .fields = &fs_dir_entry_fields },
    .{ .name = "FsReaddirpResponse", .kind = .object, .fields = &fs_readdirp_response_fields },
    .{ .name = "FsOpenRequest", .kind = .object, .fields = &fs_open_request_fields },
    .{ .name = "FsOpenResponse", .kind = .object, .fields = &fs_open_response_fields },
    .{ .name = "FsReadRequest", .kind = .object, .fields = &fs_read_request_fields },
    .{ .name = "FsReadResponse", .kind = .object, .fields = &fs_read_response_fields },
    .{ .name = "FsWriteRequest", .kind = .object, .fields = &fs_write_request_fields },
    .{ .name = "FsWriteResponse", .kind = .object, .fields = &fs_write_response_fields },
    .{ .name = "FsInvalidateEvent", .kind = .object, .fields = &fs_inval_event_fields },
    .{ .name = "FsInvalidateDirEvent", .kind = .object, .fields = &fs_inval_dir_event_fields },
};

pub fn findSchema(name: []const u8) ?SchemaSpec {
    for (all_schemas) |schema| {
        if (std.mem.eql(u8, schema.name, name)) return schema;
    }
    return null;
}

fn controlSchema(
    control_type: unified.ControlType,
    category: []const u8,
    direction: MessageDirection,
    payload_schema: ?[]const u8,
    result_schema: ?[]const u8,
    alias_of: ?[]const u8,
) MessageSchemaSpec {
    return .{
        .channel = .control,
        .wire_name = unified.controlTypeName(control_type),
        .category = category,
        .direction = direction,
        .correlation_field = "id",
        .payload_schema = payload_schema,
        .result_schema = result_schema,
        .error_schema = if (direction == .@"error") "ControlError" else null,
        .alias_of = alias_of,
    };
}

pub fn controlMessageSchema(control_type: unified.ControlType) MessageSchemaSpec {
    return switch (control_type) {
        .version => controlSchema(.version, "handshake", .request, "ControlVersionRequestPayload", null, null),
        .version_ack => controlSchema(.version_ack, "handshake", .response, "ControlVersionAckPayload", null, null),
        .connect => controlSchema(.connect, "handshake", .request, "EmptyObject", null, null),
        .connect_ack => controlSchema(.connect_ack, "handshake", .response, "ControlConnectAckPayload", null, null),
        .session_attach => controlSchema(.session_attach, "session", .request, "SessionAttachRequest", "SessionStatusResponse", null),
        .session_status => controlSchema(.session_status, "session", .request, "SessionStatusRequest", "SessionStatusResponse", null),
        .session_resume => controlSchema(.session_resume, "session", .request, "SessionKeyRequest", "SessionStatusResponse", null),
        .session_list => controlSchema(.session_list, "session", .request, null, "SessionListResponse", null),
        .session_close => controlSchema(.session_close, "session", .request, "SessionKeyRequest", "SessionCloseResponse", null),
        .session_restore => controlSchema(.session_restore, "session", .request, "AgentIdRequest", "SessionRestoreResponse", null),
        .session_history => controlSchema(.session_history, "session", .request, "SessionHistoryRequest", "SessionHistoryResponse", null),
        .ping => controlSchema(.ping, "operations", .request, "AnyJson", "AnyJson", null),
        .pong => controlSchema(.pong, "operations", .response, "AnyJson", null, null),
        .metrics => controlSchema(.metrics, "operations", .request, null, "AnyJson", null),
        .auth_status => controlSchema(.auth_status, "auth", .request, null, "AnyJson", null),
        .auth_rotate => controlSchema(.auth_rotate, "auth", .request, null, "AnyJson", null),
        .node_invite_create => controlSchema(.node_invite_create, "node", .request, "AnyJson", "AnyJson", null),
        .node_join_request => controlSchema(.node_join_request, "node", .request, "AnyJson", "AnyJson", null),
        .node_join_pending_list => controlSchema(.node_join_pending_list, "node", .request, null, "AnyJson", null),
        .node_join_approve => controlSchema(.node_join_approve, "node", .request, "AnyJson", "AnyJson", null),
        .node_join_deny => controlSchema(.node_join_deny, "node", .request, "AnyJson", "AnyJson", null),
        .node_join => controlSchema(.node_join, "node", .request, "AnyJson", "AnyJson", null),
        .node_ensure => controlSchema(.node_ensure, "node", .request, "NodeEnsureRequest", "EnsuredNodeIdentity", null),
        .node_lease_refresh => controlSchema(.node_lease_refresh, "node", .request, "AnyJson", "AnyJson", null),
        .venom_bind => controlSchema(.venom_bind, "venom", .request, "VenomBindRequest", "AnyJson", null),
        .venom_upsert => controlSchema(.venom_upsert, "venom", .request, "AnyJson", "AnyJson", null),
        .venom_get => controlSchema(.venom_get, "venom", .request, "AnyJson", "AnyJson", null),
        .agent_ensure => controlSchema(.agent_ensure, "agent", .request, "AnyJson", "AnyJson", null),
        .agent_list => controlSchema(.agent_list, "agent", .request, null, "AgentListResponse", null),
        .agent_get => controlSchema(.agent_get, "agent", .request, "AgentIdRequest", "AgentGetResponse", null),
        .node_list => controlSchema(.node_list, "node", .request, null, "NodeListResponse", null),
        .node_get => controlSchema(.node_get, "node", .request, "NodeIdRequest", "NodeGetResponse", null),
        .node_delete => controlSchema(.node_delete, "node", .request, "NodeIdRequest", "AnyJson", null),
        .workspace_create => controlSchema(.workspace_create, "workspace", .request, "WorkspaceCreateRequest", "WorkspaceDetail", null),
        .workspace_update => controlSchema(.workspace_update, "workspace", .request, "WorkspaceUpdateRequest", "WorkspaceDetail", null),
        .workspace_delete => controlSchema(.workspace_delete, "workspace", .request, "WorkspaceRefRequest", "WorkspaceDeleteResponse", null),
        .workspace_list => controlSchema(.workspace_list, "workspace", .request, null, "WorkspaceListResponse", null),
        .workspace_get => controlSchema(.workspace_get, "workspace", .request, "WorkspaceRefRequest", "WorkspaceDetail", null),
        .workspace_template_list => controlSchema(.workspace_template_list, "workspace", .request, null, "WorkspaceTemplateListResponse", null),
        .workspace_template_get => controlSchema(.workspace_template_get, "workspace", .request, "WorkspaceTemplateGetRequest", "WorkspaceTemplateGetResponse", null),
        .workspace_mount_set => controlSchema(.workspace_mount_set, "workspace", .request, "WorkspaceMountSetRequest", "WorkspaceDetail", null),
        .workspace_mount_remove => controlSchema(.workspace_mount_remove, "workspace", .request, "WorkspaceMountRemoveRequest", "WorkspaceDetail", null),
        .workspace_mount_list => controlSchema(.workspace_mount_list, "workspace", .request, "WorkspaceRefRequest", "WorkspaceMountListResponse", null),
        .workspace_bind_set => controlSchema(.workspace_bind_set, "workspace", .request, "WorkspaceBindSetRequest", "WorkspaceDetail", null),
        .workspace_bind_remove => controlSchema(.workspace_bind_remove, "workspace", .request, "WorkspaceBindRemoveRequest", "WorkspaceDetail", null),
        .workspace_bind_list => controlSchema(.workspace_bind_list, "workspace", .request, "WorkspaceRefRequest", "WorkspaceBindListResponse", null),
        .workspace_token_rotate => controlSchema(.workspace_token_rotate, "workspace", .request, "WorkspaceRefRequest", "WorkspaceTokenMutation", null),
        .workspace_token_revoke => controlSchema(.workspace_token_revoke, "workspace", .request, "WorkspaceRefRequest", "WorkspaceTokenMutation", null),
        .workspace_activate => controlSchema(.workspace_activate, "workspace", .request, "WorkspaceRefRequest", "WorkspaceStatus", null),
        .workspace_up => controlSchema(.workspace_up, "workspace", .request, "WorkspaceUpRequest", "WorkspaceUpResponse", null),
        .project_create => controlSchema(.project_create, "project", .request, "ProjectCreateRequest", "ProjectDetail", "control.workspace_create"),
        .project_update => controlSchema(.project_update, "project", .request, "ProjectUpdateRequest", "ProjectDetail", "control.workspace_update"),
        .project_delete => controlSchema(.project_delete, "project", .request, "ProjectRefRequest", "ProjectDeleteResponse", "control.workspace_delete"),
        .project_list => controlSchema(.project_list, "project", .request, null, "ProjectListResponse", "control.workspace_list"),
        .project_get => controlSchema(.project_get, "project", .request, "ProjectRefRequest", "ProjectDetail", "control.workspace_get"),
        .project_mount_set => controlSchema(.project_mount_set, "project", .request, "ProjectMountSetRequest", "ProjectDetail", "control.workspace_mount_set"),
        .project_mount_remove => controlSchema(.project_mount_remove, "project", .request, "ProjectMountRemoveRequest", "ProjectDetail", "control.workspace_mount_remove"),
        .project_mount_list => controlSchema(.project_mount_list, "project", .request, "ProjectRefRequest", "ProjectMountListResponse", "control.workspace_mount_list"),
        .project_token_rotate => controlSchema(.project_token_rotate, "project", .request, "ProjectRefRequest", "ProjectTokenMutation", "control.workspace_token_rotate"),
        .project_token_revoke => controlSchema(.project_token_revoke, "project", .request, "ProjectRefRequest", "ProjectTokenMutation", "control.workspace_token_revoke"),
        .project_activate => controlSchema(.project_activate, "project", .request, "ProjectRefRequest", "ProjectActivation", "control.workspace_activate"),
        .workspace_status => controlSchema(.workspace_status, "workspace", .request, "WorkspaceStatusRequest", "WorkspaceStatus", null),
        .reconcile_status => controlSchema(.reconcile_status, "workspace", .request, "ReconcileStatusRequest", "ReconcileStatusResponse", null),
        .project_up => controlSchema(.project_up, "project", .request, "ProjectUpRequest", "ProjectUpResponse", "control.workspace_up"),
        .audit_tail => controlSchema(.audit_tail, "audit", .request, "AnyJson", "AnyJson", null),
        .err => .{
            .channel = .control,
            .wire_name = unified.controlTypeName(.err),
            .category = "error",
            .direction = .@"error",
            .correlation_field = "id",
            .error_schema = "ControlError",
        },
        .unknown => unreachable,
    };
}

fn acheronSchema(
    fsrpc_type: unified.FsrpcType,
    category: []const u8,
    direction: MessageDirection,
    payload_schema: ?[]const u8,
    root_fields: []const FieldSpec,
) MessageSchemaSpec {
    return .{
        .channel = .acheron,
        .wire_name = unified.acheronTypeName(fsrpc_type),
        .category = category,
        .direction = direction,
        .correlation_field = if (direction == .event) null else "tag",
        .root_fields = root_fields,
        .payload_schema = payload_schema,
        .error_schema = switch (direction) {
            .@"error" => if (fsrpc_type == .fs_err) "AcheronFsError" else "AcheronError",
            else => null,
        },
    };
}

const acheron_tag_root = [_]FieldSpec{};
const version_request_root = [_]FieldSpec{
    field("msize", "u32"),
    field("version", "string"),
};
const attach_request_root = [_]FieldSpec{
    field("fid", "u32"),
};
const fs_node_root = [_]FieldSpec{
    field("node", "u64"),
};
const fs_handle_root = [_]FieldSpec{
    field("h", "u64"),
};

pub fn acheronMessageSchema(fsrpc_type: unified.FsrpcType) MessageSchemaSpec {
    return switch (fsrpc_type) {
        .t_version => acheronSchema(.t_version, "runtime", .request, null, &version_request_root),
        .r_version => acheronSchema(.r_version, "runtime", .response, null, &version_request_root),
        .t_attach => acheronSchema(.t_attach, "runtime", .request, null, &attach_request_root),
        .r_attach => acheronSchema(.r_attach, "runtime", .response, "AcheronAttachResponse", &acheron_tag_root),
        .t_walk, .r_walk, .t_open, .r_open, .t_read, .r_read, .t_write, .r_write, .t_stat, .r_stat, .t_clunk, .r_clunk, .t_flush, .r_flush => acheronSchema(fsrpc_type, "runtime", if (std.mem.startsWith(u8, unified.acheronTypeName(fsrpc_type), "acheron.t_")) .request else .response, "AnyJson", &acheron_tag_root),
        .fs_t_hello => acheronSchema(.fs_t_hello, "node_fs", .request, "FsHelloRequest", &acheron_tag_root),
        .fs_r_hello => acheronSchema(.fs_r_hello, "node_fs", .response, "FsHelloResponse", &acheron_tag_root),
        .fs_t_exports, .fs_r_exports => acheronSchema(fsrpc_type, "node_fs", if (std.mem.startsWith(u8, unified.acheronTypeName(fsrpc_type), "acheron.t_")) .request else .response, "AnyJson", &acheron_tag_root),
        .fs_t_lookup => acheronSchema(.fs_t_lookup, "node_fs", .request, "FsLookupRequest", &fs_node_root),
        .fs_r_lookup => acheronSchema(.fs_r_lookup, "node_fs", .response, "FsLookupResponse", &acheron_tag_root),
        .fs_t_getattr => acheronSchema(.fs_t_getattr, "node_fs", .request, "EmptyObject", &fs_node_root),
        .fs_r_getattr => acheronSchema(.fs_r_getattr, "node_fs", .response, "FsGetattrResponse", &acheron_tag_root),
        .fs_t_readdirp => acheronSchema(.fs_t_readdirp, "node_fs", .request, "FsReaddirpRequest", &fs_node_root),
        .fs_r_readdirp => acheronSchema(.fs_r_readdirp, "node_fs", .response, "FsReaddirpResponse", &acheron_tag_root),
        .fs_t_symlink, .fs_r_symlink, .fs_t_setxattr, .fs_r_setxattr, .fs_t_getxattr, .fs_r_getxattr, .fs_t_listxattr, .fs_r_listxattr, .fs_t_removexattr, .fs_r_removexattr, .fs_t_lock, .fs_r_lock, .fs_t_create, .fs_r_create, .fs_t_truncate, .fs_r_truncate, .fs_t_unlink, .fs_r_unlink, .fs_t_mkdir, .fs_r_mkdir, .fs_t_rmdir, .fs_r_rmdir, .fs_t_rename, .fs_r_rename, .fs_t_statfs, .fs_r_statfs => acheronSchema(fsrpc_type, "node_fs", if (std.mem.startsWith(u8, unified.acheronTypeName(fsrpc_type), "acheron.t_")) .request else .response, "AnyJson", &acheron_tag_root),
        .fs_t_open => acheronSchema(.fs_t_open, "node_fs", .request, "FsOpenRequest", &fs_node_root),
        .fs_r_open => acheronSchema(.fs_r_open, "node_fs", .response, "FsOpenResponse", &acheron_tag_root),
        .fs_t_read => acheronSchema(.fs_t_read, "node_fs", .request, "FsReadRequest", &fs_handle_root),
        .fs_r_read => acheronSchema(.fs_r_read, "node_fs", .response, "FsReadResponse", &acheron_tag_root),
        .fs_t_close => acheronSchema(.fs_t_close, "node_fs", .request, "EmptyObject", &fs_handle_root),
        .fs_r_close => acheronSchema(.fs_r_close, "node_fs", .response, "EmptyObject", &acheron_tag_root),
        .fs_t_write => acheronSchema(.fs_t_write, "node_fs", .request, "FsWriteRequest", &fs_handle_root),
        .fs_r_write => acheronSchema(.fs_r_write, "node_fs", .response, "FsWriteResponse", &acheron_tag_root),
        .fs_evt_inval => acheronSchema(.fs_evt_inval, "node_fs", .event, "FsInvalidateEvent", &.{}),
        .fs_evt_inval_dir => acheronSchema(.fs_evt_inval_dir, "node_fs", .event, "FsInvalidateDirEvent", &.{}),
        .fs_err => .{
            .channel = .acheron,
            .wire_name = unified.acheronTypeName(.fs_err),
            .category = "node_fs",
            .direction = .@"error",
            .correlation_field = "tag",
            .error_schema = "AcheronFsError",
        },
        .err => .{
            .channel = .acheron,
            .wire_name = unified.acheronTypeName(.err),
            .category = "runtime",
            .direction = .@"error",
            .correlation_field = "tag",
            .error_schema = "AcheronError",
        },
        .unknown => unreachable,
    };
}
