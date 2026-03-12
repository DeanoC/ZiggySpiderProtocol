// Generated from src/sdk_artifacts.zig. Do not edit by hand.
use serde::{Deserialize, Serialize};

pub type AnyJson = serde_json::Value;

pub const CONTROL_PROTOCOL: &str = "unified-v2";
pub const ACHERON_RUNTIME_VERSION: &str = "acheron-1";
pub const NODE_FS_PROTOCOL: &str = "unified-v2-fs";
pub const NODE_FS_PROTO: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Channel {
    #[serde(rename = "control")]
    Control,
    #[serde(rename = "acheron")]
    Acheron,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessageType {
    #[serde(rename = "control.version")]
    Version,
    #[serde(rename = "control.version_ack")]
    VersionAck,
    #[serde(rename = "control.connect")]
    Connect,
    #[serde(rename = "control.connect_ack")]
    ConnectAck,
    #[serde(rename = "control.session_attach")]
    SessionAttach,
    #[serde(rename = "control.session_status")]
    SessionStatus,
    #[serde(rename = "control.session_resume")]
    SessionResume,
    #[serde(rename = "control.session_list")]
    SessionList,
    #[serde(rename = "control.session_close")]
    SessionClose,
    #[serde(rename = "control.session_restore")]
    SessionRestore,
    #[serde(rename = "control.session_history")]
    SessionHistory,
    #[serde(rename = "control.ping")]
    Ping,
    #[serde(rename = "control.pong")]
    Pong,
    #[serde(rename = "control.metrics")]
    Metrics,
    #[serde(rename = "control.auth_status")]
    AuthStatus,
    #[serde(rename = "control.auth_rotate")]
    AuthRotate,
    #[serde(rename = "control.node_invite_create")]
    NodeInviteCreate,
    #[serde(rename = "control.node_join_request")]
    NodeJoinRequest,
    #[serde(rename = "control.node_join_pending_list")]
    NodeJoinPendingList,
    #[serde(rename = "control.node_join_approve")]
    NodeJoinApprove,
    #[serde(rename = "control.node_join_deny")]
    NodeJoinDeny,
    #[serde(rename = "control.node_join")]
    NodeJoin,
    #[serde(rename = "control.node_ensure")]
    NodeEnsure,
    #[serde(rename = "control.node_lease_refresh")]
    NodeLeaseRefresh,
    #[serde(rename = "control.venom_bind")]
    VenomBind,
    #[serde(rename = "control.venom_upsert")]
    VenomUpsert,
    #[serde(rename = "control.venom_get")]
    VenomGet,
    #[serde(rename = "control.agent_ensure")]
    AgentEnsure,
    #[serde(rename = "control.agent_list")]
    AgentList,
    #[serde(rename = "control.agent_get")]
    AgentGet,
    #[serde(rename = "control.node_list")]
    NodeList,
    #[serde(rename = "control.node_get")]
    NodeGet,
    #[serde(rename = "control.node_delete")]
    NodeDelete,
    #[serde(rename = "control.workspace_create")]
    WorkspaceCreate,
    #[serde(rename = "control.workspace_update")]
    WorkspaceUpdate,
    #[serde(rename = "control.workspace_delete")]
    WorkspaceDelete,
    #[serde(rename = "control.workspace_list")]
    WorkspaceList,
    #[serde(rename = "control.workspace_get")]
    WorkspaceGet,
    #[serde(rename = "control.workspace_template_list")]
    WorkspaceTemplateList,
    #[serde(rename = "control.workspace_template_get")]
    WorkspaceTemplateGet,
    #[serde(rename = "control.workspace_mount_set")]
    WorkspaceMountSet,
    #[serde(rename = "control.workspace_mount_remove")]
    WorkspaceMountRemove,
    #[serde(rename = "control.workspace_mount_list")]
    WorkspaceMountList,
    #[serde(rename = "control.workspace_bind_set")]
    WorkspaceBindSet,
    #[serde(rename = "control.workspace_bind_remove")]
    WorkspaceBindRemove,
    #[serde(rename = "control.workspace_bind_list")]
    WorkspaceBindList,
    #[serde(rename = "control.workspace_token_rotate")]
    WorkspaceTokenRotate,
    #[serde(rename = "control.workspace_token_revoke")]
    WorkspaceTokenRevoke,
    #[serde(rename = "control.workspace_activate")]
    WorkspaceActivate,
    #[serde(rename = "control.workspace_up")]
    WorkspaceUp,
    #[serde(rename = "control.project_create")]
    ProjectCreate,
    #[serde(rename = "control.project_update")]
    ProjectUpdate,
    #[serde(rename = "control.project_delete")]
    ProjectDelete,
    #[serde(rename = "control.project_list")]
    ProjectList,
    #[serde(rename = "control.project_get")]
    ProjectGet,
    #[serde(rename = "control.project_mount_set")]
    ProjectMountSet,
    #[serde(rename = "control.project_mount_remove")]
    ProjectMountRemove,
    #[serde(rename = "control.project_mount_list")]
    ProjectMountList,
    #[serde(rename = "control.project_token_rotate")]
    ProjectTokenRotate,
    #[serde(rename = "control.project_token_revoke")]
    ProjectTokenRevoke,
    #[serde(rename = "control.project_activate")]
    ProjectActivate,
    #[serde(rename = "control.workspace_status")]
    WorkspaceStatus,
    #[serde(rename = "control.reconcile_status")]
    ReconcileStatus,
    #[serde(rename = "control.project_up")]
    ProjectUp,
    #[serde(rename = "control.audit_tail")]
    AuditTail,
    #[serde(rename = "control.error")]
    Err,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcheronMessageType {
    #[serde(rename = "acheron.t_version")]
    TVersion,
    #[serde(rename = "acheron.r_version")]
    RVersion,
    #[serde(rename = "acheron.t_attach")]
    TAttach,
    #[serde(rename = "acheron.r_attach")]
    RAttach,
    #[serde(rename = "acheron.t_walk")]
    TWalk,
    #[serde(rename = "acheron.r_walk")]
    RWalk,
    #[serde(rename = "acheron.t_open")]
    TOpen,
    #[serde(rename = "acheron.r_open")]
    ROpen,
    #[serde(rename = "acheron.t_read")]
    TRead,
    #[serde(rename = "acheron.r_read")]
    RRead,
    #[serde(rename = "acheron.t_write")]
    TWrite,
    #[serde(rename = "acheron.r_write")]
    RWrite,
    #[serde(rename = "acheron.t_stat")]
    TStat,
    #[serde(rename = "acheron.r_stat")]
    RStat,
    #[serde(rename = "acheron.t_clunk")]
    TClunk,
    #[serde(rename = "acheron.r_clunk")]
    RClunk,
    #[serde(rename = "acheron.t_flush")]
    TFlush,
    #[serde(rename = "acheron.r_flush")]
    RFlush,
    #[serde(rename = "acheron.t_fs_hello")]
    FsTHello,
    #[serde(rename = "acheron.r_fs_hello")]
    FsRHello,
    #[serde(rename = "acheron.t_fs_exports")]
    FsTExports,
    #[serde(rename = "acheron.r_fs_exports")]
    FsRExports,
    #[serde(rename = "acheron.t_fs_lookup")]
    FsTLookup,
    #[serde(rename = "acheron.r_fs_lookup")]
    FsRLookup,
    #[serde(rename = "acheron.t_fs_getattr")]
    FsTGetattr,
    #[serde(rename = "acheron.r_fs_getattr")]
    FsRGetattr,
    #[serde(rename = "acheron.t_fs_readdirp")]
    FsTReaddirp,
    #[serde(rename = "acheron.r_fs_readdirp")]
    FsRReaddirp,
    #[serde(rename = "acheron.t_fs_symlink")]
    FsTSymlink,
    #[serde(rename = "acheron.r_fs_symlink")]
    FsRSymlink,
    #[serde(rename = "acheron.t_fs_setxattr")]
    FsTSetxattr,
    #[serde(rename = "acheron.r_fs_setxattr")]
    FsRSetxattr,
    #[serde(rename = "acheron.t_fs_getxattr")]
    FsTGetxattr,
    #[serde(rename = "acheron.r_fs_getxattr")]
    FsRGetxattr,
    #[serde(rename = "acheron.t_fs_listxattr")]
    FsTListxattr,
    #[serde(rename = "acheron.r_fs_listxattr")]
    FsRListxattr,
    #[serde(rename = "acheron.t_fs_removexattr")]
    FsTRemovexattr,
    #[serde(rename = "acheron.r_fs_removexattr")]
    FsRRemovexattr,
    #[serde(rename = "acheron.t_fs_open")]
    FsTOpen,
    #[serde(rename = "acheron.r_fs_open")]
    FsROpen,
    #[serde(rename = "acheron.t_fs_read")]
    FsTRead,
    #[serde(rename = "acheron.r_fs_read")]
    FsRRead,
    #[serde(rename = "acheron.t_fs_close")]
    FsTClose,
    #[serde(rename = "acheron.r_fs_close")]
    FsRClose,
    #[serde(rename = "acheron.t_fs_lock")]
    FsTLock,
    #[serde(rename = "acheron.r_fs_lock")]
    FsRLock,
    #[serde(rename = "acheron.t_fs_create")]
    FsTCreate,
    #[serde(rename = "acheron.r_fs_create")]
    FsRCreate,
    #[serde(rename = "acheron.t_fs_write")]
    FsTWrite,
    #[serde(rename = "acheron.r_fs_write")]
    FsRWrite,
    #[serde(rename = "acheron.t_fs_truncate")]
    FsTTruncate,
    #[serde(rename = "acheron.r_fs_truncate")]
    FsRTruncate,
    #[serde(rename = "acheron.t_fs_unlink")]
    FsTUnlink,
    #[serde(rename = "acheron.r_fs_unlink")]
    FsRUnlink,
    #[serde(rename = "acheron.t_fs_mkdir")]
    FsTMkdir,
    #[serde(rename = "acheron.r_fs_mkdir")]
    FsRMkdir,
    #[serde(rename = "acheron.t_fs_rmdir")]
    FsTRmdir,
    #[serde(rename = "acheron.r_fs_rmdir")]
    FsRRmdir,
    #[serde(rename = "acheron.t_fs_rename")]
    FsTRename,
    #[serde(rename = "acheron.r_fs_rename")]
    FsRRename,
    #[serde(rename = "acheron.t_fs_statfs")]
    FsTStatfs,
    #[serde(rename = "acheron.r_fs_statfs")]
    FsRStatfs,
    #[serde(rename = "acheron.e_fs_inval")]
    FsEvtInval,
    #[serde(rename = "acheron.e_fs_inval_dir")]
    FsEvtInvalDir,
    #[serde(rename = "acheron.err_fs")]
    FsErr,
    #[serde(rename = "acheron.error")]
    Err,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlEnvelope<T> {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: ControlMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlErrorEnvelope {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: ControlMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    pub error: ControlError,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcheronPayloadEnvelope<T> {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: AcheronMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcheronVersionEnvelope {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: AcheronMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    pub msize: u32,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcheronAttachEnvelope {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: AcheronMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcheronNodeEnvelope<T> {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: AcheronMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    pub node: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcheronHandleEnvelope<T> {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: AcheronMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(rename = "h")]
    pub handle: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcheronErrorEnvelope<T> {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: AcheronMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    pub error: T,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AcheronEventEnvelope<T> {
    pub channel: Channel,
    #[serde(rename = "type")]
    pub message_type: AcheronMessageType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EmptyObject {
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ControlError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AcheronError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AcheronFsError {
    pub errno: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ControlVersionRequestPayload {
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ControlVersionAckPayload {
    pub protocol: String,
    pub acheron_runtime: String,
    pub acheron_node: String,
    pub acheron_node_proto: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ConnectAckWorkspaceMount {
    pub mount_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ConnectAckWorkspace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<ConnectAckWorkspaceMount>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ControlConnectAckPayload {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_only: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_session_attach: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<ConnectAckWorkspace>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NodeEnsureRequest {
    pub node_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_ttl_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct EnsuredNodeIdentity {
    pub node_id: String,
    pub node_name: String,
    pub node_secret: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct MountView {
    pub mount_path: String,
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_url: Option<String>,
    pub export_name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct BindView {
    pub bind_path: String,
    pub target_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceSummary {
    #[serde(alias = "id", alias = "project_id")]
    pub workspace_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_delete_protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_locked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectSummary {
    #[serde(alias = "id", alias = "workspace_id")]
    pub project_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_delete_protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_locked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceDetail {
    #[serde(alias = "id", alias = "project_id")]
    pub workspace_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_delete_protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_locked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "project_token")]
    pub workspace_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binds: Option<Vec<BindView>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectDetail {
    #[serde(alias = "id", alias = "workspace_id")]
    pub project_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_delete_protected: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_locked: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "workspace_token")]
    pub project_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binds: Option<Vec<BindView>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceRefRequest {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectRefRequest {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NodeIdRequest {
    pub node_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentIdRequest {
    pub agent_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceTemplateGetRequest {
    pub template_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionKeyRequest {
    pub session_key: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionAttachRequest {
    pub session_key: String,
    pub agent_id: String,
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionStatusRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionHistoryRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceCreateRequest {
    pub name: String,
    pub vision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AnyJson>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectCreateRequest {
    pub name: String,
    pub vision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AnyJson>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceUpdateRequest {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AnyJson>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectUpdateRequest {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AnyJson>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceMountSetRequest {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
    pub node_id: String,
    pub export_name: String,
    pub mount_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectMountSetRequest {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
    pub node_id: String,
    pub export_name: String,
    pub mount_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceMountRemoveRequest {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
    pub mount_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectMountRemoveRequest {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
    pub mount_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceBindSetRequest {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
    pub bind_path: String,
    pub target_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectBindSetRequest {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
    pub bind_path: String,
    pub target_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceBindRemoveRequest {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
    pub bind_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectBindRemoveRequest {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
    pub bind_path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceUpRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AnyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_mounts: Option<AnyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_binds: Option<AnyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectUpRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_policy: Option<AnyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_mounts: Option<AnyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_binds: Option<AnyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceStatusRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReconcileStatusRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct VenomBindRequest {
    pub venom_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceTemplateBind {
    pub bind_path: String,
    pub venom_id: String,
    pub provider_scope: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceTemplate {
    pub id: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binds: Option<Vec<WorkspaceTemplateBind>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceTemplateListResponse {
    pub templates: Vec<WorkspaceTemplate>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceTemplateGetResponse {
    pub template: WorkspaceTemplate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceListResponse {
    pub workspaces: Vec<WorkspaceSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectListResponse {
    pub projects: Vec<ProjectSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceMountListResponse {
    pub workspace_id: String,
    pub mounts: Vec<MountView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectMountListResponse {
    pub project_id: String,
    pub mounts: Vec<MountView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceBindListResponse {
    pub workspace_id: String,
    pub binds: Vec<BindView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectBindListResponse {
    pub project_id: String,
    pub binds: Vec<BindView>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceDeleteResponse {
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "id", alias = "project_id")]
    pub workspace_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectDeleteResponse {
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "id", alias = "workspace_id")]
    pub project_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceTokenMutation {
    #[serde(alias = "id", alias = "project_id")]
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "project_token")]
    pub workspace_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectTokenMutation {
    #[serde(alias = "id", alias = "workspace_id")]
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "workspace_token")]
    pub project_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DriftItem {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct DriftSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<DriftItem>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AvailabilitySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceStatus {
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "id", alias = "project_id")]
    pub workspace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desired_mounts: Option<Vec<MountView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_mounts: Option<Vec<MountView>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<DriftSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability: Option<AvailabilitySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconcile_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectActivation {
    pub agent_id: String,
    #[serde(alias = "id", alias = "workspace_id")]
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionAttachState {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionStatusResponse {
    pub session_key: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    pub attach: SessionAttachState,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionSummary {
    pub session_key: String,
    pub agent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_active_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionListResponse {
    pub active_session: String,
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionCloseResponse {
    pub session_key: String,
    pub closed: bool,
    pub active_session: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionRestoreResponse {
    pub found: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionHistoryResponse {
    pub sessions: Vec<SessionSummary>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReconcileProjectStatus {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mounts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_mounts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online_mounts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degraded_mounts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_mounts: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ReconcileStatusResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconcile_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconcile_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_ops_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycles_total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_ops: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projects: Option<Vec<ReconcileProjectStatus>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NodeInfo {
    pub node_id: String,
    pub node_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NodeListResponse {
    pub nodes: Vec<NodeInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct NodeGetResponse {
    pub node: NodeInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentInfo {
    #[serde(alias = "id")]
    pub agent_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub needs_hatching: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentListResponse {
    pub agents: Vec<AgentInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AgentGetResponse {
    pub agent: AgentInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct WorkspaceUpResponse {
    pub workspace_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_token: Option<String>,
    pub created: bool,
    pub activated: bool,
    pub workspace: AnyJson,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProjectUpResponse {
    pub project_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_token: Option<String>,
    pub created: bool,
    pub activated: bool,
    pub workspace: AnyJson,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct AcheronAttachResponse {
    pub layout: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roots: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsHelloRequest {
    pub protocol: String,
    pub proto: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsHelloCapabilities {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exports: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub write: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsHelloResponse {
    pub protocol: String,
    pub proto: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<FsHelloCapabilities>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps: Option<AnyJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<AnyJson>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsLookupRequest {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsLookupResponse {
    pub node: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr: Option<AnyJson>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsGetattrResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attr: Option<AnyJson>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsReaddirpRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsDirEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsReaddirpResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<FsDirEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ents: Option<Vec<FsDirEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eof: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsOpenRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsOpenResponse {
    pub handle: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsReadRequest {
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsReadResponse {
    pub data_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eof: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsWriteRequest {
    pub offset: u64,
    pub data_b64: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsWriteResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsInvalidateEvent {
    pub node: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gen: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct FsInvalidateDirEvent {
    pub dir: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir_gen: Option<u64>,
}

pub type ControlErrorEnvelopeEnum = ControlErrorEnvelope;

#[derive(Debug, Clone, PartialEq)]
pub enum ControlRequestEnvelope {
    Version(ControlEnvelope<ControlVersionRequestPayload>),
    Connect(ControlEnvelope<EmptyObject>),
    SessionAttach(ControlEnvelope<SessionAttachRequest>),
    SessionStatus(ControlEnvelope<SessionStatusRequest>),
    SessionResume(ControlEnvelope<SessionKeyRequest>),
    SessionList(ControlEnvelope<EmptyObject>),
    SessionClose(ControlEnvelope<SessionKeyRequest>),
    SessionRestore(ControlEnvelope<AgentIdRequest>),
    SessionHistory(ControlEnvelope<SessionHistoryRequest>),
    Ping(ControlEnvelope<AnyJson>),
    Metrics(ControlEnvelope<EmptyObject>),
    AuthStatus(ControlEnvelope<EmptyObject>),
    AuthRotate(ControlEnvelope<EmptyObject>),
    NodeInviteCreate(ControlEnvelope<AnyJson>),
    NodeJoinRequest(ControlEnvelope<AnyJson>),
    NodeJoinPendingList(ControlEnvelope<EmptyObject>),
    NodeJoinApprove(ControlEnvelope<AnyJson>),
    NodeJoinDeny(ControlEnvelope<AnyJson>),
    NodeJoin(ControlEnvelope<AnyJson>),
    NodeEnsure(ControlEnvelope<NodeEnsureRequest>),
    NodeLeaseRefresh(ControlEnvelope<AnyJson>),
    VenomBind(ControlEnvelope<VenomBindRequest>),
    VenomUpsert(ControlEnvelope<AnyJson>),
    VenomGet(ControlEnvelope<AnyJson>),
    AgentEnsure(ControlEnvelope<AnyJson>),
    AgentList(ControlEnvelope<EmptyObject>),
    AgentGet(ControlEnvelope<AgentIdRequest>),
    NodeList(ControlEnvelope<EmptyObject>),
    NodeGet(ControlEnvelope<NodeIdRequest>),
    NodeDelete(ControlEnvelope<NodeIdRequest>),
    WorkspaceCreate(ControlEnvelope<WorkspaceCreateRequest>),
    WorkspaceUpdate(ControlEnvelope<WorkspaceUpdateRequest>),
    WorkspaceDelete(ControlEnvelope<WorkspaceRefRequest>),
    WorkspaceList(ControlEnvelope<EmptyObject>),
    WorkspaceGet(ControlEnvelope<WorkspaceRefRequest>),
    WorkspaceTemplateList(ControlEnvelope<EmptyObject>),
    WorkspaceTemplateGet(ControlEnvelope<WorkspaceTemplateGetRequest>),
    WorkspaceMountSet(ControlEnvelope<WorkspaceMountSetRequest>),
    WorkspaceMountRemove(ControlEnvelope<WorkspaceMountRemoveRequest>),
    WorkspaceMountList(ControlEnvelope<WorkspaceRefRequest>),
    WorkspaceBindSet(ControlEnvelope<WorkspaceBindSetRequest>),
    WorkspaceBindRemove(ControlEnvelope<WorkspaceBindRemoveRequest>),
    WorkspaceBindList(ControlEnvelope<WorkspaceRefRequest>),
    WorkspaceTokenRotate(ControlEnvelope<WorkspaceRefRequest>),
    WorkspaceTokenRevoke(ControlEnvelope<WorkspaceRefRequest>),
    WorkspaceActivate(ControlEnvelope<WorkspaceRefRequest>),
    WorkspaceUp(ControlEnvelope<WorkspaceUpRequest>),
    ProjectCreate(ControlEnvelope<ProjectCreateRequest>),
    ProjectUpdate(ControlEnvelope<ProjectUpdateRequest>),
    ProjectDelete(ControlEnvelope<ProjectRefRequest>),
    ProjectList(ControlEnvelope<EmptyObject>),
    ProjectGet(ControlEnvelope<ProjectRefRequest>),
    ProjectMountSet(ControlEnvelope<ProjectMountSetRequest>),
    ProjectMountRemove(ControlEnvelope<ProjectMountRemoveRequest>),
    ProjectMountList(ControlEnvelope<ProjectRefRequest>),
    ProjectTokenRotate(ControlEnvelope<ProjectRefRequest>),
    ProjectTokenRevoke(ControlEnvelope<ProjectRefRequest>),
    ProjectActivate(ControlEnvelope<ProjectRefRequest>),
    WorkspaceStatus(ControlEnvelope<WorkspaceStatusRequest>),
    ReconcileStatus(ControlEnvelope<ReconcileStatusRequest>),
    ProjectUp(ControlEnvelope<ProjectUpRequest>),
    AuditTail(ControlEnvelope<AnyJson>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlResponseEnvelope {
    VersionAck(ControlEnvelope<ControlVersionAckPayload>),
    ConnectAck(ControlEnvelope<ControlConnectAckPayload>),
    SessionAttach(ControlEnvelope<SessionStatusResponse>),
    SessionStatus(ControlEnvelope<SessionStatusResponse>),
    SessionResume(ControlEnvelope<SessionStatusResponse>),
    SessionList(ControlEnvelope<SessionListResponse>),
    SessionClose(ControlEnvelope<SessionCloseResponse>),
    SessionRestore(ControlEnvelope<SessionRestoreResponse>),
    SessionHistory(ControlEnvelope<SessionHistoryResponse>),
    Ping(ControlEnvelope<AnyJson>),
    Pong(ControlEnvelope<AnyJson>),
    Metrics(ControlEnvelope<AnyJson>),
    AuthStatus(ControlEnvelope<AnyJson>),
    AuthRotate(ControlEnvelope<AnyJson>),
    NodeInviteCreate(ControlEnvelope<AnyJson>),
    NodeJoinRequest(ControlEnvelope<AnyJson>),
    NodeJoinPendingList(ControlEnvelope<AnyJson>),
    NodeJoinApprove(ControlEnvelope<AnyJson>),
    NodeJoinDeny(ControlEnvelope<AnyJson>),
    NodeJoin(ControlEnvelope<AnyJson>),
    NodeEnsure(ControlEnvelope<EnsuredNodeIdentity>),
    NodeLeaseRefresh(ControlEnvelope<AnyJson>),
    VenomBind(ControlEnvelope<AnyJson>),
    VenomUpsert(ControlEnvelope<AnyJson>),
    VenomGet(ControlEnvelope<AnyJson>),
    AgentEnsure(ControlEnvelope<AnyJson>),
    AgentList(ControlEnvelope<AgentListResponse>),
    AgentGet(ControlEnvelope<AgentGetResponse>),
    NodeList(ControlEnvelope<NodeListResponse>),
    NodeGet(ControlEnvelope<NodeGetResponse>),
    NodeDelete(ControlEnvelope<AnyJson>),
    WorkspaceCreate(ControlEnvelope<WorkspaceDetail>),
    WorkspaceUpdate(ControlEnvelope<WorkspaceDetail>),
    WorkspaceDelete(ControlEnvelope<WorkspaceDeleteResponse>),
    WorkspaceList(ControlEnvelope<WorkspaceListResponse>),
    WorkspaceGet(ControlEnvelope<WorkspaceDetail>),
    WorkspaceTemplateList(ControlEnvelope<WorkspaceTemplateListResponse>),
    WorkspaceTemplateGet(ControlEnvelope<WorkspaceTemplateGetResponse>),
    WorkspaceMountSet(ControlEnvelope<WorkspaceDetail>),
    WorkspaceMountRemove(ControlEnvelope<WorkspaceDetail>),
    WorkspaceMountList(ControlEnvelope<WorkspaceMountListResponse>),
    WorkspaceBindSet(ControlEnvelope<WorkspaceDetail>),
    WorkspaceBindRemove(ControlEnvelope<WorkspaceDetail>),
    WorkspaceBindList(ControlEnvelope<WorkspaceBindListResponse>),
    WorkspaceTokenRotate(ControlEnvelope<WorkspaceTokenMutation>),
    WorkspaceTokenRevoke(ControlEnvelope<WorkspaceTokenMutation>),
    WorkspaceActivate(ControlEnvelope<WorkspaceStatus>),
    WorkspaceUp(ControlEnvelope<WorkspaceUpResponse>),
    ProjectCreate(ControlEnvelope<ProjectDetail>),
    ProjectUpdate(ControlEnvelope<ProjectDetail>),
    ProjectDelete(ControlEnvelope<ProjectDeleteResponse>),
    ProjectList(ControlEnvelope<ProjectListResponse>),
    ProjectGet(ControlEnvelope<ProjectDetail>),
    ProjectMountSet(ControlEnvelope<ProjectDetail>),
    ProjectMountRemove(ControlEnvelope<ProjectDetail>),
    ProjectMountList(ControlEnvelope<ProjectMountListResponse>),
    ProjectTokenRotate(ControlEnvelope<ProjectTokenMutation>),
    ProjectTokenRevoke(ControlEnvelope<ProjectTokenMutation>),
    ProjectActivate(ControlEnvelope<ProjectActivation>),
    WorkspaceStatus(ControlEnvelope<WorkspaceStatus>),
    ReconcileStatus(ControlEnvelope<ReconcileStatusResponse>),
    ProjectUp(ControlEnvelope<ProjectUpResponse>),
    AuditTail(ControlEnvelope<AnyJson>),
}

impl ControlRequestEnvelope {
    pub fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::Version(inner) => serde_json::to_value(inner),
            Self::Connect(inner) => serde_json::to_value(inner),
            Self::SessionAttach(inner) => serde_json::to_value(inner),
            Self::SessionStatus(inner) => serde_json::to_value(inner),
            Self::SessionResume(inner) => serde_json::to_value(inner),
            Self::SessionList(inner) => serde_json::to_value(inner),
            Self::SessionClose(inner) => serde_json::to_value(inner),
            Self::SessionRestore(inner) => serde_json::to_value(inner),
            Self::SessionHistory(inner) => serde_json::to_value(inner),
            Self::Ping(inner) => serde_json::to_value(inner),
            Self::Metrics(inner) => serde_json::to_value(inner),
            Self::AuthStatus(inner) => serde_json::to_value(inner),
            Self::AuthRotate(inner) => serde_json::to_value(inner),
            Self::NodeInviteCreate(inner) => serde_json::to_value(inner),
            Self::NodeJoinRequest(inner) => serde_json::to_value(inner),
            Self::NodeJoinPendingList(inner) => serde_json::to_value(inner),
            Self::NodeJoinApprove(inner) => serde_json::to_value(inner),
            Self::NodeJoinDeny(inner) => serde_json::to_value(inner),
            Self::NodeJoin(inner) => serde_json::to_value(inner),
            Self::NodeEnsure(inner) => serde_json::to_value(inner),
            Self::NodeLeaseRefresh(inner) => serde_json::to_value(inner),
            Self::VenomBind(inner) => serde_json::to_value(inner),
            Self::VenomUpsert(inner) => serde_json::to_value(inner),
            Self::VenomGet(inner) => serde_json::to_value(inner),
            Self::AgentEnsure(inner) => serde_json::to_value(inner),
            Self::AgentList(inner) => serde_json::to_value(inner),
            Self::AgentGet(inner) => serde_json::to_value(inner),
            Self::NodeList(inner) => serde_json::to_value(inner),
            Self::NodeGet(inner) => serde_json::to_value(inner),
            Self::NodeDelete(inner) => serde_json::to_value(inner),
            Self::WorkspaceCreate(inner) => serde_json::to_value(inner),
            Self::WorkspaceUpdate(inner) => serde_json::to_value(inner),
            Self::WorkspaceDelete(inner) => serde_json::to_value(inner),
            Self::WorkspaceList(inner) => serde_json::to_value(inner),
            Self::WorkspaceGet(inner) => serde_json::to_value(inner),
            Self::WorkspaceTemplateList(inner) => serde_json::to_value(inner),
            Self::WorkspaceTemplateGet(inner) => serde_json::to_value(inner),
            Self::WorkspaceMountSet(inner) => serde_json::to_value(inner),
            Self::WorkspaceMountRemove(inner) => serde_json::to_value(inner),
            Self::WorkspaceMountList(inner) => serde_json::to_value(inner),
            Self::WorkspaceBindSet(inner) => serde_json::to_value(inner),
            Self::WorkspaceBindRemove(inner) => serde_json::to_value(inner),
            Self::WorkspaceBindList(inner) => serde_json::to_value(inner),
            Self::WorkspaceTokenRotate(inner) => serde_json::to_value(inner),
            Self::WorkspaceTokenRevoke(inner) => serde_json::to_value(inner),
            Self::WorkspaceActivate(inner) => serde_json::to_value(inner),
            Self::WorkspaceUp(inner) => serde_json::to_value(inner),
            Self::ProjectCreate(inner) => serde_json::to_value(inner),
            Self::ProjectUpdate(inner) => serde_json::to_value(inner),
            Self::ProjectDelete(inner) => serde_json::to_value(inner),
            Self::ProjectList(inner) => serde_json::to_value(inner),
            Self::ProjectGet(inner) => serde_json::to_value(inner),
            Self::ProjectMountSet(inner) => serde_json::to_value(inner),
            Self::ProjectMountRemove(inner) => serde_json::to_value(inner),
            Self::ProjectMountList(inner) => serde_json::to_value(inner),
            Self::ProjectTokenRotate(inner) => serde_json::to_value(inner),
            Self::ProjectTokenRevoke(inner) => serde_json::to_value(inner),
            Self::ProjectActivate(inner) => serde_json::to_value(inner),
            Self::WorkspaceStatus(inner) => serde_json::to_value(inner),
            Self::ReconcileStatus(inner) => serde_json::to_value(inner),
            Self::ProjectUp(inner) => serde_json::to_value(inner),
            Self::AuditTail(inner) => serde_json::to_value(inner),
        }
    }

    pub fn from_value(value: serde_json::Value) -> serde_json::Result<Self> {
        let message_type = value.get("type").and_then(|v| v.as_str()).ok_or_else(|| serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing type")))?;
        match message_type {
            "control.version" => Ok(Self::Version(serde_json::from_value(value)?)),
            "control.connect" => Ok(Self::Connect(serde_json::from_value(value)?)),
            "control.session_attach" => Ok(Self::SessionAttach(serde_json::from_value(value)?)),
            "control.session_status" => Ok(Self::SessionStatus(serde_json::from_value(value)?)),
            "control.session_resume" => Ok(Self::SessionResume(serde_json::from_value(value)?)),
            "control.session_list" => Ok(Self::SessionList(serde_json::from_value(value)?)),
            "control.session_close" => Ok(Self::SessionClose(serde_json::from_value(value)?)),
            "control.session_restore" => Ok(Self::SessionRestore(serde_json::from_value(value)?)),
            "control.session_history" => Ok(Self::SessionHistory(serde_json::from_value(value)?)),
            "control.ping" => Ok(Self::Ping(serde_json::from_value(value)?)),
            "control.metrics" => Ok(Self::Metrics(serde_json::from_value(value)?)),
            "control.auth_status" => Ok(Self::AuthStatus(serde_json::from_value(value)?)),
            "control.auth_rotate" => Ok(Self::AuthRotate(serde_json::from_value(value)?)),
            "control.node_invite_create" => Ok(Self::NodeInviteCreate(serde_json::from_value(value)?)),
            "control.node_join_request" => Ok(Self::NodeJoinRequest(serde_json::from_value(value)?)),
            "control.node_join_pending_list" => Ok(Self::NodeJoinPendingList(serde_json::from_value(value)?)),
            "control.node_join_approve" => Ok(Self::NodeJoinApprove(serde_json::from_value(value)?)),
            "control.node_join_deny" => Ok(Self::NodeJoinDeny(serde_json::from_value(value)?)),
            "control.node_join" => Ok(Self::NodeJoin(serde_json::from_value(value)?)),
            "control.node_ensure" => Ok(Self::NodeEnsure(serde_json::from_value(value)?)),
            "control.node_lease_refresh" => Ok(Self::NodeLeaseRefresh(serde_json::from_value(value)?)),
            "control.venom_bind" => Ok(Self::VenomBind(serde_json::from_value(value)?)),
            "control.venom_upsert" => Ok(Self::VenomUpsert(serde_json::from_value(value)?)),
            "control.venom_get" => Ok(Self::VenomGet(serde_json::from_value(value)?)),
            "control.agent_ensure" => Ok(Self::AgentEnsure(serde_json::from_value(value)?)),
            "control.agent_list" => Ok(Self::AgentList(serde_json::from_value(value)?)),
            "control.agent_get" => Ok(Self::AgentGet(serde_json::from_value(value)?)),
            "control.node_list" => Ok(Self::NodeList(serde_json::from_value(value)?)),
            "control.node_get" => Ok(Self::NodeGet(serde_json::from_value(value)?)),
            "control.node_delete" => Ok(Self::NodeDelete(serde_json::from_value(value)?)),
            "control.workspace_create" => Ok(Self::WorkspaceCreate(serde_json::from_value(value)?)),
            "control.workspace_update" => Ok(Self::WorkspaceUpdate(serde_json::from_value(value)?)),
            "control.workspace_delete" => Ok(Self::WorkspaceDelete(serde_json::from_value(value)?)),
            "control.workspace_list" => Ok(Self::WorkspaceList(serde_json::from_value(value)?)),
            "control.workspace_get" => Ok(Self::WorkspaceGet(serde_json::from_value(value)?)),
            "control.workspace_template_list" => Ok(Self::WorkspaceTemplateList(serde_json::from_value(value)?)),
            "control.workspace_template_get" => Ok(Self::WorkspaceTemplateGet(serde_json::from_value(value)?)),
            "control.workspace_mount_set" => Ok(Self::WorkspaceMountSet(serde_json::from_value(value)?)),
            "control.workspace_mount_remove" => Ok(Self::WorkspaceMountRemove(serde_json::from_value(value)?)),
            "control.workspace_mount_list" => Ok(Self::WorkspaceMountList(serde_json::from_value(value)?)),
            "control.workspace_bind_set" => Ok(Self::WorkspaceBindSet(serde_json::from_value(value)?)),
            "control.workspace_bind_remove" => Ok(Self::WorkspaceBindRemove(serde_json::from_value(value)?)),
            "control.workspace_bind_list" => Ok(Self::WorkspaceBindList(serde_json::from_value(value)?)),
            "control.workspace_token_rotate" => Ok(Self::WorkspaceTokenRotate(serde_json::from_value(value)?)),
            "control.workspace_token_revoke" => Ok(Self::WorkspaceTokenRevoke(serde_json::from_value(value)?)),
            "control.workspace_activate" => Ok(Self::WorkspaceActivate(serde_json::from_value(value)?)),
            "control.workspace_up" => Ok(Self::WorkspaceUp(serde_json::from_value(value)?)),
            "control.project_create" => Ok(Self::ProjectCreate(serde_json::from_value(value)?)),
            "control.project_update" => Ok(Self::ProjectUpdate(serde_json::from_value(value)?)),
            "control.project_delete" => Ok(Self::ProjectDelete(serde_json::from_value(value)?)),
            "control.project_list" => Ok(Self::ProjectList(serde_json::from_value(value)?)),
            "control.project_get" => Ok(Self::ProjectGet(serde_json::from_value(value)?)),
            "control.project_mount_set" => Ok(Self::ProjectMountSet(serde_json::from_value(value)?)),
            "control.project_mount_remove" => Ok(Self::ProjectMountRemove(serde_json::from_value(value)?)),
            "control.project_mount_list" => Ok(Self::ProjectMountList(serde_json::from_value(value)?)),
            "control.project_token_rotate" => Ok(Self::ProjectTokenRotate(serde_json::from_value(value)?)),
            "control.project_token_revoke" => Ok(Self::ProjectTokenRevoke(serde_json::from_value(value)?)),
            "control.project_activate" => Ok(Self::ProjectActivate(serde_json::from_value(value)?)),
            "control.workspace_status" => Ok(Self::WorkspaceStatus(serde_json::from_value(value)?)),
            "control.reconcile_status" => Ok(Self::ReconcileStatus(serde_json::from_value(value)?)),
            "control.project_up" => Ok(Self::ProjectUp(serde_json::from_value(value)?)),
            "control.audit_tail" => Ok(Self::AuditTail(serde_json::from_value(value)?)),
            _ => Err(serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported type"))),
        }
    }

    pub fn message_type(&self) -> ControlMessageType {
        match self {
            Self::Version(_) => ControlMessageType::Version,
            Self::Connect(_) => ControlMessageType::Connect,
            Self::SessionAttach(_) => ControlMessageType::SessionAttach,
            Self::SessionStatus(_) => ControlMessageType::SessionStatus,
            Self::SessionResume(_) => ControlMessageType::SessionResume,
            Self::SessionList(_) => ControlMessageType::SessionList,
            Self::SessionClose(_) => ControlMessageType::SessionClose,
            Self::SessionRestore(_) => ControlMessageType::SessionRestore,
            Self::SessionHistory(_) => ControlMessageType::SessionHistory,
            Self::Ping(_) => ControlMessageType::Ping,
            Self::Metrics(_) => ControlMessageType::Metrics,
            Self::AuthStatus(_) => ControlMessageType::AuthStatus,
            Self::AuthRotate(_) => ControlMessageType::AuthRotate,
            Self::NodeInviteCreate(_) => ControlMessageType::NodeInviteCreate,
            Self::NodeJoinRequest(_) => ControlMessageType::NodeJoinRequest,
            Self::NodeJoinPendingList(_) => ControlMessageType::NodeJoinPendingList,
            Self::NodeJoinApprove(_) => ControlMessageType::NodeJoinApprove,
            Self::NodeJoinDeny(_) => ControlMessageType::NodeJoinDeny,
            Self::NodeJoin(_) => ControlMessageType::NodeJoin,
            Self::NodeEnsure(_) => ControlMessageType::NodeEnsure,
            Self::NodeLeaseRefresh(_) => ControlMessageType::NodeLeaseRefresh,
            Self::VenomBind(_) => ControlMessageType::VenomBind,
            Self::VenomUpsert(_) => ControlMessageType::VenomUpsert,
            Self::VenomGet(_) => ControlMessageType::VenomGet,
            Self::AgentEnsure(_) => ControlMessageType::AgentEnsure,
            Self::AgentList(_) => ControlMessageType::AgentList,
            Self::AgentGet(_) => ControlMessageType::AgentGet,
            Self::NodeList(_) => ControlMessageType::NodeList,
            Self::NodeGet(_) => ControlMessageType::NodeGet,
            Self::NodeDelete(_) => ControlMessageType::NodeDelete,
            Self::WorkspaceCreate(_) => ControlMessageType::WorkspaceCreate,
            Self::WorkspaceUpdate(_) => ControlMessageType::WorkspaceUpdate,
            Self::WorkspaceDelete(_) => ControlMessageType::WorkspaceDelete,
            Self::WorkspaceList(_) => ControlMessageType::WorkspaceList,
            Self::WorkspaceGet(_) => ControlMessageType::WorkspaceGet,
            Self::WorkspaceTemplateList(_) => ControlMessageType::WorkspaceTemplateList,
            Self::WorkspaceTemplateGet(_) => ControlMessageType::WorkspaceTemplateGet,
            Self::WorkspaceMountSet(_) => ControlMessageType::WorkspaceMountSet,
            Self::WorkspaceMountRemove(_) => ControlMessageType::WorkspaceMountRemove,
            Self::WorkspaceMountList(_) => ControlMessageType::WorkspaceMountList,
            Self::WorkspaceBindSet(_) => ControlMessageType::WorkspaceBindSet,
            Self::WorkspaceBindRemove(_) => ControlMessageType::WorkspaceBindRemove,
            Self::WorkspaceBindList(_) => ControlMessageType::WorkspaceBindList,
            Self::WorkspaceTokenRotate(_) => ControlMessageType::WorkspaceTokenRotate,
            Self::WorkspaceTokenRevoke(_) => ControlMessageType::WorkspaceTokenRevoke,
            Self::WorkspaceActivate(_) => ControlMessageType::WorkspaceActivate,
            Self::WorkspaceUp(_) => ControlMessageType::WorkspaceUp,
            Self::ProjectCreate(_) => ControlMessageType::ProjectCreate,
            Self::ProjectUpdate(_) => ControlMessageType::ProjectUpdate,
            Self::ProjectDelete(_) => ControlMessageType::ProjectDelete,
            Self::ProjectList(_) => ControlMessageType::ProjectList,
            Self::ProjectGet(_) => ControlMessageType::ProjectGet,
            Self::ProjectMountSet(_) => ControlMessageType::ProjectMountSet,
            Self::ProjectMountRemove(_) => ControlMessageType::ProjectMountRemove,
            Self::ProjectMountList(_) => ControlMessageType::ProjectMountList,
            Self::ProjectTokenRotate(_) => ControlMessageType::ProjectTokenRotate,
            Self::ProjectTokenRevoke(_) => ControlMessageType::ProjectTokenRevoke,
            Self::ProjectActivate(_) => ControlMessageType::ProjectActivate,
            Self::WorkspaceStatus(_) => ControlMessageType::WorkspaceStatus,
            Self::ReconcileStatus(_) => ControlMessageType::ReconcileStatus,
            Self::ProjectUp(_) => ControlMessageType::ProjectUp,
            Self::AuditTail(_) => ControlMessageType::AuditTail,
        }
    }
}

impl ControlResponseEnvelope {
    pub fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::VersionAck(inner) => serde_json::to_value(inner),
            Self::ConnectAck(inner) => serde_json::to_value(inner),
            Self::SessionAttach(inner) => serde_json::to_value(inner),
            Self::SessionStatus(inner) => serde_json::to_value(inner),
            Self::SessionResume(inner) => serde_json::to_value(inner),
            Self::SessionList(inner) => serde_json::to_value(inner),
            Self::SessionClose(inner) => serde_json::to_value(inner),
            Self::SessionRestore(inner) => serde_json::to_value(inner),
            Self::SessionHistory(inner) => serde_json::to_value(inner),
            Self::Ping(inner) => serde_json::to_value(inner),
            Self::Pong(inner) => serde_json::to_value(inner),
            Self::Metrics(inner) => serde_json::to_value(inner),
            Self::AuthStatus(inner) => serde_json::to_value(inner),
            Self::AuthRotate(inner) => serde_json::to_value(inner),
            Self::NodeInviteCreate(inner) => serde_json::to_value(inner),
            Self::NodeJoinRequest(inner) => serde_json::to_value(inner),
            Self::NodeJoinPendingList(inner) => serde_json::to_value(inner),
            Self::NodeJoinApprove(inner) => serde_json::to_value(inner),
            Self::NodeJoinDeny(inner) => serde_json::to_value(inner),
            Self::NodeJoin(inner) => serde_json::to_value(inner),
            Self::NodeEnsure(inner) => serde_json::to_value(inner),
            Self::NodeLeaseRefresh(inner) => serde_json::to_value(inner),
            Self::VenomBind(inner) => serde_json::to_value(inner),
            Self::VenomUpsert(inner) => serde_json::to_value(inner),
            Self::VenomGet(inner) => serde_json::to_value(inner),
            Self::AgentEnsure(inner) => serde_json::to_value(inner),
            Self::AgentList(inner) => serde_json::to_value(inner),
            Self::AgentGet(inner) => serde_json::to_value(inner),
            Self::NodeList(inner) => serde_json::to_value(inner),
            Self::NodeGet(inner) => serde_json::to_value(inner),
            Self::NodeDelete(inner) => serde_json::to_value(inner),
            Self::WorkspaceCreate(inner) => serde_json::to_value(inner),
            Self::WorkspaceUpdate(inner) => serde_json::to_value(inner),
            Self::WorkspaceDelete(inner) => serde_json::to_value(inner),
            Self::WorkspaceList(inner) => serde_json::to_value(inner),
            Self::WorkspaceGet(inner) => serde_json::to_value(inner),
            Self::WorkspaceTemplateList(inner) => serde_json::to_value(inner),
            Self::WorkspaceTemplateGet(inner) => serde_json::to_value(inner),
            Self::WorkspaceMountSet(inner) => serde_json::to_value(inner),
            Self::WorkspaceMountRemove(inner) => serde_json::to_value(inner),
            Self::WorkspaceMountList(inner) => serde_json::to_value(inner),
            Self::WorkspaceBindSet(inner) => serde_json::to_value(inner),
            Self::WorkspaceBindRemove(inner) => serde_json::to_value(inner),
            Self::WorkspaceBindList(inner) => serde_json::to_value(inner),
            Self::WorkspaceTokenRotate(inner) => serde_json::to_value(inner),
            Self::WorkspaceTokenRevoke(inner) => serde_json::to_value(inner),
            Self::WorkspaceActivate(inner) => serde_json::to_value(inner),
            Self::WorkspaceUp(inner) => serde_json::to_value(inner),
            Self::ProjectCreate(inner) => serde_json::to_value(inner),
            Self::ProjectUpdate(inner) => serde_json::to_value(inner),
            Self::ProjectDelete(inner) => serde_json::to_value(inner),
            Self::ProjectList(inner) => serde_json::to_value(inner),
            Self::ProjectGet(inner) => serde_json::to_value(inner),
            Self::ProjectMountSet(inner) => serde_json::to_value(inner),
            Self::ProjectMountRemove(inner) => serde_json::to_value(inner),
            Self::ProjectMountList(inner) => serde_json::to_value(inner),
            Self::ProjectTokenRotate(inner) => serde_json::to_value(inner),
            Self::ProjectTokenRevoke(inner) => serde_json::to_value(inner),
            Self::ProjectActivate(inner) => serde_json::to_value(inner),
            Self::WorkspaceStatus(inner) => serde_json::to_value(inner),
            Self::ReconcileStatus(inner) => serde_json::to_value(inner),
            Self::ProjectUp(inner) => serde_json::to_value(inner),
            Self::AuditTail(inner) => serde_json::to_value(inner),
        }
    }

    pub fn from_value(value: serde_json::Value) -> serde_json::Result<Self> {
        let message_type = value.get("type").and_then(|v| v.as_str()).ok_or_else(|| serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing type")))?;
        match message_type {
            "control.version_ack" => Ok(Self::VersionAck(serde_json::from_value(value)?)),
            "control.connect_ack" => Ok(Self::ConnectAck(serde_json::from_value(value)?)),
            "control.session_attach" => Ok(Self::SessionAttach(serde_json::from_value(value)?)),
            "control.session_status" => Ok(Self::SessionStatus(serde_json::from_value(value)?)),
            "control.session_resume" => Ok(Self::SessionResume(serde_json::from_value(value)?)),
            "control.session_list" => Ok(Self::SessionList(serde_json::from_value(value)?)),
            "control.session_close" => Ok(Self::SessionClose(serde_json::from_value(value)?)),
            "control.session_restore" => Ok(Self::SessionRestore(serde_json::from_value(value)?)),
            "control.session_history" => Ok(Self::SessionHistory(serde_json::from_value(value)?)),
            "control.ping" => Ok(Self::Ping(serde_json::from_value(value)?)),
            "control.pong" => Ok(Self::Pong(serde_json::from_value(value)?)),
            "control.metrics" => Ok(Self::Metrics(serde_json::from_value(value)?)),
            "control.auth_status" => Ok(Self::AuthStatus(serde_json::from_value(value)?)),
            "control.auth_rotate" => Ok(Self::AuthRotate(serde_json::from_value(value)?)),
            "control.node_invite_create" => Ok(Self::NodeInviteCreate(serde_json::from_value(value)?)),
            "control.node_join_request" => Ok(Self::NodeJoinRequest(serde_json::from_value(value)?)),
            "control.node_join_pending_list" => Ok(Self::NodeJoinPendingList(serde_json::from_value(value)?)),
            "control.node_join_approve" => Ok(Self::NodeJoinApprove(serde_json::from_value(value)?)),
            "control.node_join_deny" => Ok(Self::NodeJoinDeny(serde_json::from_value(value)?)),
            "control.node_join" => Ok(Self::NodeJoin(serde_json::from_value(value)?)),
            "control.node_ensure" => Ok(Self::NodeEnsure(serde_json::from_value(value)?)),
            "control.node_lease_refresh" => Ok(Self::NodeLeaseRefresh(serde_json::from_value(value)?)),
            "control.venom_bind" => Ok(Self::VenomBind(serde_json::from_value(value)?)),
            "control.venom_upsert" => Ok(Self::VenomUpsert(serde_json::from_value(value)?)),
            "control.venom_get" => Ok(Self::VenomGet(serde_json::from_value(value)?)),
            "control.agent_ensure" => Ok(Self::AgentEnsure(serde_json::from_value(value)?)),
            "control.agent_list" => Ok(Self::AgentList(serde_json::from_value(value)?)),
            "control.agent_get" => Ok(Self::AgentGet(serde_json::from_value(value)?)),
            "control.node_list" => Ok(Self::NodeList(serde_json::from_value(value)?)),
            "control.node_get" => Ok(Self::NodeGet(serde_json::from_value(value)?)),
            "control.node_delete" => Ok(Self::NodeDelete(serde_json::from_value(value)?)),
            "control.workspace_create" => Ok(Self::WorkspaceCreate(serde_json::from_value(value)?)),
            "control.workspace_update" => Ok(Self::WorkspaceUpdate(serde_json::from_value(value)?)),
            "control.workspace_delete" => Ok(Self::WorkspaceDelete(serde_json::from_value(value)?)),
            "control.workspace_list" => Ok(Self::WorkspaceList(serde_json::from_value(value)?)),
            "control.workspace_get" => Ok(Self::WorkspaceGet(serde_json::from_value(value)?)),
            "control.workspace_template_list" => Ok(Self::WorkspaceTemplateList(serde_json::from_value(value)?)),
            "control.workspace_template_get" => Ok(Self::WorkspaceTemplateGet(serde_json::from_value(value)?)),
            "control.workspace_mount_set" => Ok(Self::WorkspaceMountSet(serde_json::from_value(value)?)),
            "control.workspace_mount_remove" => Ok(Self::WorkspaceMountRemove(serde_json::from_value(value)?)),
            "control.workspace_mount_list" => Ok(Self::WorkspaceMountList(serde_json::from_value(value)?)),
            "control.workspace_bind_set" => Ok(Self::WorkspaceBindSet(serde_json::from_value(value)?)),
            "control.workspace_bind_remove" => Ok(Self::WorkspaceBindRemove(serde_json::from_value(value)?)),
            "control.workspace_bind_list" => Ok(Self::WorkspaceBindList(serde_json::from_value(value)?)),
            "control.workspace_token_rotate" => Ok(Self::WorkspaceTokenRotate(serde_json::from_value(value)?)),
            "control.workspace_token_revoke" => Ok(Self::WorkspaceTokenRevoke(serde_json::from_value(value)?)),
            "control.workspace_activate" => Ok(Self::WorkspaceActivate(serde_json::from_value(value)?)),
            "control.workspace_up" => Ok(Self::WorkspaceUp(serde_json::from_value(value)?)),
            "control.project_create" => Ok(Self::ProjectCreate(serde_json::from_value(value)?)),
            "control.project_update" => Ok(Self::ProjectUpdate(serde_json::from_value(value)?)),
            "control.project_delete" => Ok(Self::ProjectDelete(serde_json::from_value(value)?)),
            "control.project_list" => Ok(Self::ProjectList(serde_json::from_value(value)?)),
            "control.project_get" => Ok(Self::ProjectGet(serde_json::from_value(value)?)),
            "control.project_mount_set" => Ok(Self::ProjectMountSet(serde_json::from_value(value)?)),
            "control.project_mount_remove" => Ok(Self::ProjectMountRemove(serde_json::from_value(value)?)),
            "control.project_mount_list" => Ok(Self::ProjectMountList(serde_json::from_value(value)?)),
            "control.project_token_rotate" => Ok(Self::ProjectTokenRotate(serde_json::from_value(value)?)),
            "control.project_token_revoke" => Ok(Self::ProjectTokenRevoke(serde_json::from_value(value)?)),
            "control.project_activate" => Ok(Self::ProjectActivate(serde_json::from_value(value)?)),
            "control.workspace_status" => Ok(Self::WorkspaceStatus(serde_json::from_value(value)?)),
            "control.reconcile_status" => Ok(Self::ReconcileStatus(serde_json::from_value(value)?)),
            "control.project_up" => Ok(Self::ProjectUp(serde_json::from_value(value)?)),
            "control.audit_tail" => Ok(Self::AuditTail(serde_json::from_value(value)?)),
            _ => Err(serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported type"))),
        }
    }

    pub fn message_type(&self) -> ControlMessageType {
        match self {
            Self::VersionAck(_) => ControlMessageType::VersionAck,
            Self::ConnectAck(_) => ControlMessageType::ConnectAck,
            Self::SessionAttach(_) => ControlMessageType::SessionAttach,
            Self::SessionStatus(_) => ControlMessageType::SessionStatus,
            Self::SessionResume(_) => ControlMessageType::SessionResume,
            Self::SessionList(_) => ControlMessageType::SessionList,
            Self::SessionClose(_) => ControlMessageType::SessionClose,
            Self::SessionRestore(_) => ControlMessageType::SessionRestore,
            Self::SessionHistory(_) => ControlMessageType::SessionHistory,
            Self::Ping(_) => ControlMessageType::Ping,
            Self::Pong(_) => ControlMessageType::Pong,
            Self::Metrics(_) => ControlMessageType::Metrics,
            Self::AuthStatus(_) => ControlMessageType::AuthStatus,
            Self::AuthRotate(_) => ControlMessageType::AuthRotate,
            Self::NodeInviteCreate(_) => ControlMessageType::NodeInviteCreate,
            Self::NodeJoinRequest(_) => ControlMessageType::NodeJoinRequest,
            Self::NodeJoinPendingList(_) => ControlMessageType::NodeJoinPendingList,
            Self::NodeJoinApprove(_) => ControlMessageType::NodeJoinApprove,
            Self::NodeJoinDeny(_) => ControlMessageType::NodeJoinDeny,
            Self::NodeJoin(_) => ControlMessageType::NodeJoin,
            Self::NodeEnsure(_) => ControlMessageType::NodeEnsure,
            Self::NodeLeaseRefresh(_) => ControlMessageType::NodeLeaseRefresh,
            Self::VenomBind(_) => ControlMessageType::VenomBind,
            Self::VenomUpsert(_) => ControlMessageType::VenomUpsert,
            Self::VenomGet(_) => ControlMessageType::VenomGet,
            Self::AgentEnsure(_) => ControlMessageType::AgentEnsure,
            Self::AgentList(_) => ControlMessageType::AgentList,
            Self::AgentGet(_) => ControlMessageType::AgentGet,
            Self::NodeList(_) => ControlMessageType::NodeList,
            Self::NodeGet(_) => ControlMessageType::NodeGet,
            Self::NodeDelete(_) => ControlMessageType::NodeDelete,
            Self::WorkspaceCreate(_) => ControlMessageType::WorkspaceCreate,
            Self::WorkspaceUpdate(_) => ControlMessageType::WorkspaceUpdate,
            Self::WorkspaceDelete(_) => ControlMessageType::WorkspaceDelete,
            Self::WorkspaceList(_) => ControlMessageType::WorkspaceList,
            Self::WorkspaceGet(_) => ControlMessageType::WorkspaceGet,
            Self::WorkspaceTemplateList(_) => ControlMessageType::WorkspaceTemplateList,
            Self::WorkspaceTemplateGet(_) => ControlMessageType::WorkspaceTemplateGet,
            Self::WorkspaceMountSet(_) => ControlMessageType::WorkspaceMountSet,
            Self::WorkspaceMountRemove(_) => ControlMessageType::WorkspaceMountRemove,
            Self::WorkspaceMountList(_) => ControlMessageType::WorkspaceMountList,
            Self::WorkspaceBindSet(_) => ControlMessageType::WorkspaceBindSet,
            Self::WorkspaceBindRemove(_) => ControlMessageType::WorkspaceBindRemove,
            Self::WorkspaceBindList(_) => ControlMessageType::WorkspaceBindList,
            Self::WorkspaceTokenRotate(_) => ControlMessageType::WorkspaceTokenRotate,
            Self::WorkspaceTokenRevoke(_) => ControlMessageType::WorkspaceTokenRevoke,
            Self::WorkspaceActivate(_) => ControlMessageType::WorkspaceActivate,
            Self::WorkspaceUp(_) => ControlMessageType::WorkspaceUp,
            Self::ProjectCreate(_) => ControlMessageType::ProjectCreate,
            Self::ProjectUpdate(_) => ControlMessageType::ProjectUpdate,
            Self::ProjectDelete(_) => ControlMessageType::ProjectDelete,
            Self::ProjectList(_) => ControlMessageType::ProjectList,
            Self::ProjectGet(_) => ControlMessageType::ProjectGet,
            Self::ProjectMountSet(_) => ControlMessageType::ProjectMountSet,
            Self::ProjectMountRemove(_) => ControlMessageType::ProjectMountRemove,
            Self::ProjectMountList(_) => ControlMessageType::ProjectMountList,
            Self::ProjectTokenRotate(_) => ControlMessageType::ProjectTokenRotate,
            Self::ProjectTokenRevoke(_) => ControlMessageType::ProjectTokenRevoke,
            Self::ProjectActivate(_) => ControlMessageType::ProjectActivate,
            Self::WorkspaceStatus(_) => ControlMessageType::WorkspaceStatus,
            Self::ReconcileStatus(_) => ControlMessageType::ReconcileStatus,
            Self::ProjectUp(_) => ControlMessageType::ProjectUp,
            Self::AuditTail(_) => ControlMessageType::AuditTail,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AcheronRequestEnvelope {
    TVersion(AcheronVersionEnvelope),
    TAttach(AcheronAttachEnvelope),
    TWalk(AcheronPayloadEnvelope<AnyJson>),
    TOpen(AcheronPayloadEnvelope<AnyJson>),
    TRead(AcheronPayloadEnvelope<AnyJson>),
    TWrite(AcheronPayloadEnvelope<AnyJson>),
    TStat(AcheronPayloadEnvelope<AnyJson>),
    TClunk(AcheronPayloadEnvelope<AnyJson>),
    TFlush(AcheronPayloadEnvelope<AnyJson>),
    FsTHello(AcheronPayloadEnvelope<FsHelloRequest>),
    FsTExports(AcheronPayloadEnvelope<AnyJson>),
    FsTLookup(AcheronNodeEnvelope<FsLookupRequest>),
    FsTGetattr(AcheronNodeEnvelope<EmptyObject>),
    FsTReaddirp(AcheronNodeEnvelope<FsReaddirpRequest>),
    FsTSymlink(AcheronPayloadEnvelope<AnyJson>),
    FsTSetxattr(AcheronPayloadEnvelope<AnyJson>),
    FsTGetxattr(AcheronPayloadEnvelope<AnyJson>),
    FsTListxattr(AcheronPayloadEnvelope<AnyJson>),
    FsTRemovexattr(AcheronPayloadEnvelope<AnyJson>),
    FsTOpen(AcheronNodeEnvelope<FsOpenRequest>),
    FsTRead(AcheronHandleEnvelope<FsReadRequest>),
    FsTClose(AcheronHandleEnvelope<EmptyObject>),
    FsTLock(AcheronPayloadEnvelope<AnyJson>),
    FsTCreate(AcheronPayloadEnvelope<AnyJson>),
    FsTWrite(AcheronHandleEnvelope<FsWriteRequest>),
    FsTTruncate(AcheronPayloadEnvelope<AnyJson>),
    FsTUnlink(AcheronPayloadEnvelope<AnyJson>),
    FsTMkdir(AcheronPayloadEnvelope<AnyJson>),
    FsTRmdir(AcheronPayloadEnvelope<AnyJson>),
    FsTRename(AcheronPayloadEnvelope<AnyJson>),
    FsTStatfs(AcheronPayloadEnvelope<AnyJson>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AcheronResponseEnvelope {
    RVersion(AcheronVersionEnvelope),
    RAttach(AcheronPayloadEnvelope<AcheronAttachResponse>),
    RWalk(AcheronPayloadEnvelope<AnyJson>),
    ROpen(AcheronPayloadEnvelope<AnyJson>),
    RRead(AcheronPayloadEnvelope<AnyJson>),
    RWrite(AcheronPayloadEnvelope<AnyJson>),
    RStat(AcheronPayloadEnvelope<AnyJson>),
    RClunk(AcheronPayloadEnvelope<AnyJson>),
    RFlush(AcheronPayloadEnvelope<AnyJson>),
    FsRHello(AcheronPayloadEnvelope<FsHelloResponse>),
    FsRExports(AcheronPayloadEnvelope<AnyJson>),
    FsRLookup(AcheronPayloadEnvelope<FsLookupResponse>),
    FsRGetattr(AcheronPayloadEnvelope<FsGetattrResponse>),
    FsRReaddirp(AcheronPayloadEnvelope<FsReaddirpResponse>),
    FsRSymlink(AcheronPayloadEnvelope<AnyJson>),
    FsRSetxattr(AcheronPayloadEnvelope<AnyJson>),
    FsRGetxattr(AcheronPayloadEnvelope<AnyJson>),
    FsRListxattr(AcheronPayloadEnvelope<AnyJson>),
    FsRRemovexattr(AcheronPayloadEnvelope<AnyJson>),
    FsROpen(AcheronPayloadEnvelope<FsOpenResponse>),
    FsRRead(AcheronPayloadEnvelope<FsReadResponse>),
    FsRClose(AcheronPayloadEnvelope<EmptyObject>),
    FsRLock(AcheronPayloadEnvelope<AnyJson>),
    FsRCreate(AcheronPayloadEnvelope<AnyJson>),
    FsRWrite(AcheronPayloadEnvelope<FsWriteResponse>),
    FsRTruncate(AcheronPayloadEnvelope<AnyJson>),
    FsRUnlink(AcheronPayloadEnvelope<AnyJson>),
    FsRMkdir(AcheronPayloadEnvelope<AnyJson>),
    FsRRmdir(AcheronPayloadEnvelope<AnyJson>),
    FsRRename(AcheronPayloadEnvelope<AnyJson>),
    FsRStatfs(AcheronPayloadEnvelope<AnyJson>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AcheronEventEnvelopeEnum {
    FsEvtInval(AcheronEventEnvelope<FsInvalidateEvent>),
    FsEvtInvalDir(AcheronEventEnvelope<FsInvalidateDirEvent>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum AcheronErrorEnvelopeEnum {
    Error(AcheronErrorEnvelope<AcheronError>),
    FsErr(AcheronErrorEnvelope<AcheronFsError>),
}

impl AcheronRequestEnvelope {
    pub fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::TVersion(inner) => serde_json::to_value(inner),
            Self::TAttach(inner) => serde_json::to_value(inner),
            Self::TWalk(inner) => serde_json::to_value(inner),
            Self::TOpen(inner) => serde_json::to_value(inner),
            Self::TRead(inner) => serde_json::to_value(inner),
            Self::TWrite(inner) => serde_json::to_value(inner),
            Self::TStat(inner) => serde_json::to_value(inner),
            Self::TClunk(inner) => serde_json::to_value(inner),
            Self::TFlush(inner) => serde_json::to_value(inner),
            Self::FsTHello(inner) => serde_json::to_value(inner),
            Self::FsTExports(inner) => serde_json::to_value(inner),
            Self::FsTLookup(inner) => serde_json::to_value(inner),
            Self::FsTGetattr(inner) => serde_json::to_value(inner),
            Self::FsTReaddirp(inner) => serde_json::to_value(inner),
            Self::FsTSymlink(inner) => serde_json::to_value(inner),
            Self::FsTSetxattr(inner) => serde_json::to_value(inner),
            Self::FsTGetxattr(inner) => serde_json::to_value(inner),
            Self::FsTListxattr(inner) => serde_json::to_value(inner),
            Self::FsTRemovexattr(inner) => serde_json::to_value(inner),
            Self::FsTOpen(inner) => serde_json::to_value(inner),
            Self::FsTRead(inner) => serde_json::to_value(inner),
            Self::FsTClose(inner) => serde_json::to_value(inner),
            Self::FsTLock(inner) => serde_json::to_value(inner),
            Self::FsTCreate(inner) => serde_json::to_value(inner),
            Self::FsTWrite(inner) => serde_json::to_value(inner),
            Self::FsTTruncate(inner) => serde_json::to_value(inner),
            Self::FsTUnlink(inner) => serde_json::to_value(inner),
            Self::FsTMkdir(inner) => serde_json::to_value(inner),
            Self::FsTRmdir(inner) => serde_json::to_value(inner),
            Self::FsTRename(inner) => serde_json::to_value(inner),
            Self::FsTStatfs(inner) => serde_json::to_value(inner),
        }
    }

    pub fn from_value(value: serde_json::Value) -> serde_json::Result<Self> {
        let message_type = value.get("type").and_then(|v| v.as_str()).ok_or_else(|| serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing type")))?;
        match message_type {
            "acheron.t_version" => Ok(Self::TVersion(serde_json::from_value(value)?)),
            "acheron.t_attach" => Ok(Self::TAttach(serde_json::from_value(value)?)),
            "acheron.t_walk" => Ok(Self::TWalk(serde_json::from_value(value)?)),
            "acheron.t_open" => Ok(Self::TOpen(serde_json::from_value(value)?)),
            "acheron.t_read" => Ok(Self::TRead(serde_json::from_value(value)?)),
            "acheron.t_write" => Ok(Self::TWrite(serde_json::from_value(value)?)),
            "acheron.t_stat" => Ok(Self::TStat(serde_json::from_value(value)?)),
            "acheron.t_clunk" => Ok(Self::TClunk(serde_json::from_value(value)?)),
            "acheron.t_flush" => Ok(Self::TFlush(serde_json::from_value(value)?)),
            "acheron.t_fs_hello" => Ok(Self::FsTHello(serde_json::from_value(value)?)),
            "acheron.t_fs_exports" => Ok(Self::FsTExports(serde_json::from_value(value)?)),
            "acheron.t_fs_lookup" => Ok(Self::FsTLookup(serde_json::from_value(value)?)),
            "acheron.t_fs_getattr" => Ok(Self::FsTGetattr(serde_json::from_value(value)?)),
            "acheron.t_fs_readdirp" => Ok(Self::FsTReaddirp(serde_json::from_value(value)?)),
            "acheron.t_fs_symlink" => Ok(Self::FsTSymlink(serde_json::from_value(value)?)),
            "acheron.t_fs_setxattr" => Ok(Self::FsTSetxattr(serde_json::from_value(value)?)),
            "acheron.t_fs_getxattr" => Ok(Self::FsTGetxattr(serde_json::from_value(value)?)),
            "acheron.t_fs_listxattr" => Ok(Self::FsTListxattr(serde_json::from_value(value)?)),
            "acheron.t_fs_removexattr" => Ok(Self::FsTRemovexattr(serde_json::from_value(value)?)),
            "acheron.t_fs_open" => Ok(Self::FsTOpen(serde_json::from_value(value)?)),
            "acheron.t_fs_read" => Ok(Self::FsTRead(serde_json::from_value(value)?)),
            "acheron.t_fs_close" => Ok(Self::FsTClose(serde_json::from_value(value)?)),
            "acheron.t_fs_lock" => Ok(Self::FsTLock(serde_json::from_value(value)?)),
            "acheron.t_fs_create" => Ok(Self::FsTCreate(serde_json::from_value(value)?)),
            "acheron.t_fs_write" => Ok(Self::FsTWrite(serde_json::from_value(value)?)),
            "acheron.t_fs_truncate" => Ok(Self::FsTTruncate(serde_json::from_value(value)?)),
            "acheron.t_fs_unlink" => Ok(Self::FsTUnlink(serde_json::from_value(value)?)),
            "acheron.t_fs_mkdir" => Ok(Self::FsTMkdir(serde_json::from_value(value)?)),
            "acheron.t_fs_rmdir" => Ok(Self::FsTRmdir(serde_json::from_value(value)?)),
            "acheron.t_fs_rename" => Ok(Self::FsTRename(serde_json::from_value(value)?)),
            "acheron.t_fs_statfs" => Ok(Self::FsTStatfs(serde_json::from_value(value)?)),
            _ => Err(serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported type"))),
        }
    }

    pub fn message_type(&self) -> AcheronMessageType {
        match self {
            Self::TVersion(_) => AcheronMessageType::TVersion,
            Self::TAttach(_) => AcheronMessageType::TAttach,
            Self::TWalk(_) => AcheronMessageType::TWalk,
            Self::TOpen(_) => AcheronMessageType::TOpen,
            Self::TRead(_) => AcheronMessageType::TRead,
            Self::TWrite(_) => AcheronMessageType::TWrite,
            Self::TStat(_) => AcheronMessageType::TStat,
            Self::TClunk(_) => AcheronMessageType::TClunk,
            Self::TFlush(_) => AcheronMessageType::TFlush,
            Self::FsTHello(_) => AcheronMessageType::FsTHello,
            Self::FsTExports(_) => AcheronMessageType::FsTExports,
            Self::FsTLookup(_) => AcheronMessageType::FsTLookup,
            Self::FsTGetattr(_) => AcheronMessageType::FsTGetattr,
            Self::FsTReaddirp(_) => AcheronMessageType::FsTReaddirp,
            Self::FsTSymlink(_) => AcheronMessageType::FsTSymlink,
            Self::FsTSetxattr(_) => AcheronMessageType::FsTSetxattr,
            Self::FsTGetxattr(_) => AcheronMessageType::FsTGetxattr,
            Self::FsTListxattr(_) => AcheronMessageType::FsTListxattr,
            Self::FsTRemovexattr(_) => AcheronMessageType::FsTRemovexattr,
            Self::FsTOpen(_) => AcheronMessageType::FsTOpen,
            Self::FsTRead(_) => AcheronMessageType::FsTRead,
            Self::FsTClose(_) => AcheronMessageType::FsTClose,
            Self::FsTLock(_) => AcheronMessageType::FsTLock,
            Self::FsTCreate(_) => AcheronMessageType::FsTCreate,
            Self::FsTWrite(_) => AcheronMessageType::FsTWrite,
            Self::FsTTruncate(_) => AcheronMessageType::FsTTruncate,
            Self::FsTUnlink(_) => AcheronMessageType::FsTUnlink,
            Self::FsTMkdir(_) => AcheronMessageType::FsTMkdir,
            Self::FsTRmdir(_) => AcheronMessageType::FsTRmdir,
            Self::FsTRename(_) => AcheronMessageType::FsTRename,
            Self::FsTStatfs(_) => AcheronMessageType::FsTStatfs,
        }
    }
}

impl AcheronResponseEnvelope {
    pub fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::RVersion(inner) => serde_json::to_value(inner),
            Self::RAttach(inner) => serde_json::to_value(inner),
            Self::RWalk(inner) => serde_json::to_value(inner),
            Self::ROpen(inner) => serde_json::to_value(inner),
            Self::RRead(inner) => serde_json::to_value(inner),
            Self::RWrite(inner) => serde_json::to_value(inner),
            Self::RStat(inner) => serde_json::to_value(inner),
            Self::RClunk(inner) => serde_json::to_value(inner),
            Self::RFlush(inner) => serde_json::to_value(inner),
            Self::FsRHello(inner) => serde_json::to_value(inner),
            Self::FsRExports(inner) => serde_json::to_value(inner),
            Self::FsRLookup(inner) => serde_json::to_value(inner),
            Self::FsRGetattr(inner) => serde_json::to_value(inner),
            Self::FsRReaddirp(inner) => serde_json::to_value(inner),
            Self::FsRSymlink(inner) => serde_json::to_value(inner),
            Self::FsRSetxattr(inner) => serde_json::to_value(inner),
            Self::FsRGetxattr(inner) => serde_json::to_value(inner),
            Self::FsRListxattr(inner) => serde_json::to_value(inner),
            Self::FsRRemovexattr(inner) => serde_json::to_value(inner),
            Self::FsROpen(inner) => serde_json::to_value(inner),
            Self::FsRRead(inner) => serde_json::to_value(inner),
            Self::FsRClose(inner) => serde_json::to_value(inner),
            Self::FsRLock(inner) => serde_json::to_value(inner),
            Self::FsRCreate(inner) => serde_json::to_value(inner),
            Self::FsRWrite(inner) => serde_json::to_value(inner),
            Self::FsRTruncate(inner) => serde_json::to_value(inner),
            Self::FsRUnlink(inner) => serde_json::to_value(inner),
            Self::FsRMkdir(inner) => serde_json::to_value(inner),
            Self::FsRRmdir(inner) => serde_json::to_value(inner),
            Self::FsRRename(inner) => serde_json::to_value(inner),
            Self::FsRStatfs(inner) => serde_json::to_value(inner),
        }
    }

    pub fn from_value(value: serde_json::Value) -> serde_json::Result<Self> {
        let message_type = value.get("type").and_then(|v| v.as_str()).ok_or_else(|| serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing type")))?;
        match message_type {
            "acheron.r_version" => Ok(Self::RVersion(serde_json::from_value(value)?)),
            "acheron.r_attach" => Ok(Self::RAttach(serde_json::from_value(value)?)),
            "acheron.r_walk" => Ok(Self::RWalk(serde_json::from_value(value)?)),
            "acheron.r_open" => Ok(Self::ROpen(serde_json::from_value(value)?)),
            "acheron.r_read" => Ok(Self::RRead(serde_json::from_value(value)?)),
            "acheron.r_write" => Ok(Self::RWrite(serde_json::from_value(value)?)),
            "acheron.r_stat" => Ok(Self::RStat(serde_json::from_value(value)?)),
            "acheron.r_clunk" => Ok(Self::RClunk(serde_json::from_value(value)?)),
            "acheron.r_flush" => Ok(Self::RFlush(serde_json::from_value(value)?)),
            "acheron.r_fs_hello" => Ok(Self::FsRHello(serde_json::from_value(value)?)),
            "acheron.r_fs_exports" => Ok(Self::FsRExports(serde_json::from_value(value)?)),
            "acheron.r_fs_lookup" => Ok(Self::FsRLookup(serde_json::from_value(value)?)),
            "acheron.r_fs_getattr" => Ok(Self::FsRGetattr(serde_json::from_value(value)?)),
            "acheron.r_fs_readdirp" => Ok(Self::FsRReaddirp(serde_json::from_value(value)?)),
            "acheron.r_fs_symlink" => Ok(Self::FsRSymlink(serde_json::from_value(value)?)),
            "acheron.r_fs_setxattr" => Ok(Self::FsRSetxattr(serde_json::from_value(value)?)),
            "acheron.r_fs_getxattr" => Ok(Self::FsRGetxattr(serde_json::from_value(value)?)),
            "acheron.r_fs_listxattr" => Ok(Self::FsRListxattr(serde_json::from_value(value)?)),
            "acheron.r_fs_removexattr" => Ok(Self::FsRRemovexattr(serde_json::from_value(value)?)),
            "acheron.r_fs_open" => Ok(Self::FsROpen(serde_json::from_value(value)?)),
            "acheron.r_fs_read" => Ok(Self::FsRRead(serde_json::from_value(value)?)),
            "acheron.r_fs_close" => Ok(Self::FsRClose(serde_json::from_value(value)?)),
            "acheron.r_fs_lock" => Ok(Self::FsRLock(serde_json::from_value(value)?)),
            "acheron.r_fs_create" => Ok(Self::FsRCreate(serde_json::from_value(value)?)),
            "acheron.r_fs_write" => Ok(Self::FsRWrite(serde_json::from_value(value)?)),
            "acheron.r_fs_truncate" => Ok(Self::FsRTruncate(serde_json::from_value(value)?)),
            "acheron.r_fs_unlink" => Ok(Self::FsRUnlink(serde_json::from_value(value)?)),
            "acheron.r_fs_mkdir" => Ok(Self::FsRMkdir(serde_json::from_value(value)?)),
            "acheron.r_fs_rmdir" => Ok(Self::FsRRmdir(serde_json::from_value(value)?)),
            "acheron.r_fs_rename" => Ok(Self::FsRRename(serde_json::from_value(value)?)),
            "acheron.r_fs_statfs" => Ok(Self::FsRStatfs(serde_json::from_value(value)?)),
            _ => Err(serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported type"))),
        }
    }

    pub fn message_type(&self) -> AcheronMessageType {
        match self {
            Self::RVersion(_) => AcheronMessageType::RVersion,
            Self::RAttach(_) => AcheronMessageType::RAttach,
            Self::RWalk(_) => AcheronMessageType::RWalk,
            Self::ROpen(_) => AcheronMessageType::ROpen,
            Self::RRead(_) => AcheronMessageType::RRead,
            Self::RWrite(_) => AcheronMessageType::RWrite,
            Self::RStat(_) => AcheronMessageType::RStat,
            Self::RClunk(_) => AcheronMessageType::RClunk,
            Self::RFlush(_) => AcheronMessageType::RFlush,
            Self::FsRHello(_) => AcheronMessageType::FsRHello,
            Self::FsRExports(_) => AcheronMessageType::FsRExports,
            Self::FsRLookup(_) => AcheronMessageType::FsRLookup,
            Self::FsRGetattr(_) => AcheronMessageType::FsRGetattr,
            Self::FsRReaddirp(_) => AcheronMessageType::FsRReaddirp,
            Self::FsRSymlink(_) => AcheronMessageType::FsRSymlink,
            Self::FsRSetxattr(_) => AcheronMessageType::FsRSetxattr,
            Self::FsRGetxattr(_) => AcheronMessageType::FsRGetxattr,
            Self::FsRListxattr(_) => AcheronMessageType::FsRListxattr,
            Self::FsRRemovexattr(_) => AcheronMessageType::FsRRemovexattr,
            Self::FsROpen(_) => AcheronMessageType::FsROpen,
            Self::FsRRead(_) => AcheronMessageType::FsRRead,
            Self::FsRClose(_) => AcheronMessageType::FsRClose,
            Self::FsRLock(_) => AcheronMessageType::FsRLock,
            Self::FsRCreate(_) => AcheronMessageType::FsRCreate,
            Self::FsRWrite(_) => AcheronMessageType::FsRWrite,
            Self::FsRTruncate(_) => AcheronMessageType::FsRTruncate,
            Self::FsRUnlink(_) => AcheronMessageType::FsRUnlink,
            Self::FsRMkdir(_) => AcheronMessageType::FsRMkdir,
            Self::FsRRmdir(_) => AcheronMessageType::FsRRmdir,
            Self::FsRRename(_) => AcheronMessageType::FsRRename,
            Self::FsRStatfs(_) => AcheronMessageType::FsRStatfs,
        }
    }
}

impl AcheronEventEnvelopeEnum {
    pub fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::FsEvtInval(inner) => serde_json::to_value(inner),
            Self::FsEvtInvalDir(inner) => serde_json::to_value(inner),
        }
    }

    pub fn from_value(value: serde_json::Value) -> serde_json::Result<Self> {
        let message_type = value.get("type").and_then(|v| v.as_str()).ok_or_else(|| serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing type")))?;
        match message_type {
            "acheron.e_fs_inval" => Ok(Self::FsEvtInval(serde_json::from_value(value)?)),
            "acheron.e_fs_inval_dir" => Ok(Self::FsEvtInvalDir(serde_json::from_value(value)?)),
            _ => Err(serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported type"))),
        }
    }

    pub fn message_type(&self) -> AcheronMessageType {
        match self {
            Self::FsEvtInval(_) => AcheronMessageType::FsEvtInval,
            Self::FsEvtInvalDir(_) => AcheronMessageType::FsEvtInvalDir,
        }
    }
}

impl AcheronErrorEnvelopeEnum {
    pub fn to_value(&self) -> serde_json::Result<serde_json::Value> {
        match self {
            Self::Error(inner) => serde_json::to_value(inner),
            Self::FsErr(inner) => serde_json::to_value(inner),
        }
    }

    pub fn from_value(value: serde_json::Value) -> serde_json::Result<Self> {
        let message_type = value.get("type").and_then(|v| v.as_str()).ok_or_else(|| serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "missing type")))?;
        match message_type {
            "acheron.error" => Ok(Self::Error(serde_json::from_value(value)?)),
            "acheron.err_fs" => Ok(Self::FsErr(serde_json::from_value(value)?)),
            _ => Err(serde_json::Error::io(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported type"))),
        }
    }
}

