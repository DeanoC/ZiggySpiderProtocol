# Unified-v2 Control Protocol

Status: generated from `sdk/spec/protocol.json`

This is the canonical control-plane reference for public Spiderweb clients. The source of truth is the current Zig implementation in `unified_types.zig`, `unified_parse.zig`, and `unified_build.zig`.

## Constants

- protocol name: `unified-v2`
- websocket endpoint: control lives on the base websocket path (`/`)
- request correlation field: `id`
- error message type: `control.error`

## Envelope Rules

- Every message must include `channel: "control"`.
- Every message must include a `type` in the `control.*` namespace.
- `id` is required for request/response correlation in normal client flows.
- `control.error` uses `ok: false` plus `error.code` and `error.message`.
- Legacy control names rejected by the current parser are excluded from this reference.

## Required Handshake

1. Send `control.version` with payload `{"protocol":"unified-v2"}`.
2. Wait for `control.version_ack`.
3. Send `control.connect`.
4. Wait for `control.connect_ack`.

## Public Message Catalog

| Message | Category | Direction |
| --- | --- | --- || `control.version` | handshake | request |
| `control.version_ack` | handshake | response |
| `control.connect` | handshake | request |
| `control.connect_ack` | handshake | response |
| `control.session_attach` | session | request |
| `control.session_status` | session | request |
| `control.session_resume` | session | request |
| `control.session_list` | session | request |
| `control.session_close` | session | request |
| `control.session_restore` | session | request |
| `control.session_history` | session | request |
| `control.ping` | operations | request |
| `control.pong` | operations | response |
| `control.metrics` | operations | request |
| `control.auth_status` | auth | request |
| `control.auth_rotate` | auth | request |
| `control.node_invite_create` | node | request |
| `control.node_join_request` | node | request |
| `control.node_join_pending_list` | node | request |
| `control.node_join_approve` | node | request |
| `control.node_join_deny` | node | request |
| `control.node_join` | node | request |
| `control.node_ensure` | node | request |
| `control.node_lease_refresh` | node | request |
| `control.venom_bind` | venom | request |
| `control.venom_upsert` | venom | request |
| `control.venom_get` | venom | request |
| `control.agent_ensure` | agent | request |
| `control.agent_list` | agent | request |
| `control.agent_get` | agent | request |
| `control.node_list` | node | request |
| `control.node_get` | node | request |
| `control.node_delete` | node | request |
| `control.workspace_create` | workspace | request |
| `control.workspace_update` | workspace | request |
| `control.workspace_delete` | workspace | request |
| `control.workspace_list` | workspace | request |
| `control.workspace_get` | workspace | request |
| `control.workspace_template_list` | workspace | request |
| `control.workspace_template_get` | workspace | request |
| `control.workspace_mount_set` | workspace | request |
| `control.workspace_mount_remove` | workspace | request |
| `control.workspace_mount_list` | workspace | request |
| `control.workspace_bind_set` | workspace | request |
| `control.workspace_bind_remove` | workspace | request |
| `control.workspace_bind_list` | workspace | request |
| `control.workspace_token_rotate` | workspace | request |
| `control.workspace_token_revoke` | workspace | request |
| `control.workspace_activate` | workspace | request |
| `control.workspace_up` | workspace | request |
| `control.project_create` | project | request |
| `control.project_update` | project | request |
| `control.project_delete` | project | request |
| `control.project_list` | project | request |
| `control.project_get` | project | request |
| `control.project_mount_set` | project | request |
| `control.project_mount_remove` | project | request |
| `control.project_mount_list` | project | request |
| `control.project_token_rotate` | project | request |
| `control.project_token_revoke` | project | request |
| `control.project_activate` | project | request |
| `control.workspace_status` | workspace | request |
| `control.reconcile_status` | workspace | request |
| `control.project_up` | project | request |
| `control.audit_tail` | audit | request |
| `control.error` | error | error |

## Error Envelope

Canonical error shape:

```json
{"channel":"control","type":"control.error","id":"req-1","ok":false,"error":{"code":"missing_field","message":"..."}}
```

See fixture: `sdk/spec/fixtures/control/error.response.json`.

## Explicit Exclusions

These names are not part of the public protocol surface represented here:
- `session.send`
- `control.debug_subscribe`
- `control.debug_unsubscribe`
- `control.node_service_watch`
- `control.node_service_unwatch`
- `control.node_service_event`
- `control.venom_watch`
- `control.venom_unwatch`
- `control.venom_event`
