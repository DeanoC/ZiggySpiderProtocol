# ZiggySpiderProtocol

Shared Spiderweb protocol parsing/building utilities for Zig-based server and clients.

## Exports

- Protocol message types and parse helpers
- Protocol response envelope builders
- Client `session.send` payload builder helper
- `spiderweb_fs` module:
  - FS-RPC protocol schema (`fs_protocol`)
  - WebSocket frame transport helpers (`websocket_transport`)
  - FS client transport (`fs_client`)
- `spiderweb_node` module:
  - Standalone node runtime components (`fs_node_main`, `fs_node_server`, `fs_node_ops`, pairing/service helpers)
  - Source adapter stack (linux/posix/windows/gdrive/namespace/local)
  - Namespace service model and runtime scaffolding:
    - `node_capability_providers` (built-in + extra service catalog payloads)
    - `service_manifest` (manifest loader for service descriptors)
    - `namespace_driver` (driver/runtime descriptor contracts)
    - `service_runtime_manager` (service lifecycle registry)
    - `plugin_loader_native`, `plugin_loader_process`, `plugin_loader_wasm` (runtime loader scaffolds)
  - Namespace executable ABI doc:
    - `docs/NAMESPACE_DRIVER_ABI_V1.md`

## Build

- `zig build`
- `zig build test`
