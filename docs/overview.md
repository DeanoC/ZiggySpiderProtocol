# SpiderProtocol Overview

SpiderProtocol is the shared protocol library for Spiderweb servers, clients, and node runtimes. It defines control and filesystem parsing/building, plus the node runtime modules used by Spiderweb and SpiderNode.

Official Zig module name:
- `spider-protocol`

Compatibility alias still exported:
- `ziggy-spider-protocol`

## What It Provides

- Unified-v2 control parsing and envelope builders
- Acheron FS protocol schemas and helpers
- WebSocket transport helpers
- Node runtime components (fs node server + ops)
- Service catalog and namespace runtime scaffolding

## Modules

- `spiderweb_fs`
  - FS-RPC protocol schema (`fs_protocol`)
  - WebSocket frame helpers (`websocket_transport`)
  - FS client transport (`fs_client`)

- `spiderweb_node`
  - Standalone node runtime components (`fs_node_main`, `fs_node_server`, `fs_node_ops`)
  - Source adapter stack (linux/posix/windows/gdrive/namespace/local)
  - Service catalog + manifest loader
  - Namespace driver/runtime scaffolding (native_proc / native_inproc / wasm)

## Driver ABI

Executable namespace drivers follow the ABI documented in:
- `protocols/namespace-driver-abi-v1.md`
