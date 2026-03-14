# SpiderProtocol Overview

SpiderProtocol is the canonical shared protocol library for Spiderweb servers,
clients, SDK generators, and node runtimes. It defines the public control and
Acheron wire surfaces, emits generated protocol artifacts, and exposes node
runtime modules used by Spiderweb and SpiderNode.

Official Zig module name:
- `spider-protocol`

## What It Provides

- Unified-v2 control parsing and envelope builders
- Acheron runtime and node-FS message catalogs
- Generated protocol specs, fixtures, and SDKs under `sdk/`
- First-class TypeScript, Python, Go, Rust, and Swift SDK artifacts
- WebSocket transport helpers
- Node runtime components (fs node server + ops)
- Service catalog and namespace runtime scaffolding

## Modules

- `spiderweb_fs`
  - Internal FS helper schema (`fs_protocol`)
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

## Canonical Protocol References

- `protocols/unified-v2-control.md`
- `protocols/acheron-runtime-v1.md`
- `protocols/node-fs-unified-v2.md`
- `protocols/spider-venom-wasm-abi-v1.md`
