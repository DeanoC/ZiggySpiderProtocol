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

## Build

- `zig build`
- `zig build test`
