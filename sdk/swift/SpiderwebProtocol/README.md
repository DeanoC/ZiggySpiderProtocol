# Spiderweb Protocol SDK for Swift

Reference Swift package for generated Spiderweb protocol constants.

It currently exposes:

- unified-v2 control protocol constants
- Acheron runtime and node-FS message type catalogs
- envelope rule metadata

`Sources/SpiderwebProtocol/Generated.swift` is generated from the canonical Zig
schema via `zig build sync-sdk`.

## Development

```bash
swift build
```
