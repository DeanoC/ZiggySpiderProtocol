# spiderweb-protocol

Internal/reference Rust SDK for SpiderProtocol.

It exposes:

- generated wire types in `spiderweb_protocol::generated`
- parsing, transport, and client helpers in `spiderweb_protocol::protocol`
- `TokioWebSocketTextTransport` behind the `websocket` feature

Generate `src/generated.rs` from the canonical Zig schema with:

```bash
zig build sync-sdk
```

Run tests with:

```bash
cargo test --all-features
```
