# SpiderProtocol Documentation

This folder contains the canonical maintained docs for Spiderweb protocol,
generated protocol references, and node runtime module contracts.

## Start Here
- `../README.md` - quick build + repo summary
- `overview.md` - role in the stack and module map
- `protocols/unified-v2-control.md` - canonical generated control protocol reference
- `protocols/acheron-runtime-v1.md` - canonical generated Acheron runtime reference
- `protocols/node-fs-unified-v2.md` - canonical generated node FS reference
- `protocols/spider-venom-wasm-abi-v1.md` - canonical generated Spider Venom WASM ABI reference
- `protocols/namespace-driver-abi-v1.md` - executable namespace driver ABI

Generated protocol artifacts live under `../sdk/spec/` and are refreshed with:

- `zig build sync-sdk`

Language SDKs live under:

- `../sdk/typescript/spiderweb-protocol`
- `../sdk/python/spiderweb_protocol`
- `../sdk/go/spiderwebprotocol`
- `../sdk/rust/spiderweb-protocol`
- `../sdk/swift/SpiderwebProtocol`
