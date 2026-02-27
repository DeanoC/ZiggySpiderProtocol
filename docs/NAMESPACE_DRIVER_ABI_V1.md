# Acheron Namespace Driver ABI v1

Status: active

This document defines the first executable runtime contract for node-exported
namespace services.

## Scope

ABI v1 standardizes three runtime modes with the same namespace control surface:

- `runtime.type = "native_proc"`
- `runtime.type = "native_inproc"`
- `runtime.type = "wasm"`

## Manifest Contract

Service manifests that should expose a live executable namespace must include:

- `service_id` (`string`)
- `runtime.type` (`native_proc` | `native_inproc` | `wasm`)
- `runtime.abi = "namespace-driver-v1"` (recommended; treated as metadata)
- runtime path field for selected mode:
  - `native_proc`: `runtime.executable_path`
  - `native_inproc`: `runtime.library_path`
  - `wasm`: `runtime.module_path`
- `runtime.args` (`array<string>`, optional)
- `runtime.timeout_ms` (`u64`, optional, default `30000`)
- `runtime.runner_path` (`string`, optional; wasm only, defaults to `wasmtime`)
- `runtime.entrypoint` (`string`, optional; wasm only)

If the runtime-specific path field is omitted, the service can still be
published in the catalog, but no executable namespace export is created.

## Namespace Projection

For each executable service, the node runtime creates a namespace export with:

- export name: `svc-<service_id>`
- source id/path seed: `service:<service_id>`

Projected files:

- `README.md`
- `SCHEMA.json`
- `result.json`
- `status.json`
- `metrics.json`
- `last_error.txt`
- `config.json` (writable JSON object)
- `health.json`
- `control/invoke.json` (writable)
- `control/reset` (writable)
- `control/enable` (writable)
- `control/disable` (writable)
- `control/restart` (writable)

## Invoke Contract

Invocation is file-driven:

- write a JSON object payload to `control/invoke.json`
- runtime executes the configured driver runtime
- payload bytes are sent to runtime `stdin` for `native_proc`/`wasm`

Operational reset:

- write any payload to `control/reset`
- runtime resets:
  - `result.json` -> `{"state":"idle"}`
  - `status.json` -> `{"state":"idle"}`
  - `metrics.json` unchanged
  - `last_error.txt` -> empty string

Runtime control:

- write any payload to `control/disable`
  - disables runtime invocation
  - `status.json.state` becomes `"offline"`
  - invokes return `EPERM`
- write any payload to `control/enable`
  - re-enables invocation
  - `status.json.state` becomes `"idle"`
- write any payload to `control/restart`
  - increments restart counter
  - clears `last_error.txt`
  - `status.json` becomes `"idle"` (or `"offline"` when disabled)
- write JSON object payload to `config.json`
  - persists as service runtime config state
  - reflected in `health.json` metadata

Result mapping:

- process exit code `0`
  - `result.json` = process `stdout` (or `{}` if empty)
  - `last_error.txt` = `""`
  - `status.json.state` = `"ok"`
- non-zero exit (or runtime failure)
  - `last_error.txt` = process `stderr` (or fallback error text)
  - `status.json.state` = `"error"`
  - `status.json.exit_code` populated

Timeout behavior:

- `runtime.timeout_ms` is enforced as a hard deadline for `native_proc`,
  `native_inproc`, and `wasm`
- `native_inproc` runs inside an internal helper subprocess so deadline
  enforcement can safely terminate execution
- when deadline is reached, the active runtime process is force-terminated
- `status.json.state` becomes `"timeout"`
- `timeouts_total` increments in `metrics.json`

`metrics.json` tracks invocation counters and timing:

- `invokes_total`
- `failures_total`
- `consecutive_failures`
- `timeouts_total`
- `last_duration_ms`
- `last_started_ms`
- `last_finished_ms`
- `last_exit_code`

`health.json` tracks runtime operational state:

- `state` (`online` | `offline` | `degraded`)
- `enabled` (`bool`)
- `last_control_op`
- `last_control_ms`
- `restarts_total`
- plus invocation summary mirrors from `metrics.json`

Writes trigger FS invalidation events on updated files.

## Process Rules

- `stdin`: full invoke JSON payload
- `stdout`: JSON result payload (recommended)
- `stderr`: human-readable diagnostic text
- max collected output follows node write-size guardrails

Drivers should treat each invocation as stateless, idempotent where possible,
and return structured JSON on `stdout`.

## Native In-Process ABI

`native_inproc` libraries must export:

- symbol: `spiderweb_driver_v1_invoke_json`
- call convention: C
- signature:

```c
int spiderweb_driver_v1_invoke_json(
  const uint8_t* payload_ptr,
  size_t payload_len,
  uint8_t* stdout_ptr,
  size_t stdout_cap,
  size_t* stdout_len,
  uint8_t* stderr_ptr,
  size_t stderr_cap,
  size_t* stderr_len
);
```

Return `0` for success; non-zero for failure. Output bytes are written into
host-provided buffers.

## WASM Runtime Rules

`wasm` mode executes through an external runner command:

- default runner: `wasmtime`
- command shape:
  - `runner_path run [--invoke <entrypoint>] <module_path> [args...]`
- invoke payload is written to runner stdin; stdout/stderr map to the same
  namespace result/error files.

## Error Mapping

Node runtime maps invocation issues to FS-RPC errors:

- invalid invoke payload JSON -> `EINVAL`
- denied invocation -> `EPERM`
- process/runtime failures -> `EIO`

## Compatibility

ABI versioning is manifest-declared.
Future runtime types (`native_inproc`, `wasm`) must preserve the same
filesystem-facing control surface (`control/invoke.json`, `result.json`,
`status.json`, `last_error.txt`) for stable agent workflows.
